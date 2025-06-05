//go:build linux

package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/PRO-Robotech/nftrace/internal/collectors"

	kernel_info "github.com/H-BF/corlib/pkg/kernel-info"
	"github.com/H-BF/corlib/pkg/lazy"
	"github.com/H-BF/corlib/pkg/meta"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	oz "github.com/go-ozzo/ozzo-validation/v4"
	"golang.org/x/sys/unix"
)

var (
	requiredKernelModules   = []string{"nf_tables"}
	minKernelVersionSupport = kernel_info.KernelVersion{Major: 5, Minor: 8, Patch: 0}
)

type (
	// Config - configuration for ebpf trace collector
	Config struct {
		// Params
		SampleRate     uint64
		RingBuffSize   int
		UseAggregation bool
		EventsRate     uint64
	}

	ebpfTraceCollector struct {
		objs    bpfObjects
		metrics Metrics

		bufflen  int
		readyMsk bool

		ch        chan collectors.CollectorMsg
		onceRun   sync.Once
		onceClose sync.Once
		stop      chan struct{}
		stopped   chan struct{}
		cancels   []func() error
	}
)

var _ collectors.TraceCollector = (*ebpfTraceCollector)(nil)

func NewEbpfTraceCollector(cfg Config) (tc *ebpfTraceCollector, err error) {
	var cancels []func() error

	defer func() {
		if err != nil {
			for _, cancel := range cancels {
				defer func() { _ = cancel() }() // for reverse order
			}
		}
	}()

	err = cfg.validate()
	if err != nil {
		return nil, fmt.Errorf("failed to validate ebpf trace collector config: %w", err)
	}

	err = ensureKernelSupport()
	if err != nil {
		return nil, err
	}

	if err = ensureMemlock.Value(); err != nil {
		return nil, fmt.Errorf("failed to lock memory for process: %w", err)
	}

	var loadOpts *ebpf.CollectionOptions
	objs := bpfObjects{}

	queMap, e := newPerCpuQueMap(meta.GetFieldTag(&objs.bpfMaps, &objs.PerCpuQue, "ebpf"), runtime.NumCPU())
	if e != nil {
		return nil, fmt.Errorf("failed to create map in map que: %w", e)
	}

	cancels = append(cancels, queMap.Close)

	loadOpts = &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			meta.GetFieldTag(&objs.bpfMaps, &objs.PerCpuQue, "ebpf"): queMap,
		},
	}

	if err = loadBpfObjects(&objs, loadOpts); err != nil {
		return nil, fmt.Errorf("failed to load bpf objects: %w", err)
	}

	key := uint32(0)
	if err = objs.SampleRate.Put(key, cfg.SampleRate); err != nil {
		return nil, fmt.Errorf("failed to update sample_rate map: %w", err)
	}

	if cfg.UseAggregation {
		if err = objs.UseAggregation.Put(key, uint64(1)); err != nil {
			return nil, fmt.Errorf("failed to update aggregation value in ebpf map: %w", err)
		}

		cancelPerfEvent, e := newPerCpuPerfEventTimer(runtime.NumCPU(), objs.SendAgregatedTrace, cfg.EventsRate)
		if e != nil {
			return nil, e
		}
		cancels = append(cancels, cancelPerfEvent)
	}

	kp, e := link.Kprobe(kProbeBreakPoint, objs.KprobeNftTraceNotify, nil)
	if e != nil {
		return nil, fmt.Errorf("opening kprobe: %w", e)
	}

	cancels = append(cancels, kp.Close, objs.Close)

	return &ebpfTraceCollector{
		objs: objs,

		bufflen:  cfg.RingBuffSize,
		readyMsk: cfg.UseAggregation || cfg.SampleRate > 0,

		stop:    make(chan struct{}),
		cancels: cancels,
	}, nil
}

// Collect
func (ec *ebpfTraceCollector) Collect(ctx context.Context) <-chan collectors.CollectorMsg {
	ec.onceRun.Do(func() {
		ec.ch = make(chan collectors.CollectorMsg, readerQueSize)
		go func() {
			defer close(ec.ch)

			err := ec.run(ctx, func(tr collectors.NftTrace) {
				select {
				case <-ctx.Done():
					ec.ch <- collectors.CollectorMsg{Trace: tr, Err: ctx.Err()}
					return
				case <-ec.stop:
					return
				case ec.ch <- collectors.CollectorMsg{Trace: tr}:
				}
			})

			if !errors.Is(err, context.Canceled) {
				ec.ch <- collectors.CollectorMsg{Err: err}
			}
		}()
	})

	return ec.ch
}

// Close
func (ec *ebpfTraceCollector) Close() error {
	ec.onceClose.Do(func() {
		close(ec.stop)
		ec.onceRun.Do(func() {})
		if ec.stopped != nil {
			<-ec.stopped
		}
		ec.cancel()
	})
	return nil
}

func (ec *ebpfTraceCollector) run(ctx context.Context, callback func(collectors.NftTrace)) error {
	ec.stopped = make(chan struct{})
	defer close(ec.stopped)

	return ec.pushTraces(ctx, func(event EbpfTrace) {
		if callback != nil {
			callback(event.ToNftTrace())
		}
	})
}

func (ec *ebpfTraceCollector) pushTraces(ctx context.Context, callback func(event EbpfTrace)) error {
	errCh := make(chan error, 1)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer func() {
			close(errCh)
			wg.Done()
		}()
		errCh <- ec.readTraces(ctx, callback)
	}()

	var jobErr error
	select {
	case <-ctx.Done():
		jobErr = ctx.Err()
	case <-ec.stop:
		jobErr = nil
	case jobErr = <-errCh:
	}

	wg.Wait()

	return jobErr
}

func (ec *ebpfTraceCollector) readTraces(ctx context.Context, callback func(event EbpfTrace)) (err error) {
	var (
		trace  bpfTraceInfo
		record = new(perf.Record)
	)

	rd, err := perf.NewReader(ec.objs.TraceEvents, ec.bufflen)
	if err != nil {
		return fmt.Errorf("opening ringbuf reader: %w", err)
	}
	defer func() { _ = rd.Close() }()

	for err == nil {
		select {
		case <-ctx.Done():
			return nil
		case <-ec.stop:
			return nil
		default:
		}
		rd.SetDeadline(time.Now().Add(time.Second))
		err = rd.ReadInto(record)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				err = nil
			} else {
				err = fmt.Errorf("reading trace from reader: %w", err)
			}
			continue
		}
		ec.metrics.LostSamples += record.LostSamples

		if len(record.RawSample) == 0 {
			continue
		}

		trace = *(*bpfTraceInfo)(unsafe.Pointer(&record.RawSample[0]))
		ec.metrics.PktCnt = trace.Counter

		if callback != nil {
			callback(EbpfTrace{trace, ec.readyMsk, ec.metrics})
		}
	}

	return err
}

func (ec *ebpfTraceCollector) cancel() {
	for _, cancel := range ec.cancels {
		defer func() { _ = cancel() }() // for reverse order
	}
	ec.cancels = nil
}

func (cfg Config) validate() error {
	return oz.ValidateStruct(&cfg,
		oz.Field(&cfg.RingBuffSize,
			oz.Min(1).
				Error(
					fmt.Errorf(
						"EbpfCollector/ringBuffSize is %d, but should be >= 1",
						cfg.RingBuffSize,
					).Error(),
				),
		),
		oz.Field(&cfg.EventsRate, oz.By(func(v interface{}) error {
			n, _ := oz.ToUint(v)
			if n < 1 || n > 100 {
				return oz.NewError("range", "should be in range from 1 to 100")
			}
			return nil
		})),
	)
}

// Helpers

var ensureMemlock = lazy.MakeInitializer(func() error {
	var t struct {
		buf []byte
		err error
	}
	const mem1Gb = 1 << 30
	if t.err = rlimit.RemoveMemlock(); t.err == nil {
		t.buf = make([]byte, mem1Gb)
	}
	return t.err
})

func newPerCpuQueMap(mapName string, nCPU int) (*ebpf.Map, error) {
	outerMapSpec := ebpf.MapSpec{
		Name:       mapName,
		Type:       ebpf.ArrayOfMaps,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: MaxCPUs,
		Contents:   make([]ebpf.MapKV, runtime.NumCPU()),
		InnerMap: &ebpf.MapSpec{
			Name:       "inner_map",
			Type:       ebpf.Queue,
			KeySize:    0,
			ValueSize:  4,
			MaxEntries: MaxConnectionsPerSec,
		},
	}

	for i := 0; i < nCPU; i++ {
		innerMap, err := ebpf.NewMap(outerMapSpec.InnerMap)
		if err != nil {
			return nil, fmt.Errorf("inner_map: %w", err)
		}
		defer innerMap.Close() //nolint:errcheck
		k := uint32(i)         //nolint:gosec
		outerMapSpec.Contents[i] = ebpf.MapKV{Key: k, Value: innerMap}
	}
	return ebpf.NewMap(&outerMapSpec)
}

// newPerCpuPerfEventTimer - assign perf event program as a timer. Rate should be in range 1 ... 100 (means number of events per second)
func newPerCpuPerfEventTimer(nCPU int, program *ebpf.Program, rate uint64) (cancel func() error, err error) {
	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_SOFTWARE,
		Config: unix.PERF_COUNT_SW_CPU_CLOCK,
		Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
		Sample: rate,
		Wakeup: 1,
		Bits:   unix.PerfBitFreq,
	}
	attr.Size = uint32(binary.Size(&attr)) //nolint:gosec
	var (
		fds []int
		fd  int
	)

	cancel = func() error {
		for i := range fds {
			_ = unix.Close(fds[i])
		}
		return nil
	}

	defer func() {
		if err != nil {
			_ = cancel()
		}
	}()

	for cpu := range nCPU {
		fd, err = unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if err != nil {
			return cancel, fmt.Errorf("failed to create perf event for cpu %d: %w", cpu, err)
		}
		fds = append(fds, fd)

		if err = unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, program.FD()); err != nil {
			return cancel, fmt.Errorf("failed to attach perf event fo the cpu %d: %w", cpu, err)
		}

		if err = unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
			return cancel, fmt.Errorf("failed to enable perf event for the cpu %d: %w", cpu, err)
		}
	}

	return cancel, err
}

func ensureKernelSupport() (err error) {
	if err = kernel_info.CheckKernelVersion(minKernelVersionSupport); err != nil {
		return fmt.Errorf("failed to check kernel version: %w", err)
	}
	if err = kernel_info.CheckBTFKernelSupport(); err != nil {
		return fmt.Errorf("failed to check BTF kernel support: %w", err)
	}
	if err = kernel_info.CheckKernelModules(requiredKernelModules...); err != nil {
		return fmt.Errorf("failed to check kernel modules: %w", err)
	}
	return nil
}
