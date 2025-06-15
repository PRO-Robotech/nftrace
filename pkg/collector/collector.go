package collector

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/PRO-Robotech/nftrace"
	"github.com/PRO-Robotech/nftrace/internal/app"
	"github.com/PRO-Robotech/nftrace/internal/collectors"
	"github.com/PRO-Robotech/nftrace/internal/collectors/ebpf"
	"github.com/PRO-Robotech/nftrace/internal/collectors/netlink"
	"github.com/PRO-Robotech/nftrace/internal/providers"
	tg "github.com/PRO-Robotech/nftrace/internal/trace-group"

	"github.com/H-BF/corlib/logger"
)

var (
	NewEbpfTraceCollector    = newTraceCollector[EbpfCfg]
	NewNetlinkTraceCollector = newTraceCollector[NetlinkCfg]
)

type (
	EbpfCollector    = *collectorImpl[EbpfCfg]
	NetlinkCollector = *collectorImpl[NetlinkCfg]
)

type (
	collectorImpl[T cfgType] struct {
		collector    collectors.TraceCollector
		linkProvider providers.LinkProvider
		ruleProvider providers.RuleProvider

		ch         chan Msg
		useLogging bool

		onceRun   sync.Once
		onceClose sync.Once
		stop      chan struct{}
		stopped   chan struct{}
	}
)

func newTraceCollector[T cfgType](cfg T, useLogging bool) (*collectorImpl[T], error) {
	var (
		collector collectors.TraceCollector
		lp        providers.LinkProvider
		rp        providers.RuleProvider
		err       error
	)

	switch t := any(cfg).(type) {
	case EbpfCfg:
		collector, err = ebpf.NewEbpfTraceCollector(t)
	case NetlinkCfg:
		collector, err = netlink.NewNetlinkTraceCollector(t)
	default:
		return nil, fmt.Errorf("unsupported collector config type: %T", t)
	}
	if err != nil {
		return nil, err
	}

	return &collectorImpl[T]{
		collector:    collector,
		linkProvider: lp,
		ruleProvider: rp,
		useLogging:   useLogging,
		stop:         make(chan struct{}),
	}, nil
}

// Collect
func (c *collectorImpl[T]) Collect(ctx context.Context) <-chan Msg {
	c.onceRun.Do(func() {
		c.ch = make(chan Msg, readerQueSize)
		go func() {
			defer close(c.ch)

			err := c.run(ctx, func(tr nftrace.Trace, metrics collectors.Telemetry) {
				select {
				case <-ctx.Done():
					c.ch <- Msg{Trace: tr, Metrics: metrics, Err: ctx.Err()}
					return
				case <-c.stop:
					return
				case c.ch <- Msg{Trace: tr, Metrics: metrics}:
				}
			})

			if !errors.Is(err, context.Canceled) {
				c.ch <- Msg{Err: err}
			}
		}()
	})

	return c.ch
}

func (c *collectorImpl[T]) run(ctx context.Context, cb func(nftrace.Trace, collectors.Telemetry)) error {
	c.stopped = make(chan struct{})
	defer close(c.stopped)

	if !c.useLogging {
		logger.ToContext(ctx, app.NopLogger())
	}

	log := logger.FromContext(ctx).Named("collector")
	log.Info("start")
	defer log.Info("stopped")

	lp, err := providers.NewLinkProvider(ctx, c.useLogging)
	if err != nil {
		return fmt.Errorf("failed to create link provider: %w", err)
	}
	defer func() { _ = lp.Close() }()
	rp, err := providers.NewRuleProvider(ctx, c.useLogging)
	if err != nil {
		return fmt.Errorf("failed to create rule provider: %w", err)
	}
	defer func() { _ = rp.Close() }()

	traceGroup := tg.NewTraceGroup(lp, rp)
	defer traceGroup.Close()

	for stm := c.collector.Collect(ctx); err == nil; {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.stop:
			return nil
		case msg, ok := <-stm:
			if !ok {
				return nil
			}

			if msg.Err != nil {
				return msg.Err
			}

			err = traceGroup.Handle(msg.Trace, cb)
			if errors.Is(err, tg.ErrTraceDataNotReady) {
				err = nil // Ignore this error, it means the trace data is not ready yet
			}
		}
	}

	return nil
}

// Close
func (c *collectorImpl[T]) Close() error {
	c.onceClose.Do(func() {
		close(c.stop)
		c.onceRun.Do(func() {})
		if c.stopped != nil {
			<-c.stopped
		}
		_ = c.collector.Close()
	})
	return nil
}
