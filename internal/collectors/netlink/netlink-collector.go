package netlink

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/PRO-Robotech/nftrace/internal/collectors"

	nl "github.com/H-BF/corlib/pkg/netlink"
	oz "github.com/go-ozzo/ozzo-validation/v4"
	"golang.org/x/sys/unix"
)

type (
	Config struct {
		// Params
		NlBuffLen      int
		UseAggregation bool
	}

	// netlinkTraceCollector - implementation of the TraceCollector interface
	netlinkTraceCollector struct {
		metrics Metrics

		nlRcvBuffLen int
		aggregate    bool

		nlWatcher nl.NetlinkWatcher

		ch        chan collectors.CollectorMsg
		onceRun   sync.Once
		onceClose sync.Once
		stop      chan struct{}
		stopped   chan struct{}
	}
)

var _ collectors.TraceCollector = (*netlinkTraceCollector)(nil)

func NewNetlinkTraceCollector(cfg Config) (*netlinkTraceCollector, error) {
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config for netlink trace collector: %w", err)
	}
	nlWatcher, err := nl.NewNetlinkWatcher(unix.NETLINK_NETFILTER,
		nl.WithReadBuffLen(cfg.NlBuffLen),
		nl.WithNetlinkGroups(unix.NFNLGRP_NFTRACE),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create netlink trace-watcher: %v", err)
	}

	nc := &netlinkTraceCollector{
		nlRcvBuffLen: cfg.NlBuffLen,
		aggregate:    cfg.UseAggregation,
		nlWatcher:    nlWatcher,
		stop:         make(chan struct{}),
	}

	return nc, nil
}

func (nc *netlinkTraceCollector) run(ctx context.Context, callback func(collectors.NftTrace)) (err error) {
	nc.stopped = make(chan struct{})
	reader := nc.nlWatcher.Stream(ctx)

	defer close(nc.stopped)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-nc.stop:
			return nil
		case nlData, ok := <-reader:
			if !ok {
				return errors.New("trace watcher has already closed")
			}
			err = nlData.Err
			messages := nlData.Messages

			if err != nil {
				if errors.Is(err, nl.ErrNlMem) {
					nc.metrics.MemOvflCnt += 1
					continue
				}
				if errors.Is(err, nl.ErrNlDataNotReady) ||
					errors.Is(err, nl.ErrNlReadInterrupted) {
					continue
				}

				return fmt.Errorf("failed to rcv nl message: %w", err)
			}

			for _, msg := range messages {
				var tr NetlinkTrace
				if err = tr.InitFromMsg(msg); err != nil {
					return err
				}
				if callback != nil {
					callback(tr.ToNftTrace())
				}
			}
		}
	}
}

// Reader
func (nc *netlinkTraceCollector) Collect(ctx context.Context) <-chan collectors.CollectorMsg {
	nc.onceRun.Do(func() {
		nc.ch = make(chan collectors.CollectorMsg, readerQueSize)
		go func() {
			defer close(nc.ch)

			err := nc.run(ctx, func(tr collectors.NftTrace) {
				select {
				case <-ctx.Done():
					nc.ch <- collectors.CollectorMsg{Trace: tr, Err: ctx.Err()}
					return
				case <-nc.stop:
					return
				case nc.ch <- collectors.CollectorMsg{Trace: tr}:
				}
			})

			if !errors.Is(err, context.Canceled) {
				nc.ch <- collectors.CollectorMsg{Err: err}
			}
		}()
	})

	return nc.ch
}

// Close collector
func (nc *netlinkTraceCollector) Close() error {
	nc.onceClose.Do(func() {
		close(nc.stop)
		nc.onceRun.Do(func() {})
		if nc.stopped != nil {
			<-nc.stopped
		}
		_ = nc.nlWatcher.Close()
	})
	return nil
}

func (cfg Config) validate() error {
	return oz.ValidateStruct(&cfg,
		oz.Field(&cfg.NlBuffLen,
			oz.Min(nl.SockBuffLen16MB).
				Error(
					fmt.Errorf(
						"Collector/nlBuffLen is %d, but should be >= %d",
						cfg.NlBuffLen, nl.SockBuffLen16MB,
					).Error(),
				),
		),
	)
}
