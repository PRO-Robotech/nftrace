package watchers

import (
	"context"
	"errors"
	"fmt"
	"sync"

	nl "github.com/H-BF/corlib/pkg/netlink"
	"github.com/H-BF/corlib/pkg/queue"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

var (
	LinkWatcher       = newWatcher[LinkEvent]
	RuleWatcher       = newWatcher[RuleEvent]
	ChainWatcher      = newWatcher[ChainEvent]
	SetWatcher        = newWatcher[SetEvent]
	SetElementWatcher = newWatcher[SetElementEvent]
	TableWatcher      = newWatcher[TableEvent]
	NftWatcher        = newWatcher[NftEvent]
)

type (
	watcherImpl[T watcherT] struct {
		nlWatcher nl.NetlinkWatcher
		que       queue.FIFO[T]
		ch        chan WatcherEvent[T]

		onceRun   sync.Once
		onceClose sync.Once
		stop      chan struct{}
		stopped   chan struct{}
	}
)

func newWatcher[T watcherT]() (*watcherImpl[T], error) {
	nlWatcher, err := makeNlWatcher[T]()
	if err != nil {
		return nil, err
	}

	return &watcherImpl[T]{
		nlWatcher: nlWatcher,
		que:       queue.NewFIFO[T](),
		stop:      make(chan struct{}),
	}, nil
}

// Stream - start streaming watching events
func (w *watcherImpl[T]) Stream(ctx context.Context) <-chan WatcherEvent[T] {
	const queSize = 100
	w.onceRun.Do(func() {
		w.ch = make(chan WatcherEvent[T], queSize)
		errCh := make(chan error, 1)
		go func() {
			defer close(errCh)
			errCh <- w.run(ctx)
		}()
		go func() {
			defer close(w.ch)

			for reader := w.que.Reader(); ; {
				select {
				case <-ctx.Done():
					return
				case <-w.stop:
					return
				case err := <-errCh:
					if err != nil {
						w.ch <- WatcherEvent[T]{Err: ErrWatcher{err}}
					}
					return
				case ln, ok := <-reader:
					if !ok {
						return
					}
					select {
					case <-ctx.Done():
						return
					case <-w.stop:
						return
					case w.ch <- WatcherEvent[T]{Evt: ln}:
					}
				}
			}
		}()
	})

	return w.ch
}

// Close watcher
func (w *watcherImpl[T]) Close() error {
	w.onceClose.Do(func() {
		close(w.stop)
		w.onceRun.Do(func() {})
		if w.stopped != nil {
			<-w.stopped
		}
		_ = w.nlWatcher.Close()
		_ = w.que.Close()
	})
	return nil
}

func (w *watcherImpl[T]) run(ctx context.Context) (err error) {
	w.stopped = make(chan struct{})
	defer close(w.stopped)

	for stm := w.nlWatcher.Stream(ctx); ; {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-w.stop:
			return nil
		case nlData, ok := <-stm:
			if !ok {
				return errors.New("netlink watcher has already closed")
			}
			err = nlData.Err
			messages := nlData.Messages

			if err != nil {
				if errors.Is(err, nl.ErrNlMem) {
					continue
				}
				if errors.Is(err, nl.ErrNlDataNotReady) ||
					errors.Is(err, nl.ErrNlReadInterrupted) {
					continue
				}

				return fmt.Errorf("failed to rcv nl message: %w", err)
			}

			for _, msg := range messages {
				err = w.handleNlMsg(msg)
				if err != nil && !errors.Is(err, ErrMismatchedNlMsgType) {
					return err
				}
			}
		}
	}
}

func (w *watcherImpl[T]) handleNlMsg(msg netlink.Message) (err error) {
	var (
		val any
		t   T
	)
	switch any(t).(type) {
	case LinkEvent:
		val, err = linkEvtFromNlMsg(nl.NetlinkNfMsg(msg))
	case RuleEvent:
		val, err = ruleEvtFromNlMsg(msg)
	case ChainEvent:
		val, err = chainEvtFromNlMsg(msg)
	case SetEvent:
		val, err = setEvtFromNlMsg(msg)
	case SetElementEvent:
		val, err = setElementEvtFromNlMsg(msg)
	case TableEvent:
		val, err = tableEvtFromNlMsg(msg)
	case NftEvent:
		val, err = nftEvtFromNlMsg(msg)
	default:
		err = fmt.Errorf("can't find netlink handler for the watcher type %T: %w",
			t, ErrUnsupportedWatcherType)
	}

	if err != nil {
		return err
	}

	w.que.Put(val.(T))
	return nil
}

func makeNlWatcher[T watcherT]() (nl.NetlinkWatcher, error) {
	var t T
	switch any(t).(type) {
	case LinkEvent:
		return nl.NewNetlinkWatcher(unix.NETLINK_ROUTE,
			nl.WithReadBuffLen(nl.SockBuffLen16MB),
			nl.WithNetlinkGroups(unix.RTMGRP_LINK, unix.RTMGRP_IPV4_IFADDR),
		)
	case RuleEvent, ChainEvent, SetEvent,
		SetElementEvent, TableEvent, NftEvent:
		return nl.NewNetlinkWatcher(unix.NETLINK_NETFILTER,
			nl.WithReadBuffLen(nl.SockBuffLen16MB),
			nl.WithNetlinkGroups(unix.NFNLGRP_NFTABLES),
		)
	}

	return nil, ErrUnsupportedWatcherType
}
