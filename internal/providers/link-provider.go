package providers

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/PRO-Robotech/nftrace/internal/app"

	"github.com/H-BF/corlib/logger"
	nl "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type (
	Link struct {
		Name  string
		Index int
	}

	linkProvider struct {
		cache  cache[int, Link]
		cancel context.CancelFunc

		lastErr atomic.Value
	}
)

var _ LinkProvider = (*linkProvider)(nil)

func NewLinkProvider(ctx context.Context, useLogging bool) (*linkProvider, error) {
	ctx, cancel := context.WithCancel(ctx)

	lp := &linkProvider{
		cancel: cancel,
	}

	if !useLogging {
		logger.ToContext(ctx, app.NopLogger())
	}

	if err := lp.reloadCache(); err != nil {
		cancel()
		return nil, err
	}

	go lp.run(ctx)

	return lp, nil
}

func (lp *linkProvider) LinkByIndex(idx int) (Link, error) {
	if err, ok := lp.lastErr.Load().(error); ok && err != nil {
		return Link{}, err
	}

	if v, ok := lp.cache.Get(idx); ok {
		return v, nil
	}

	nl, err := nl.LinkByIndex(idx)
	if err != nil {
		return Link{}, fmt.Errorf("link %d not found: %w", idx, err)
	}
	l := Link{Name: nl.Attrs().Name, Index: nl.Attrs().Index}
	lp.cache.Put(l.Index, l)
	return l, nil
}

func (lp *linkProvider) Close() error {
	lp.cancel()
	return nil
}

func (lp *linkProvider) run(ctx context.Context) {
	updates := make(chan nl.LinkUpdate)
	done := make(chan struct{})
	if err := nl.LinkSubscribe(updates, done); err != nil {
		lp.fatal(err)
		return
	}
	log := logger.FromContext(ctx).Named("link-provider")
	log.Info("started, listening for link changes")

	defer func() {
		close(done)
		log.Info("stopped")
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case u, ok := <-updates:
			if !ok {
				lp.fatal(errors.New("netlink: update channel closed"))
				return
			}
			attrs := u.Attrs()
			action := "unknown"
			switch u.Header.Type {
			case unix.RTM_NEWLINK:
				action = "added"
				lp.cache.Put(attrs.Index, Link{Name: attrs.Name, Index: attrs.Index})
			case unix.RTM_DELLINK:
				action = "removed"
				lp.cache.Del(attrs.Index)
			}
			log.Debugf("received link event: %s has %s", attrs.Name, action)
		}
	}
}

func (lp *linkProvider) fatal(err error) {
	lp.lastErr.Store(err)
	lp.cancel()
}

func (lp *linkProvider) reloadCache() error {
	list, err := nl.LinkList()
	if err != nil {
		return fmt.Errorf("link list: %w", err)
	}
	lp.cache.Clear()
	for _, l := range list {
		attrs := l.Attrs()
		lp.cache.Put(attrs.Index, Link{Name: attrs.Name, Index: attrs.Index})
	}
	return nil
}
