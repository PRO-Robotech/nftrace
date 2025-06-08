package main

import (
	"sync"

	"github.com/PRO-Robotech/nftrace/internal/app"
	. "github.com/PRO-Robotech/nftrace/internal/app/link-watcher" //nolint:revive

	"github.com/H-BF/corlib/logger"
	"github.com/pkg/errors"
	nl "github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

func main() {
	app.SetupContext()
	ctx := app.Context()
	logger.SetLevel(zap.InfoLevel)
	logger.InfoKV(ctx, "-= HELLO =-", "version", app.GetVersion())

	if err := app.SetupLogger(LogLevel); err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "setup logger"))
	}

	updates := make(chan nl.LinkUpdate)
	done := make(chan struct{})
	if err := nl.LinkSubscribe(updates, done); err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "subscribe link watcher"))
		return
	}
	defer close(done)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()

		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-updates:
				if !ok {
					return
				}
				attrs := msg.Attrs()
				switch msg.Header.Type {
				case unix.RTM_NEWLINK:
					logger.Infof(ctx, "%s added", attrs.Name)
				case unix.RTM_DELLINK:
					logger.Infof(ctx, "%s removed", attrs.Name)
				}
			}
		}
	}()
	wg.Wait()
	logger.SetLevel(zap.InfoLevel)
	logger.Info(ctx, "-= BYE =-")
}
