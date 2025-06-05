package main

import (
	"sync"

	"github.com/PRO-Robotech/nftrace/internal/app"
	. "github.com/PRO-Robotech/nftrace/internal/app/link-watcher" //nolint:revive
	"github.com/PRO-Robotech/nftrace/pkg/watchers"

	"github.com/H-BF/corlib/logger"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func main() {
	SetupContext()
	ctx := app.Context()
	logger.SetLevel(zap.InfoLevel)
	logger.InfoKV(ctx, "-= HELLO =-", "version", app.GetVersion())

	if err := SetupLogger(LogLevel); err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "setup logger"))
	}

	linkWatcher, err := watchers.NftWatcher()
	if err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "create link watcher"))
	}
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer func() {
			linkWatcher.Close()
			wg.Done()
		}()
		stm := linkWatcher.Stream(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-stm:
				if !ok {
					return
				}

				logger.Infof(ctx, "%s", msg.Evt.ActionInfo())
			}
		}
	}()
	wg.Wait()
	logger.SetLevel(zap.InfoLevel)
	logger.Info(ctx, "-= BYE =-")
}
