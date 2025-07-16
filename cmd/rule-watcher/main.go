package main

import (
	"sync"

	"github.com/PRO-Robotech/nftrace/internal/app"
	. "github.com/PRO-Robotech/nftrace/internal/app/nft-watcher" //nolint:revive
	"github.com/PRO-Robotech/nftrace/pkg/watchers"

	"github.com/H-BF/corlib/logger"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func main() {
	app.SetupContext()
	ctx := app.Context()
	logger.SetLevel(zap.InfoLevel)
	logger.InfoKV(ctx, "-= HELLO =-", "version", app.GetVersion())

	if err := app.SetupLogger(LogLevel); err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "setup logger"))
	}

	ruleWatcher, err := watchers.RuleWatcher()
	if err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "create rule watcher"))
	}
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer func() {
			_ = ruleWatcher.Close()
			wg.Done()
		}()
		stm := ruleWatcher.Stream(ctx)
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
