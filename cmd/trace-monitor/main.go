package main

import (
	"fmt"
	"os"
	"sync"

	"github.com/PRO-Robotech/nftrace/internal/app"
	. "github.com/PRO-Robotech/nftrace/internal/app/trace-monitor"

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
	collector, err := SetupCollector()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup collector: %v\n", err)
		os.Exit(1)
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer func() {
			_ = collector.Close()
			wg.Done()
		}()

		for stm := collector.Collect(ctx); ; {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-stm:
				if !ok {
					return
				}
				if JsonFormat {
					logger.InfoKV(ctx, "", "trace", msg.Trace)
				} else {
					logger.Infof(ctx, "%s", msg.Trace.FiveTupleFormat())
				}
			}
		}
	}()
	wg.Wait()

	logger.SetLevel(zap.InfoLevel)
	logger.Info(ctx, "-= BYE =-")
}
