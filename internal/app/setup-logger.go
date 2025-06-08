package app

import (
	"github.com/H-BF/corlib/logger"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// SetupLogger setup app logger
func SetupLogger(lvl string) error {
	var l logger.LogLevel
	if e := l.UnmarshalText([]byte(lvl)); e != nil {
		return errors.Wrapf(e, "recognize '%s' logger level from config", lvl)
	}
	logger.SetLevel(l)
	return nil
}

type disabledLevel struct{}

func (disabledLevel) Enabled(zapcore.Level) bool { return false }

func NopLogger() logger.TypeOfLogger {
	return logger.TypeOfLogger{
		LevelEnabler:  disabledLevel{},
		SugaredLogger: zap.NewNop().Sugar(),
	}
}
