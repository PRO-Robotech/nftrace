package linkwatcher

import (
	"flag"
)

var (
	LogLevel string
)

func init() {
	flag.StringVar(&LogLevel, "level", "INFO", "log level: INFO|DEBUG|WARN|ERROR|PANIC|FATAL")
	flag.Parse()
}
