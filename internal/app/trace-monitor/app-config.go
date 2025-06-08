package trace_monitor

import (
	"flag"
)

var (
	SampleRate     uint64
	LogLevel       string
	BuffSize       int
	EvRate         uint64
	CollectorType  string
	UseAggregation bool
	JsonFormat     bool
)

const (
	Mem16MB   = 16777216
	DefEvRate = 10
)

func init() {
	flag.Uint64Var(&SampleRate, "rate", 0, "sample rate value for the tracing")
	flag.IntVar(&BuffSize, "size", Mem16MB, "receive ring buffer size in bytes")
	flag.StringVar(&LogLevel, "level", "INFO", "log level: INFO|DEBUG|WARN|ERROR|PANIC|FATAL")
	flag.Uint64Var(&EvRate, "ev", DefEvRate, "produce events per second: 1...100")
	flag.StringVar(&CollectorType, "c", "ebpf", "type of collector: ebpf|netlink")
	flag.BoolVar(&UseAggregation, "a", false, "use aggregation")
	flag.BoolVar(&JsonFormat, "j", false, "print in json format")
	flag.Parse()
}
