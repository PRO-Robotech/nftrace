package collectors

import (
	"context"
)

type (
	// TraceCollector - common interface to collect traces
	TraceCollector interface {
		Collect(ctx context.Context) <-chan CollectorMsg
		Close() error
	}

	Telemetry interface {
		isMetrics()
	}
)
