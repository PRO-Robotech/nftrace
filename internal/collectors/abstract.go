package collectors

import (
	"context"

	"github.com/PRO-Robotech/nftrace"
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

	LinkProvider interface {
		LinkByIndex(int) (string, error)
	}

	RuleProvider interface {
		GetHumanRule(nftrace.RuleDescriptor) (string, error)
	}
)
