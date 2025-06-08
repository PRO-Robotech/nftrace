package trace_monitor

import (
	"strings"

	"github.com/PRO-Robotech/nftrace/pkg/collector"

	"github.com/pkg/errors"
)

type (
	collectorConstrutor func() (collector.TraceCollector, error)
)

var collectorConstrutors = map[string]collectorConstrutor{
	"ebpf":    setupEbpfCollector,
	"netlink": setupNetlinkCollector,
}

func SetupCollector() (collector.TraceCollector, error) {
	collector, ok := collectorConstrutors[strings.ToLower(strings.TrimSpace(CollectorType))]
	if !ok {
		return nil, errors.Errorf("unknown trace collector type '%s'", CollectorType)
	}
	return collector()
}

func setupNetlinkCollector() (collector.TraceCollector, error) {
	return collector.NewNetlinkTraceCollector(
		collector.NetlinkCfg{
			NlBuffLen: BuffSize,
		},
		true,
	)
}

func setupEbpfCollector() (collector.TraceCollector, error) {
	return collector.NewEbpfTraceCollector(
		collector.EbpfCfg{
			SampleRate:     SampleRate,
			RingBuffSize:   BuffSize,
			UseAggregation: UseAggregation,
			EventsRate:     EvRate,
		},
		true,
	)
}
