package collector

import (
	"github.com/PRO-Robotech/nftrace"
	"github.com/PRO-Robotech/nftrace/internal/collectors"
	"github.com/PRO-Robotech/nftrace/internal/collectors/ebpf"
	"github.com/PRO-Robotech/nftrace/internal/collectors/netlink"
)

type (
	cfgType interface {
		EbpfCfg | NetlinkCfg
	}

	metricsType interface {
		EbpfMetrics | NetlinkMetrics
	}

	EbpfCfg    = ebpf.Config
	NetlinkCfg = netlink.Config

	EbpfMetrics    = ebpf.Metrics
	NetlinkMetrics = netlink.Metrics

	Msg struct {
		Trace   nftrace.Trace
		Metrics collectors.Telemetry
		Err     error
	}
)

var (
	EbpfMetricsFromMsg    = MetricsFromMsg[EbpfMetrics]
	NetlinkMetricsFromMsg = MetricsFromMsg[NetlinkMetrics]
)

func MetricsFromMsg[M metricsType](msg Msg) M {
	var metrics M
	switch t := any(msg.Metrics).(type) {
	case EbpfMetrics:
		metrics = any(t).(M)
	case NetlinkMetrics:
		metrics = any(t).(M)
	}
	return metrics
}
