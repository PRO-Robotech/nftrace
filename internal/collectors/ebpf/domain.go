package ebpf

import (
	"bytes"

	"github.com/PRO-Robotech/nftrace/internal/collectors"
	"github.com/PRO-Robotech/nftrace/internal/decoders"
)

const (
	IPVersion4 = 4
	IPVersion6 = 6
)

const (
	MaxConnectionsPerSec = 200000
	MaxCPUs              = 128
	kProbeBreakPoint     = "nft_trace_notify"
	readerQueSize        = 1024
)

type (
	EbpfTrace struct {
		bpfTraceInfo
		ReadyMsk bool
		metrics  Metrics
	}

	Metrics struct {
		collectors.Telemetry
		PktCnt      uint64
		LostSamples uint64
	}
)

func (trace *EbpfTrace) ToNftTrace() collectors.NftTrace {
	return collectors.NftTrace{
		TraceHash:  trace.TraceHash,
		Table:      decoders.FastBytes2String(bytes.TrimRight(trace.TableName[:], "\x00")),
		Chain:      decoders.FastBytes2String(bytes.TrimRight(trace.ChainName[:], "\x00")),
		JumpTarget: decoders.FastBytes2String(bytes.TrimRight(trace.JumpTarget[:], "\x00")),
		RuleHandle: trace.RuleHandle,
		Family:     trace.Family,
		Type:       uint32(trace.Type),
		Id:         trace.Id,
		Iif:        trace.Iif,
		Oif:        trace.Oif,
		Mark:       trace.Mark,
		Verdict:    trace.Verdict,
		Nfproto:    uint32(trace.Nfproto),
		Policy:     uint32(trace.Policy),
		Iiftype:    trace.IifType,
		Oiftype:    trace.OifType,
		Iifname:    decoders.FastBytes2String(bytes.TrimRight(trace.IifName[:], "\x00")),
		Oifname:    decoders.FastBytes2String(bytes.TrimRight(trace.OifName[:], "\x00")),
		SMacAddr:   decoders.FastHardwareAddr(trace.SrcMac[:]).String(),
		DMacAddr:   decoders.FastHardwareAddr(trace.DstMac[:]).String(),
		IpVersion:  trace.IpVersion,
		SAddr:      decoders.Ip2String(trace.IpVersion == IPVersion6, trace.SrcIp, trace.SrcIp6.In6U.U6Addr8[:]),
		DAddr:      decoders.Ip2String(trace.IpVersion == IPVersion6, trace.DstIp, trace.DstIp6.In6U.U6Addr8[:]),
		SPort:      uint32(trace.SrcPort),
		DPort:      uint32(trace.DstPort),
		Length:     uint32(trace.Len),
		IpProtocol: trace.IpProto,
		Cnt:        trace.Counter,
		ReadyMsk:   trace.ReadyMsk,
		Metrics:    trace.metrics,
	}
}
