package tracegroup

import (
	"errors"
	"fmt"
	"strings"

	model "github.com/PRO-Robotech/nftrace"
	"github.com/PRO-Robotech/nftrace/internal/collectors"
	"github.com/PRO-Robotech/nftrace/internal/providers"

	"github.com/Morwran/nft-go/pkg/nftenc"
	"github.com/Morwran/nft-go/pkg/protocols"
	nftLib "github.com/google/nftables"
	"golang.org/x/sys/unix"
)

type (
	TraceGroup struct {
		link       providers.LinkProvider
		rule       providers.RuleProvider
		topTrace   collectors.NftTrace
		traceCache map[uint32][]collectors.NftTrace
	}
)

func NewTraceGroup(link providers.LinkProvider, rule providers.RuleProvider) *TraceGroup {
	return &TraceGroup{
		link:       link,
		rule:       rule,
		traceCache: make(map[uint32][]collectors.NftTrace),
	}
}

func (t *TraceGroup) Handle(tr collectors.NftTrace, cb func(model.Trace, collectors.Telemetry)) error {
	if err := t.AddTrace(tr); err != nil {
		return err
	}
	if !t.GroupReady() {
		return ErrTraceDataNotReady
	}
	m, err := t.ToModel()
	if err != nil {
		return fmt.Errorf("failed to convert obtained trace into model: %w", err)
	}
	t.Reset()

	if cb != nil {
		cb(m, tr.Metrics)
	}

	return nil
}

func (t *TraceGroup) AddTrace(tr collectors.NftTrace) error {
	if _, ok := traceTypes[tr.Type]; !ok {
		return fmt.Errorf("type=%d: %w", tr.Type, ErrUnknownTraceType)
	}

	if tr.Type == unix.NFT_TRACETYPE_POLICY {
		tr.Verdict = tr.Policy
	}
	t.traceCache[tr.Id] = append(t.traceCache[tr.Id], tr)
	t.topTrace = tr
	return nil
}

func (t *TraceGroup) GroupReady() bool {
	if len(t.traceCache) == 0 {
		return false
	}
	v := nftenc.VerdictKind(t.topTrace.Verdict).String()
	return (v == nftenc.VerdictAccept || v == nftenc.VerdictDrop) || t.topTrace.ReadyMsk
}

func (t *TraceGroup) Close() {
	t.traceCache = nil
	t.topTrace.Reset()
}

func (t *TraceGroup) Reset() {
	delete(t.traceCache, t.topTrace.Id)
	t.topTrace.Reset()
}

func (t *TraceGroup) ToModel() (m model.Trace, err error) {
	verdict := strings.Builder{}
	traces, ok := t.traceCache[t.topTrace.Id]
	if !ok {
		return m, ErrTraceGroupEmpty
	}
	t.topTrace.Reset()
	for i, tr := range traces {
		if tr.Type == unix.NFT_TRACETYPE_RETURN {
			continue
		}
		verdict.WriteString(traceTypes[tr.Type])
		verdict.WriteString("::")
		v := nftenc.VerdictKind(int32(tr.Verdict)).String() //nolint:gosec
		verdict.WriteString(v)
		if v != nftenc.VerdictDrop && v != nftenc.VerdictAccept && i < len(traces)-1 {
			verdict.WriteString("->")
		}
		if tr.Type == unix.NFT_TRACETYPE_RULE && tr.RuleHandle != 0 && t.topTrace.RuleHandle == 0 {
			t.topTrace = tr
		}
	}

	if t.topTrace.Type != unix.NFT_TRACETYPE_RULE {
		return m, errors.New("can't find trace of rule type")
	}

	humanRule, err := t.rule.GetHumanRule(providers.RuleKey{
		TableName:   t.topTrace.Table,
		ChainName:   t.topTrace.Chain,
		Handle:      t.topTrace.RuleHandle,
		TableFamily: nftLib.TableFamily(t.topTrace.Family),
	})
	if err != nil {
		return m, fmt.Errorf("trace data: %+v: %w", t.topTrace, err)
	}

	iifname := t.topTrace.Iifname
	oifname := t.topTrace.Oifname

	if iifname == "" && t.topTrace.Iif != 0 {
		lk, err := t.link.LinkByIndex(int(t.topTrace.Iif))
		if err != nil {
			return m, fmt.Errorf(
				"failed to find link by interface id=%d: %w",
				int(t.topTrace.Iif), err)
		}
		iifname = lk.Name
	}
	if oifname == "" && t.topTrace.Oif != 0 {
		lk, err := t.link.LinkByIndex(int(t.topTrace.Oif))
		if err != nil {
			return m, fmt.Errorf(
				"failed to find link by interface id=%d: %w",
				int(t.topTrace.Oif), err)
		}
		oifname = lk.Name
	}

	m = model.Trace{
		ID:        t.topTrace.Id,
		Table:     t.topTrace.Table,
		Chain:     t.topTrace.Chain,
		Jump:      t.topTrace.JumpTarget,
		Handle:    t.topTrace.RuleHandle,
		Family:    nftenc.TableFamily(t.topTrace.Family).String(),
		IIF:       iifname,
		OIF:       oifname,
		SMAC:      t.topTrace.SMacAddr,
		DMAC:      t.topTrace.DMacAddr,
		SAddr:     t.topTrace.SAddr,
		DAddr:     t.topTrace.DAddr,
		SPort:     t.topTrace.SPort,
		DPort:     t.topTrace.DPort,
		Len:       t.topTrace.Length,
		Proto:     protocols.ProtoType(t.topTrace.IpProtocol).String(),
		Verdict:   verdict.String(),
		Rule:      humanRule,
		IpVersion: t.topTrace.IpVersion,
		Cnt:       t.topTrace.Cnt,
	}

	return m, nil
}

var traceTypes = map[uint32]string{
	unix.NFT_TRACETYPE_RULE:   "rule",
	unix.NFT_TRACETYPE_RETURN: "return",
	unix.NFT_TRACETYPE_POLICY: "policy",
}

var (
	ErrUnknownTraceType  = errors.New("unknown trace type")
	ErrTraceGroupEmpty   = errors.New("trace group is empty")
	ErrTraceDataNotReady = errors.New("trace data is not ready")
)
