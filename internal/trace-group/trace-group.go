package tracegroup

import (
	"strings"

	model "github.com/PRO-Robotech/nftrace"
	"github.com/PRO-Robotech/nftrace/internal/collectors"
	"github.com/PRO-Robotech/nftrace/internal/providers"

	"github.com/Morwran/nft-go/pkg/nftenc"
	"github.com/Morwran/nft-go/pkg/protocols"
	nftLib "github.com/google/nftables"
	"github.com/pkg/errors"
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

func NewTraceGroup(iface providers.LinkProvider, rule providers.RuleProvider) *TraceGroup {
	return &TraceGroup{
		link:       iface,
		rule:       rule,
		traceCache: make(map[uint32][]collectors.NftTrace),
	}
}

func (t *TraceGroup) AddTrace(tr collectors.NftTrace) error {
	if _, ok := traceTypes[tr.Type]; !ok {
		return errors.Wrapf(ErrUnknownTraceType, "type=%d", tr.Type)
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
		return m, errors.New("failed to find trace of rule type")
	}

	humanRule, err := t.rule.GetHumanRule(model.RuleDescriptor{
		TableName:   t.topTrace.Table,
		ChainName:   t.topTrace.Chain,
		RuleHandle:  t.topTrace.RuleHandle,
		TableFamily: nftLib.TableFamily(t.topTrace.Family),
	})
	if err != nil {
		return m, errors.WithMessagef(err, "trace data: %+v", t.topTrace)
	}

	iifname := t.topTrace.Iifname
	oifname := t.topTrace.Oifname

	if iifname == "" && t.topTrace.Iif != 0 {
		lk, err := t.link.LinkByIndex(int(t.topTrace.Iif))
		if err != nil {
			return m, errors.WithMessagef(err,
				"failed to find ifname for the ingress traffic by interface id=%d",
				int(t.topTrace.Iif))
		}
		iifname = lk.Name
	}
	if oifname == "" && t.topTrace.Oif != 0 {
		lk, err := t.link.LinkByIndex(int(t.topTrace.Oif))
		if err != nil {
			return m, errors.WithMessagef(err,
				"failed to find ifname for the egress traffic by interface id=%d",
				int(t.topTrace.Oif))
		}
		oifname = lk.Name
	}

	m = model.Trace{
		TrId:       t.topTrace.Id,
		Table:      t.topTrace.Table,
		Chain:      t.topTrace.Chain,
		JumpTarget: t.topTrace.JumpTarget,
		RuleHandle: t.topTrace.RuleHandle,
		Family:     nftenc.TableFamily(t.topTrace.Family).String(),
		Iifname:    iifname,
		Oifname:    oifname,
		SMacAddr:   t.topTrace.SMacAddr,
		DMacAddr:   t.topTrace.DMacAddr,
		SAddr:      t.topTrace.SAddr,
		DAddr:      t.topTrace.DAddr,
		SPort:      t.topTrace.SPort,
		DPort:      t.topTrace.DPort,
		Length:     t.topTrace.Length,
		IpProto:    protocols.ProtoType(t.topTrace.IpProtocol).String(),
		Verdict:    verdict.String(),
		Rule:       humanRule,
		Cnt:        t.topTrace.Cnt,
	}

	return m, nil
}

var traceTypes = map[uint32]string{
	unix.NFT_TRACETYPE_RULE:   "rule",
	unix.NFT_TRACETYPE_RETURN: "return",
	unix.NFT_TRACETYPE_POLICY: "policy",
}

var (
	ErrUnknownTraceType = errors.New("unknown trace type")
	ErrTraceGroupEmpty  = errors.New("trace group is empty")
)
