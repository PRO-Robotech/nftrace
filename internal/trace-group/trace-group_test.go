package tracegroup

import (
	"testing"

	"github.com/PRO-Robotech/nftrace/internal/collectors"
	"github.com/PRO-Robotech/nftrace/internal/providers"

	nfte "github.com/google/nftables/expr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const (
	ifaceName = "eth0"
)

type (
	DepsMock struct {
		iface providers.LinkProvider
		rule  providers.RuleProvider
	}
	LinkProviderMock struct {
		mock.Mock
	}
	ruleProviderMock struct {
		mock.Mock
	}
)

func (i *LinkProviderMock) LinkByIndex(index int) (providers.Link, error) {
	return providers.Link{Name: ifaceName}, nil
}

func (i *LinkProviderMock) Close() error {
	return nil
}

func (r *ruleProviderMock) GetHumanRule(tr providers.RuleKey) (string, error) {
	return "mocked rule", nil
}

func (r *ruleProviderMock) Close() error {
	return nil
}

func Test_TraceGroup(t *testing.T) {
	verdictGoTo := nfte.VerdictGoto
	verdictContinue := nfte.VerdictContinue
	testCases := []struct {
		name       string
		data       []collectors.NftTrace
		verdict    string
		expHandle  uint64
		checkReady bool
		mock       DepsMock
	}{
		{
			name:       "single trace type of rule with accept",
			data:       []collectors.NftTrace{{Type: unix.NFT_TRACETYPE_RULE, RuleHandle: 1, Verdict: uint32(nfte.VerdictAccept)}},
			verdict:    "rule::accept",
			expHandle:  1,
			checkReady: true,
			mock:       DepsMock{&LinkProviderMock{}, &ruleProviderMock{}},
		},
		{
			name:      "single trace type of rule with goto",
			data:      []collectors.NftTrace{{Type: unix.NFT_TRACETYPE_RULE, RuleHandle: 1, Verdict: uint32(verdictGoTo)}},
			verdict:   "rule::goto",
			expHandle: 1,
			mock:      DepsMock{&LinkProviderMock{}, &ruleProviderMock{}},
		},
		{
			name: "multiple traces with return and policy accept",
			data: []collectors.NftTrace{
				{Type: unix.NFT_TRACETYPE_RULE, RuleHandle: 1, Verdict: uint32(verdictGoTo)},
				{Type: unix.NFT_TRACETYPE_RETURN, RuleHandle: 2, Verdict: uint32(verdictContinue)},
				{Type: unix.NFT_TRACETYPE_POLICY, Policy: uint32(nfte.VerdictAccept)},
			},
			verdict:    "rule::goto->policy::accept",
			expHandle:  1,
			checkReady: true,
			mock:       DepsMock{&LinkProviderMock{}, &ruleProviderMock{}},
		},
		{
			name: "multiple traces with return rule with handle 0 and policy accept",
			data: []collectors.NftTrace{
				{Type: unix.NFT_TRACETYPE_RULE, RuleHandle: 1, Verdict: uint32(verdictGoTo)},
				{Type: unix.NFT_TRACETYPE_RULE, RuleHandle: 0, Verdict: uint32(verdictContinue)},
				{Type: unix.NFT_TRACETYPE_POLICY, Policy: uint32(nfte.VerdictAccept)},
			},
			verdict:    "rule::goto->rule::continue->policy::accept",
			expHandle:  1,
			checkReady: true,
			mock:       DepsMock{&LinkProviderMock{}, &ruleProviderMock{}},
		},
		{
			name: "multiple traces with double rule accepts",
			data: []collectors.NftTrace{
				{Type: unix.NFT_TRACETYPE_RULE, RuleHandle: 1, Verdict: uint32(verdictGoTo)},
				{Type: unix.NFT_TRACETYPE_RULE, RuleHandle: 2, Verdict: uint32(nfte.VerdictAccept)},
			},
			verdict:    "rule::goto->rule::accept",
			expHandle:  1,
			checkReady: true,
			mock:       DepsMock{&LinkProviderMock{}, &ruleProviderMock{}},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tg := NewTraceGroup(tc.mock.iface, tc.mock.rule)
			for i := range tc.data {
				require.False(t, tg.GroupReady())
				require.NoError(t, tg.AddTrace(tc.data[i]))
			}
			if tc.checkReady {
				require.True(t, tg.GroupReady())
			}
			md, err := tg.ToModel()
			require.NoError(t, err)
			require.Equal(t, tc.verdict, md.Verdict)
			require.Equal(t, tc.expHandle, md.Handle)
			tg.Close()
		})
	}
}
