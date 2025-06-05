package watchers

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/H-BF/corlib/pkg/queue"
	"github.com/PRO-Robotech/nftrace/internal/nl"
	nftLib "github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"github.com/mdlayher/netlink"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sys/unix"
)

var (
	comment = "some comment"

	policy = nftLib.ChainPolicyAccept

	tbl = &nftLib.Table{
		Family: nftLib.TableFamilyIPv4,
		Name:   "tbl",
	}
	chain = &nftLib.Chain{
		Name:     "output",
		Hooknum:  nftLib.ChainHookOutput,
		Priority: nftLib.ChainPriorityFilter,
		Table:    tbl,
		Type:     nftLib.ChainTypeFilter,
		Policy:   &policy,
	}
	ipSet = &nftLib.Set{
		Name:     "ipSet",
		Table:    tbl,
		KeyType:  nftLib.TypeIPAddr,
		Constant: true,
		Interval: true,
	}
	setElems = []nftLib.SetElement{
		{
			Key: []byte(net.ParseIP("10.34.11.179").To4()),
		},
		{
			Key:         []byte(net.ParseIP("10.34.11.180").To4()),
			IntervalEnd: true,
		},
	}
	rule = &nftLib.Rule{
		Handle: 5,
		Table:  tbl,
		Chain:  chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},
			&expr.Counter{},
			&expr.Log{},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
		UserData: userdata.AppendString([]byte(nil), userdata.TypeComment, comment),
	}
)

type (
	ConnMock struct {
		*nftLib.Conn
	}
	Recorder struct {
		requests []netlink.Message
	}
	NlWatcherMock struct {
		mock.Mock
	}
)

func NewRecorder() *Recorder {
	return &Recorder{}
}

func (r *Recorder) Conn() (*ConnMock, error) {
	conn, err := nftLib.New(nftLib.WithTestDial(
		func(req []netlink.Message) ([]netlink.Message, error) {
			r.requests = append(r.requests, req...)

			acks := make([]netlink.Message, 0, len(req))
			for _, msg := range req {
				if msg.Header.Flags&netlink.Acknowledge != 0 {
					acks = append(acks, netlink.Message{
						Header: netlink.Header{
							Length:   4,
							Type:     netlink.Error,
							Sequence: msg.Header.Sequence,
							PID:      msg.Header.PID,
						},
						Data: []byte{0, 0, 0, 0},
					})
				}
			}
			return acks, nil
		}))
	if err != nil {
		return nil, err
	}

	return &ConnMock{conn}, err
}

// Requests returns the recorded netlink messages (typically nftables requests).
func (r *Recorder) Requests() []netlink.Message {
	return r.requests
}

func (m *NlWatcherMock) Stream(ctx context.Context) <-chan nl.NlData {
	ret := m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Stream")
	}

	var r0 <-chan nl.NlData
	if rf, ok := ret.Get(0).(func() <-chan nl.NlData); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(<-chan nl.NlData)
		}
	}

	return r0
}
func (r *NlWatcherMock) Close() error {
	return nil
}

type watchersTestSuite struct {
	suite.Suite
}

func Test_Watchers(t *testing.T) {
	suite.Run(t, new(watchersTestSuite))
}

func (sui *watchersTestSuite) Test_RuleWatcher() {
	doneCh := make(chan struct{})
	defer close(doneCh)

	nlWatcher := makeNlWatcherMock(sui.T(), doneCh)
	ruleWatcher := &watcherImpl[RuleEvent]{
		nlWatcher: nlWatcher,
		que:       queue.NewFIFO[RuleEvent](),
		stop:      make(chan struct{}),
	}
	expRuleExpr := `meta l4proto tcp counter packets 0 bytes 0 log accept comment "` + comment + `" # handle 5`
	expInfo := fmt.Sprintf(
		`%T: rule '%s' has added`, *new(RuleEvent), expRuleExpr,
	)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	stream := ruleWatcher.Stream(ctx)

	for data := range stream {
		sui.Require().NoError(data.Err)
		sui.Require().Equal(expInfo, data.Evt.ActionInfo())
		sui.Require().EqualValues(rule.Handle, data.Evt.Val.Handle)
		sui.Require().EqualValues(rule.Exprs, data.Evt.Val.Exprs)
		sui.Require().EqualValues(rule.Table, data.Evt.Val.Table)
		sui.Require().EqualValues(rule.Chain.Name, data.Evt.Val.Chain.Name)
		sui.Require().EqualValues(rule.Chain.Table, data.Evt.Val.Chain.Table)
		sui.Require().EqualValues(rule.UserData, data.Evt.Val.UserData)
	}

	ruleWatcher.Close()
	nlWatcher.AssertExpectations(sui.T())
}

func (sui *watchersTestSuite) Test_ChainWatcher() {
	doneCh := make(chan struct{})
	defer close(doneCh)

	nlWatcher := makeNlWatcherMock(sui.T(), doneCh)
	chainWatcher := &watcherImpl[ChainEvent]{
		nlWatcher: nlWatcher,
		que:       queue.NewFIFO[ChainEvent](),
		stop:      make(chan struct{}),
	}
	expInfo := fmt.Sprintf(
		`%T: chain '%s' has added`, *new(ChainEvent), chain.Name,
	)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	stream := chainWatcher.Stream(ctx)

	for data := range stream {
		sui.Require().NoError(data.Err)
		sui.Require().Equal(expInfo, data.Evt.ActionInfo())
		sui.Require().EqualValues(chain, data.Evt.Val)
	}

	chainWatcher.Close()
	nlWatcher.AssertExpectations(sui.T())
}

func (sui *watchersTestSuite) Test_TableWatcher() {
	doneCh := make(chan struct{})
	defer close(doneCh)

	nlWatcher := makeNlWatcherMock(sui.T(), doneCh)
	tableWatcher := &watcherImpl[TableEvent]{
		nlWatcher: nlWatcher,
		que:       queue.NewFIFO[TableEvent](),
		stop:      make(chan struct{}),
	}
	expInfo := fmt.Sprintf(
		`%T: table '%s' has added`, *new(TableEvent), tbl.Name,
	)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	stream := tableWatcher.Stream(ctx)

	for data := range stream {
		sui.Require().NoError(data.Err)
		sui.Require().Equal(expInfo, data.Evt.ActionInfo())
		sui.Require().EqualValues(tbl, data.Evt.Val)
	}

	tableWatcher.Close()
	nlWatcher.AssertExpectations(sui.T())
}

func (sui *watchersTestSuite) Test_SetWatcher() {
	doneCh := make(chan struct{})
	defer close(doneCh)

	nlWatcher := makeNlWatcherMock(sui.T(), doneCh)
	setWatcher := &watcherImpl[SetEvent]{
		nlWatcher: nlWatcher,
		que:       queue.NewFIFO[SetEvent](),
		stop:      make(chan struct{}),
	}
	expInfo := fmt.Sprintf(
		`%T: set '%s' has added`, *new(SetEvent), ipSet.Name,
	)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	stream := setWatcher.Stream(ctx)

	for data := range stream {
		sui.Require().NoError(data.Err)
		sui.Require().Equal(expInfo, data.Evt.ActionInfo())
		sui.Require().EqualValues(ipSet, data.Evt.Val)
	}

	setWatcher.Close()
	nlWatcher.AssertExpectations(sui.T())
}

func (sui *watchersTestSuite) Test_SetElementWatcher() {
	doneCh := make(chan struct{})
	defer close(doneCh)

	nlWatcher := makeNlWatcherMock(sui.T(), doneCh)
	setElementWatcher := &watcherImpl[SetElementEvent]{
		nlWatcher: nlWatcher,
		que:       queue.NewFIFO[SetElementEvent](),
		stop:      make(chan struct{}),
	}
	expInfo := fmt.Sprintf(
		`%T: set element has added`, *new(SetElementEvent),
	)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	stream := setElementWatcher.Stream(ctx)

	for data := range stream {
		sui.Require().NoError(data.Err)
		sui.Require().Equal(expInfo, data.Evt.ActionInfo())
		sui.Require().EqualValues(setElems[0], data.Evt.Val.Elems[0])
		sui.Require().EqualValues(tbl, data.Evt.Val.Table)
	}

	setElementWatcher.Close()
	nlWatcher.AssertExpectations(sui.T())
}

func (sui *watchersTestSuite) Test_NftWatcher() {
	doneCh := make(chan struct{})
	defer close(doneCh)

	nlWatcher := makeNlWatcherMock(sui.T(), doneCh)
	nftWatcher := &watcherImpl[NftEvent]{
		nlWatcher: nlWatcher,
		que:       queue.NewFIFO[NftEvent](),
		stop:      make(chan struct{}),
	}
	expRuleExpr := `meta l4proto tcp counter packets 0 bytes 0 log accept comment "` + comment + `" # handle 5`
	expRuleInfo := fmt.Sprintf(
		`%T: rule '%s' has added`, *new(RuleEvent), expRuleExpr,
	)
	expChainInfo := fmt.Sprintf(
		`%T: chain '%s' has added`, *new(ChainEvent), chain.Name,
	)
	expSetInfo := fmt.Sprintf(
		`%T: set '%s' has added`, *new(SetEvent), ipSet.Name,
	)
	expSetElemInfo := fmt.Sprintf(
		`%T: set element has added`, *new(SetElementEvent),
	)
	expTblInfo := fmt.Sprintf(
		`%T: table '%s' has added`, *new(TableEvent), tbl.Name,
	)

	var ruleOk, chainOk, setOk, setElemOk, tableOk bool

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	stream := nftWatcher.Stream(ctx)

	for data := range stream {
		sui.Require().NoError(data.Err)
		switch data.Evt.Val.(type) {
		case RuleEvent:
			sui.Require().Equal(expRuleInfo, data.Evt.ActionInfo())
			ruleOk = true
		case ChainEvent:
			sui.Require().Equal(expChainInfo, data.Evt.ActionInfo())
			chainOk = true
		case SetEvent:
			sui.Require().Equal(expSetInfo, data.Evt.ActionInfo())
			setOk = true
		case SetElementEvent:
			sui.Require().Equal(expSetElemInfo, data.Evt.ActionInfo())
			setElemOk = true
		case TableEvent:
			sui.Require().Equal(expTblInfo, data.Evt.ActionInfo())
			tableOk = true
		default:
			sui.T().Fatalf("unexpected event type: %T", data.Evt.Val)
		}
	}

	sui.Require().True(ruleOk, "RuleEvent not received")
	sui.Require().True(chainOk, "ChainEvent not received")
	sui.Require().True(setOk, "SetEvent not received")
	sui.Require().True(setElemOk, "SetElementEvent not received")
	sui.Require().True(tableOk, "TableEvent not received")

	nftWatcher.Close()
	nlWatcher.AssertExpectations(sui.T())
}

func makeNlWatcherMock(t *testing.T, doneCh <-chan struct{}) *NlWatcherMock {
	nlWatcher := NlWatcherMock{}
	nlWatcher.On("Stream", mock.Anything).
		Maybe().
		Return(func() <-chan nl.NlData {
			out := make(chan nl.NlData)
			rec := NewRecorder()
			c, err := rec.Conn()
			if err != nil {
				t.Fatal(err)
			}

			fillRuleset(c)
			if err := c.Flush(); err != nil {
				t.Fatal(err)
			}
			go func() {
				defer close(out)
				out <- nl.NlData{Messages: rec.Requests()}
				<-doneCh
			}()
			return out
		}())
	return &nlWatcher
}

func fillRuleset(c *ConnMock) error {
	c.AddTable(tbl)
	c.AddChain(chain)
	if err := c.AddSet(ipSet, setElems); err != nil {
		return err
	}
	c.AddRule(rule)
	return nil
}
