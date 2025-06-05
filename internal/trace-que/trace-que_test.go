package cachedque

import (
	"testing"
	"time"

	"github.com/PRO-Robotech/nftrace"

	"github.com/stretchr/testify/suite"
)

type cachedQueTestSuite struct {
	suite.Suite
}

func Test_CachedQueTests(t *testing.T) {
	suite.Run(t, new(cachedQueTestSuite))
}

func (sui *cachedQueTestSuite) Test_Enque() {
	testCases := []struct {
		name string
		data []nftrace.Trace
	}{
		{
			name: "single input data",
			data: []nftrace.Trace{{TrId: 1}},
		},
		{
			name: "multiple input data",
			data: []nftrace.Trace{{TrId: 1}, {TrId: 2}, {TrId: 3}},
		},
	}
	for _, tc := range testCases {
		sui.Run(tc.name, func() {
			f := NewCachedQue(10)
			r := f.Reader()
			rd := func() (ret nftrace.Trace) {
				select {
				case ret = <-r:
				case <-time.After(time.Second):
				}
				return ret
			}
			sui.Require().Equal(0, len(f.cache))
			var got []nftrace.Trace
			f.Enque(tc.data...)
			sui.Require().Equal(0, len(f.cache))
			for range len(tc.data) {
				got = append(got, rd())
			}
			sui.Require().Equal(tc.data, got)
		})
	}
}

func (sui *cachedQueTestSuite) Test_Aggregate() {
	tc := struct {
		keys []uint64
		data []nftrace.Trace
	}{

		keys: []uint64{1, 2, 3},
		data: []nftrace.Trace{{TrId: 1, Cnt: 1}, {TrId: 2, Cnt: 2}, {TrId: 3, Cnt: 3}},
	}
	que := NewCachedQue(10)
	r := que.Reader()
	rd := func() (ret nftrace.Trace) {
		select {
		case ret = <-r:
		case <-time.After(time.Second):
		}
		return ret
	}
	var (
		exp, got []nftrace.Trace
	)

	//dummy enqueue
	que.Enque(nftrace.Trace{})
	for i := range tc.data {
		sui.Require().Equal(i, len(que.cache))
		que.Upsert(tc.keys[i], tc.data[i])
	}

	for i := range tc.data {
		sui.Require().Equal(len(tc.keys), len(que.cache))
		que.Upsert(tc.keys[i], nftrace.Trace{TrId: tc.data[i].TrId, Cnt: 1})
		exp = append(exp, nftrace.Trace{TrId: tc.data[i].TrId, Cnt: tc.data[i].Cnt + 1})
	}
	sui.Require().Equal(len(tc.data)+1, que.Len())
	sui.Require().Equal(len(tc.keys), len(que.cache))
	//dummy dequeue
	x := rd()
	sui.Require().NotNil(x)
	for range len(tc.data) {
		got = append(got, rd())
	}
	sui.Require().Equal(0, len(que.cache))
	sui.Require().Equal(exp, got)
}
