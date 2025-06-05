package nftrace

import (
	"strconv"

	"github.com/cespare/xxhash"
	nftLib "github.com/google/nftables"
)

type (
	Trace struct {
		// trace id
		TrId uint32
		// nftables table name
		Table string
		// nftables chain name
		Chain string
		// nftables jump to a target name
		JumpTarget string
		// nftables rule number
		RuleHandle uint64
		// protocols family
		Family string
		// input network interface
		Iifname string
		// output network interface
		Oifname string
		// source mac address
		SMacAddr string
		// destination mac address
		DMacAddr string
		// source ip address
		SAddr string
		// destination ip address
		DAddr string
		// source port
		SPort uint32
		// destination port
		DPort uint32
		// length packet
		Length uint32
		// ip protocol (tcp/udp/icmp/...)
		IpProto string
		// verdict for the rule
		Verdict string
		// rule expression as string
		Rule string
		// user agent id
		UserAgent string
		// aggregated trace counter
		Cnt uint64
	}

	RuleDescriptor struct {
		TableName   string
		TableFamily nftLib.TableFamily
		ChainName   string
		RuleHandle  uint64
	}
)

func (t *Trace) Hash() uint64 {
	return xxhash.Sum64String(t.IpProto + t.SAddr + t.DAddr + strconv.Itoa(int(t.SPort)) + strconv.Itoa(int(t.DPort)))
}
