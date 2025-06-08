package nftrace

import (
	"fmt"
	"strconv"

	"github.com/cespare/xxhash"
)

const (
	ipv4 = 4
	ipv6 = 6
)

type (
	Trace struct {
		// trace id
		ID uint32 `json:"id"`
		// protocols family (ip4/ip6/inet)
		Family string `json:"family"`
		// table name
		Table string `json:"table"`
		// chain name
		Chain string `json:"chain"`
		// rule expression
		Rule string `json:"rule"`
		// rule handle
		Handle uint64 `json:"handle"`
		// target chain name for jumping
		Jump string `json:"jump,omitempty"`
		// rule verdict
		Verdict string `json:"verdict"`
		// input interface name
		IIF string `json:"iif,omitempty"`
		// output interface name
		OIF string `json:"oif,omitempty"`
		// packet length
		Len uint32 `json:"len"`
		// source mac address
		SMAC string `json:"smac,omitempty"`
		// destination mac address
		DMAC string `json:"dmac,omitempty"`
		// ip protocol version (4/6)
		IpVersion uint8 `json:"ip_version,omitempty"`
		// protocol (tcp/udp/icmp/...)
		Proto string `json:"proto"`
		// source ip address
		SAddr string `json:"saddr,omitempty"`
		// destination ip address
		DAddr string `json:"daddr,omitempty"`
		// source port
		SPort uint32 `json:"sport,omitempty"`
		// destination port
		DPort uint32 `json:"dport,omitempty"`
		// aggregated trace counter
		Cnt uint64 `json:"cnt"`
	}
)

func (t *Trace) Hash() uint64 {
	return xxhash.Sum64String(t.Proto + t.SAddr + t.DAddr + strconv.Itoa(int(t.SPort)) + strconv.Itoa(int(t.DPort)))
}

func (t *Trace) FiveTupleFormat() string {
	var sPort, dPort string
	var sAddr, dAddr = t.SAddr, t.DAddr

	if t.SPort != 0 {
		sPort = fmt.Sprintf(":%d", t.SPort)
	}
	if t.DPort != 0 {
		dPort = fmt.Sprintf(":%d", t.DPort)
	}
	if t.IpVersion == ipv6 && sPort != "" {
		sAddr = fmt.Sprintf("[%s]", sAddr)
	}
	if t.IpVersion == ipv6 && dPort != "" {
		dAddr = fmt.Sprintf("[%s]", dAddr)
	}
	return fmt.Sprintf("%-30s  ->  %-30s",
		fmt.Sprintf("%s://%s%s", t.Proto, sAddr, sPort),
		fmt.Sprintf("%s://%s%s", t.Proto, dAddr, dPort),
	)
}
