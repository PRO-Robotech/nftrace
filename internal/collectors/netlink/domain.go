package netlink

import (
	"encoding/binary"

	"github.com/PRO-Robotech/nftrace/internal/collectors"
	"github.com/PRO-Robotech/nftrace/internal/collectors/netlink/headers"
	"github.com/PRO-Robotech/nftrace/internal/decoders"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const readerQueSize = 1024

type (
	NetlinkTrace struct {
		Table      string
		Chain      string
		JumpTarget string
		RuleHandle uint64
		Lh         headers.LinkHeader
		Nh         headers.NetworkHeader
		Th         headers.TransportHeader
		Family     byte
		Type       uint32
		Id         uint32
		Iif        uint32
		Oif        uint32
		Mark       uint32
		Verdict    uint32
		Nfproto    uint32
		Policy     uint32
		Iiftype    uint16
		Oiftype    uint16

		metrics Metrics
	}

	Metrics struct {
		collectors.Telemetry
		MemOvflCnt int
	}
)

func (tr *NetlinkTrace) ToNftTrace() collectors.NftTrace {
	return collectors.NftTrace{
		Table:      tr.Table,
		Chain:      tr.Chain,
		JumpTarget: tr.JumpTarget,
		RuleHandle: tr.RuleHandle,
		Family:     tr.Family,
		Type:       tr.Type,
		Id:         tr.Id,
		Iif:        tr.Iif,
		Oif:        tr.Oif,
		Mark:       tr.Mark,
		Verdict:    tr.Verdict,
		Nfproto:    tr.Nfproto,
		Policy:     tr.Policy,
		Iiftype:    tr.Iiftype,
		Oiftype:    tr.Oiftype,
		IpVersion:  tr.Nh.Version,
		SMacAddr:   decoders.FastHardwareAddr(tr.Lh.SAddr).String(),
		DMacAddr:   decoders.FastHardwareAddr(tr.Lh.DAddr).String(),
		SAddr:      tr.Nh.SAddr.String(),
		DAddr:      tr.Nh.DAddr.String(),
		SPort:      uint32(tr.Th.SPort),
		DPort:      uint32(tr.Th.DPort),
		Length:     uint32(tr.Nh.Length),
		IpProtocol: tr.Nh.Protocol,
		Cnt:        1,
		Metrics:    tr.metrics,
	}
}

func (tr *NetlinkTrace) InitFromMsg(msg netlink.Message) error {
	ad, err := netlink.NewAttributeDecoder(msg.Data[4:])
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_TRACE_ID:
			tr.Id = ad.Uint32()
		case unix.NFTA_TRACE_TYPE:
			tr.Type = ad.Uint32()
		case unix.NFTA_TRACE_TABLE:
			tr.Table = ad.String()
		case unix.NFTA_TRACE_CHAIN:
			tr.Chain = ad.String()
		case unix.NFTA_TRACE_VERDICT:
			ad, err := netlink.NewAttributeDecoder(ad.Bytes()) //nolint:govet
			if err != nil {
				return err
			}
			ad.ByteOrder = binary.BigEndian
			for ad.Next() {
				switch ad.Type() {
				case unix.NFTA_VERDICT_CODE:
					tr.Verdict = ad.Uint32()
				case unix.NFTA_VERDICT_CHAIN:
					if int32(tr.Verdict) == unix.NFT_GOTO || //nolint:gosec
						int32(tr.Verdict) == unix.NFT_JUMP { //nolint:gosec
						tr.JumpTarget = ad.String()
					}
				}
			}
		case unix.NFTA_TRACE_IIFTYPE:
			tr.Iiftype = ad.Uint16()
		case unix.NFTA_TRACE_IIF:
			tr.Iif = ad.Uint32()
		case unix.NFTA_TRACE_OIFTYPE:
			tr.Oiftype = ad.Uint16()
		case unix.NFTA_TRACE_OIF:
			tr.Oif = ad.Uint32()
		case unix.NFTA_TRACE_MARK:
			tr.Mark = ad.Uint32()
		case unix.NFTA_TRACE_RULE_HANDLE:
			tr.RuleHandle = ad.Uint64()
		case unix.NFTA_TRACE_LL_HEADER:
			if err = tr.Lh.Decode(ad.Bytes()); err != nil {
				return err
			}
		case unix.NFTA_TRACE_NETWORK_HEADER:
			if err = tr.Nh.Decode(ad.Bytes()); err != nil {
				return err
			}
		case unix.NFTA_TRACE_TRANSPORT_HEADER:
			if err = tr.Th.Decode(ad.Bytes()); err != nil {
				return err
			}
		case unix.NFTA_TRACE_NFPROTO:
			tr.Nfproto = ad.Uint32()
		case unix.NFTA_TRACE_POLICY:
			tr.Policy = ad.Uint32()
		}
	}
	tr.Family = msg.Data[0]
	return nil
}
