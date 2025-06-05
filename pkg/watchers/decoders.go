package watchers

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/PRO-Robotech/nftrace/internal/nl"

	"github.com/Morwran/nft-go/pkg/nlparser"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func linkEvtFromNlMsg(msg nl.NetlinkNfMsg) (LinkEvent, error) {
	t := msg.MsgType()

	switch t {
	case unix.RTM_DELLINK, unix.RTM_NEWLINK:
		var ifName string

		ad, err := netlink.NewAttributeDecoder(msg.DataOffset(nl.NlRtmAttrOffset))
		if err != nil {
			return LinkEvent{}, fmt.Errorf("failed to create new nl attribute decoder: %w", err)
		}
		ad.ByteOrder = binary.BigEndian
		for ad.Next() {
			if ad.Type() == unix.IFLA_IFNAME {
				ifName = ad.String()
			}
		}
		if ad.Err() != nil {
			return LinkEvent{}, fmt.Errorf("failed to unmarshal attribute: %w", ad.Err())
		}

		ifInfo := *(*unix.IfInfomsg)(unsafe.Pointer(&msg.Data[0:unix.SizeofIfInfomsg][0])) //nolint:gosec
		act := AddAction
		if t == unix.RTM_DELLINK {
			act = RmAction
		}
		return LinkEvent{Val: Link{Name: ifName, Index: int(ifInfo.Index)}, Action: act}, nil
	}

	return LinkEvent{}, ErrMismatchedNlMsgType
}

func ruleEvtFromNlMsg(msg netlink.Message) (RuleEvent, error) {
	t := nl.NetlinkNfMsg(msg).MsgType()
	switch t {
	case unix.NFT_MSG_NEWRULE, unix.NFT_MSG_DELRULE:

		rule, err := nlparser.RuleFromMsg(msg)
		if err != nil {
			return RuleEvent{}, fmt.Errorf("failed to parse rule from netlink message: %w", err)
		}

		act := AddAction
		if t == unix.NFT_MSG_DELRULE {
			act = RmAction
		}

		return RuleEvent{Val: rule, Action: act}, nil
	}

	return RuleEvent{}, ErrMismatchedNlMsgType
}

func chainEvtFromNlMsg(msg netlink.Message) (ChainEvent, error) {
	t := nl.NetlinkNfMsg(msg).MsgType()
	switch t {
	case unix.NFT_MSG_NEWCHAIN, unix.NFT_MSG_DELCHAIN:

		chain, err := nlparser.ChainFromMsg(msg)
		if err != nil {
			return ChainEvent{}, fmt.Errorf("failed to parse chain from netlink message: %w", err)
		}

		act := AddAction
		if t == unix.NFT_MSG_DELCHAIN {
			act = RmAction
		}

		return ChainEvent{Val: chain, Action: act}, nil
	}

	return ChainEvent{}, ErrMismatchedNlMsgType
}

func setEvtFromNlMsg(msg netlink.Message) (SetEvent, error) {
	t := nl.NetlinkNfMsg(msg).MsgType()
	switch t {
	case unix.NFT_MSG_NEWSET, unix.NFT_MSG_DELSET:

		set, err := nlparser.SetFromMsg(msg)
		if err != nil {
			return SetEvent{}, fmt.Errorf("failed to parse set from netlink message: %w", err)
		}

		act := AddAction
		if t == unix.NFT_MSG_DELSET {
			act = RmAction
		}

		return SetEvent{Val: set, Action: act}, nil
	}

	return SetEvent{}, ErrMismatchedNlMsgType
}

func setElementEvtFromNlMsg(msg netlink.Message) (SetElementEvent, error) {
	t := nl.NetlinkNfMsg(msg).MsgType()
	switch t {
	case unix.NFT_MSG_NEWSETELEM, unix.NFT_MSG_DELSETELEM:

		setElem, err := nlparser.SetElemsFromMsg(msg)
		if err != nil {
			return SetElementEvent{}, fmt.Errorf("failed to parse set element from netlink message: %w", err)
		}

		act := AddAction
		if t == unix.NFT_MSG_DELSETELEM {
			act = RmAction
		}

		return SetElementEvent{Val: setElem, Action: act}, nil
	}

	return SetElementEvent{}, ErrMismatchedNlMsgType
}

func tableEvtFromNlMsg(msg netlink.Message) (TableEvent, error) {
	t := nl.NetlinkNfMsg(msg).MsgType()
	switch t {
	case unix.NFT_MSG_NEWTABLE, unix.NFT_MSG_DELTABLE:

		tbl, err := nlparser.TableFromMsg(msg)
		if err != nil {
			return TableEvent{}, fmt.Errorf("failed to parse table from netlink message: %w", err)
		}

		act := AddAction
		if t == unix.NFT_MSG_DELTABLE {
			act = RmAction
		}

		return TableEvent{Val: tbl, Action: act}, nil
	}

	return TableEvent{}, ErrMismatchedNlMsgType
}

func nftEvtFromNlMsg(msg netlink.Message) (NftEvent, error) {
	t := nl.NetlinkNfMsg(msg).MsgType()
	switch t {
	case unix.NFT_MSG_NEWTABLE, unix.NFT_MSG_DELTABLE:
		tblEvt, err := tableEvtFromNlMsg(msg)
		if err != nil {
			return NftEvent{}, err
		}
		return NftEvent{Val: tblEvt, Action: tblEvt.Action}, nil
	case unix.NFT_MSG_NEWSET, unix.NFT_MSG_DELSET:
		setEvt, err := setEvtFromNlMsg(msg)
		if err != nil {
			return NftEvent{}, err
		}
		return NftEvent{Val: setEvt, Action: setEvt.Action}, nil
	case unix.NFT_MSG_NEWSETELEM, unix.NFT_MSG_DELSETELEM:
		setElemEvt, err := setElementEvtFromNlMsg(msg)
		if err != nil {
			return NftEvent{}, err
		}
		return NftEvent{Val: setElemEvt, Action: setElemEvt.Action}, nil
	case unix.NFT_MSG_NEWCHAIN, unix.NFT_MSG_DELCHAIN:
		chainEvt, err := chainEvtFromNlMsg(msg)
		if err != nil {
			return NftEvent{}, err
		}
		return NftEvent{Val: chainEvt, Action: chainEvt.Action}, nil
	case unix.NFT_MSG_NEWRULE, unix.NFT_MSG_DELRULE:
		ruleEvt, err := ruleEvtFromNlMsg(msg)
		if err != nil {
			return NftEvent{}, err
		}
		return NftEvent{Val: ruleEvt, Action: ruleEvt.Action}, nil
	}

	return NftEvent{}, ErrMismatchedNlMsgType
}
