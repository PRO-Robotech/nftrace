package watchers

import (
	"context"
	"fmt"

	"github.com/Morwran/nft-go/pkg/nlparser"
	nftLib "github.com/google/nftables"
)

type Action string

const (
	AddAction Action = "added"
	RmAction  Action = "removed"
)

type (
	watcherT interface {
		LinkEvent | RuleEvent | ChainEvent |
			SetEvent | SetElementEvent | TableEvent | NftEvent
	}
	// Watcher is an interface for a watcher that can stream events of type T.
	// T is a type that implements the watcherT interface, which can be either Link or Rule.
	Watcher[T watcherT] interface {
		Close() error
		Stream(ctx context.Context) <-chan WatcherEvent[T]
	}

	WatcherEvent[T watcherT] struct {
		Evt T
		Err error
	}
)

type NftEventFace interface {
	isNftEvent()
	ActionInfo() string
}

type (
	event[T any] struct {
		Val    T
		Action Action
	}
	nftEvent[T any] struct {
		Val    T
		Action Action
		NftEventFace
	}
)

type (
	Link struct {
		Name  string
		Index int
	}

	LinkEvent event[Link]

	NftRule struct {
		Rule  *nftLib.Rule
		Human string
	}

	RuleEvent       nftEvent[NftRule]
	ChainEvent      nftEvent[*nftLib.Chain]
	SetEvent        nftEvent[*nftLib.Set]
	SetElementEvent nftEvent[*nlparser.SetElems]
	TableEvent      nftEvent[*nftLib.Table]
	NftEvent        event[NftEventFace]
)

func (l LinkEvent) ActionInfo() string {
	if l.Val.Name != "" && l.Action != "" {
		return fmt.Sprintf("%T: '%s' has %s", l, l.Val.Name, l.Action)
	}
	return ""
}

func (r RuleEvent) ActionInfo() string {
	if r.Val.Rule != nil && r.Action != "" {
		if r.Val.Human != "" {
			return fmt.Sprintf("%T: rule '%s' has %s", r, r.Val.Human, r.Action)
		}

		return fmt.Sprintf("%T: rule handle %d has %s", r, r.Val.Rule.Handle, r.Action)
	}

	return ""
}

func (c ChainEvent) ActionInfo() string {
	if c.Val != nil && c.Action != "" {
		return fmt.Sprintf("%T: chain '%s' has %s", c, c.Val.Name, c.Action)
	}
	return ""
}

func (s SetEvent) ActionInfo() string {
	if s.Val != nil && s.Action != "" {
		return fmt.Sprintf("%T: set '%s' has %s", s, s.Val.Name, s.Action)
	}
	return ""
}

func (t TableEvent) ActionInfo() string {
	if t.Val != nil && t.Action != "" {
		return fmt.Sprintf("%T: table '%s' has %s", t, t.Val.Name, t.Action)
	}
	return ""
}

func (t SetElementEvent) ActionInfo() string {
	if t.Val != nil && t.Action != "" {
		return fmt.Sprintf("%T: set element has %s", t, t.Action)
	}
	return ""
}

func (t NftEvent) ActionInfo() string {
	if t.Val != nil && t.Action != "" {
		return t.Val.ActionInfo()
	}
	return ""
}
