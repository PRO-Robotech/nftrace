package providers

import (
	"github.com/PRO-Robotech/nftrace"
)

type (
	LinkProvider interface {
		LinkByIndex(int) (Link, error)
		Close() error
	}

	RuleProvider interface {
		GetHumanRule(nftrace.RuleDescriptor) (string, error)
	}
)
