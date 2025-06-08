package providers

type (
	LinkProvider interface {
		LinkByIndex(int) (Link, error)
		Close() error
	}

	RuleProvider interface {
		GetHumanRule(RuleKey) (string, error)
		Close() error
	}
)
