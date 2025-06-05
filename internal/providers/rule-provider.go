package providers

import (
	"context"
	"sync/atomic"
)

type ruleProvider struct {
	cache  cache[int, string]
	cancel context.CancelFunc

	lastErr atomic.Value
}
