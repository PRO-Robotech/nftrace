package providers

import (
	"sync"

	"github.com/H-BF/corlib/pkg/dict"
)

type cache[K comparable, V any] struct {
	mu    sync.RWMutex
	cache dict.HDict[K, V]
}

func (c *cache[K, V]) Get(key K) (V, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cache.Get(key)
}

func (c *cache[K, V]) Put(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache.Put(key, value)
}

func (c *cache[K, V]) Del(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache.Del(key)
}

func (c *cache[K, V]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache.Clear()
}
