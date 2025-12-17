package cache

import (
	"container/list"
	"context"
	"sync"
	"time"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/internal/domain"
	"github.com/your-org/authz-service/pkg/logger"
)

// L1Cache implements an in-memory LRU cache with TTL support.
type L1Cache struct {
	mu       sync.RWMutex
	capacity int
	ttl      time.Duration
	items    map[string]*list.Element
	order    *list.List // LRU order
	enabled  bool

	// Metrics
	hits   int64
	misses int64
}

// cacheEntry represents a single cache entry.
type cacheEntry struct {
	key       string
	decision  *domain.Decision
	expiresAt time.Time
}

// NewL1Cache creates a new L1 in-memory cache.
func NewL1Cache(cfg config.L1CacheConfig) *L1Cache {
	return &L1Cache{
		capacity: cfg.MaxSize,
		ttl:      cfg.TTL,
		items:    make(map[string]*list.Element),
		order:    list.New(),
		enabled:  cfg.Enabled,
	}
}

// Get retrieves a decision from the cache.
func (c *L1Cache) Get(ctx context.Context, key string) (*domain.Decision, bool) {
	if !c.enabled {
		return nil, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.items[key]
	if !ok {
		c.misses++
		return nil, false
	}

	entry := elem.Value.(*cacheEntry)

	// Check expiration
	if time.Now().After(entry.expiresAt) {
		c.removeElement(elem)
		c.misses++
		return nil, false
	}

	// Move to front (most recently used)
	c.order.MoveToFront(elem)
	c.hits++

	// Return a copy to prevent mutation
	decision := *entry.decision
	decision.Cached = true
	return &decision, true
}

// Set stores a decision in the cache.
func (c *L1Cache) Set(ctx context.Context, key string, decision *domain.Decision, ttl time.Duration) {
	if !c.enabled {
		return
	}

	if ttl == 0 {
		ttl = c.ttl
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if key exists
	if elem, ok := c.items[key]; ok {
		c.order.MoveToFront(elem)
		entry := elem.Value.(*cacheEntry)
		entry.decision = decision
		entry.expiresAt = time.Now().Add(ttl)
		return
	}

	// Evict if at capacity
	if c.order.Len() >= c.capacity {
		c.evictOldest()
	}

	// Add new entry
	entry := &cacheEntry{
		key:       key,
		decision:  decision,
		expiresAt: time.Now().Add(ttl),
	}
	elem := c.order.PushFront(entry)
	c.items[key] = elem
}

// Delete removes a key from the cache.
func (c *L1Cache) Delete(ctx context.Context, key string) {
	if !c.enabled {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.removeElement(elem)
	}
}

// Clear removes all entries from the cache.
func (c *L1Cache) Clear(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[string]*list.Element)
	c.order.Init()
}

// Stats returns cache statistics.
func (c *L1Cache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return CacheStats{
		Size:     c.order.Len(),
		Capacity: c.capacity,
		Hits:     c.hits,
		Misses:   c.misses,
		HitRate:  c.hitRate(),
	}
}

// evictOldest removes the least recently used entry.
func (c *L1Cache) evictOldest() {
	elem := c.order.Back()
	if elem != nil {
		c.removeElement(elem)
	}
}

// removeElement removes an element from the cache.
func (c *L1Cache) removeElement(elem *list.Element) {
	c.order.Remove(elem)
	entry := elem.Value.(*cacheEntry)
	delete(c.items, entry.key)
}

// hitRate calculates the cache hit rate.
func (c *L1Cache) hitRate() float64 {
	total := c.hits + c.misses
	if total == 0 {
		return 0
	}
	return float64(c.hits) / float64(total)
}

// StartCleanup starts a background goroutine to clean expired entries.
func (c *L1Cache) StartCleanup(ctx context.Context, interval time.Duration) {
	if !c.enabled {
		return
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.cleanupExpired()
			}
		}
	}()

	logger.Debug("L1 cache cleanup started", logger.Duration("interval", interval))
}

// cleanupExpired removes all expired entries.
func (c *L1Cache) cleanupExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var toRemove []*list.Element

	for elem := c.order.Back(); elem != nil; elem = elem.Prev() {
		entry := elem.Value.(*cacheEntry)
		if now.After(entry.expiresAt) {
			toRemove = append(toRemove, elem)
		}
	}

	for _, elem := range toRemove {
		c.removeElement(elem)
	}

	if len(toRemove) > 0 {
		logger.Debug("L1 cache cleanup completed", logger.Int("removed", len(toRemove)))
	}
}

// CacheStats holds cache statistics.
type CacheStats struct {
	Size     int     `json:"size"`
	Capacity int     `json:"capacity"`
	Hits     int64   `json:"hits"`
	Misses   int64   `json:"misses"`
	HitRate  float64 `json:"hit_rate"`
}
