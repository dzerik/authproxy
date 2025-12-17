package cache

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/internal/domain"
	"github.com/your-org/authz-service/pkg/logger"
)

// L2RedisCache implements a Redis-based distributed cache.
type L2RedisCache struct {
	client    redis.UniversalClient
	keyPrefix string
	ttl       config.CacheTTLConfig
	enabled   bool

	// Metrics
	hits   int64
	misses int64
}

// NewL2RedisCache creates a new L2 Redis cache.
func NewL2RedisCache(cfg config.L2CacheConfig) (*L2RedisCache, error) {
	if !cfg.Enabled {
		return &L2RedisCache{enabled: false}, nil
	}

	var client redis.UniversalClient

	// Use cluster client if multiple addresses provided
	if len(cfg.Redis.Addresses) > 1 {
		client = redis.NewClusterClient(&redis.ClusterOptions{
			Addrs:        cfg.Redis.Addresses,
			Password:     cfg.Redis.Password,
			PoolSize:     cfg.Redis.PoolSize,
			ReadTimeout:  cfg.Redis.ReadTimeout,
			WriteTimeout: cfg.Redis.WriteTimeout,
		})
	} else {
		addr := "localhost:6379"
		if len(cfg.Redis.Addresses) > 0 {
			addr = cfg.Redis.Addresses[0]
		}
		client = redis.NewClient(&redis.Options{
			Addr:         addr,
			Password:     cfg.Redis.Password,
			DB:           cfg.Redis.DB,
			PoolSize:     cfg.Redis.PoolSize,
			ReadTimeout:  cfg.Redis.ReadTimeout,
			WriteTimeout: cfg.Redis.WriteTimeout,
		})
	}

	return &L2RedisCache{
		client:    client,
		keyPrefix: cfg.KeyPrefix,
		ttl:       cfg.TTL,
		enabled:   true,
	}, nil
}

// Start initializes the Redis connection.
func (c *L2RedisCache) Start(ctx context.Context) error {
	if !c.enabled {
		return nil
	}

	// Test connection
	if err := c.client.Ping(ctx).Err(); err != nil {
		logger.Warn("L2 Redis cache connection failed", logger.Err(err))
		c.enabled = false
		return err
	}

	logger.Info("L2 Redis cache connected", logger.String("prefix", c.keyPrefix))
	return nil
}

// Stop closes the Redis connection.
func (c *L2RedisCache) Stop() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

// Get retrieves a decision from Redis.
func (c *L2RedisCache) Get(ctx context.Context, key string) (*domain.Decision, bool) {
	if !c.enabled {
		return nil, false
	}

	fullKey := c.keyPrefix + key

	data, err := c.client.Get(ctx, fullKey).Bytes()
	if err != nil {
		if err != redis.Nil {
			logger.Debug("L2 cache get error", logger.String("key", key), logger.Err(err))
		}
		c.misses++
		return nil, false
	}

	var decision domain.Decision
	if err := json.Unmarshal(data, &decision); err != nil {
		logger.Debug("L2 cache unmarshal error", logger.String("key", key), logger.Err(err))
		c.misses++
		return nil, false
	}

	decision.Cached = true
	c.hits++
	return &decision, true
}

// Set stores a decision in Redis.
func (c *L2RedisCache) Set(ctx context.Context, key string, decision *domain.Decision, ttl time.Duration) {
	if !c.enabled {
		return
	}

	if ttl == 0 {
		ttl = c.ttl.Authorization
	}

	fullKey := c.keyPrefix + key

	data, err := json.Marshal(decision)
	if err != nil {
		logger.Debug("L2 cache marshal error", logger.String("key", key), logger.Err(err))
		return
	}

	if err := c.client.Set(ctx, fullKey, data, ttl).Err(); err != nil {
		logger.Debug("L2 cache set error", logger.String("key", key), logger.Err(err))
	}
}

// Delete removes a key from Redis.
func (c *L2RedisCache) Delete(ctx context.Context, key string) {
	if !c.enabled {
		return
	}

	fullKey := c.keyPrefix + key
	c.client.Del(ctx, fullKey)
}

// Clear removes all keys with the configured prefix.
func (c *L2RedisCache) Clear(ctx context.Context) {
	if !c.enabled {
		return
	}

	// Use SCAN to find and delete keys with prefix
	var cursor uint64
	for {
		var keys []string
		var err error
		keys, cursor, err = c.client.Scan(ctx, cursor, c.keyPrefix+"*", 100).Result()
		if err != nil {
			logger.Warn("L2 cache clear scan error", logger.Err(err))
			return
		}

		if len(keys) > 0 {
			c.client.Del(ctx, keys...)
		}

		if cursor == 0 {
			break
		}
	}
}

// Stats returns cache statistics.
func (c *L2RedisCache) Stats() CacheStats {
	return CacheStats{
		Hits:    c.hits,
		Misses:  c.misses,
		HitRate: c.hitRate(),
	}
}

// hitRate calculates the cache hit rate.
func (c *L2RedisCache) hitRate() float64 {
	total := c.hits + c.misses
	if total == 0 {
		return 0
	}
	return float64(c.hits) / float64(total)
}

// Healthy checks if Redis is reachable.
func (c *L2RedisCache) Healthy(ctx context.Context) bool {
	if !c.enabled || c.client == nil {
		return true // Not enabled, considered healthy
	}
	return c.client.Ping(ctx).Err() == nil
}

// Enabled returns whether L2 cache is enabled.
func (c *L2RedisCache) Enabled() bool {
	return c.enabled
}
