package state

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisStore stores OAuth state in Redis.
// Suitable for high-availability deployments with multiple instances.
type RedisStore struct {
	client    redis.UniversalClient
	keyPrefix string
	ttl       time.Duration
}

// NewRedisStore creates a new Redis-based state store
func NewRedisStore(cfg Config) (*RedisStore, error) {
	if len(cfg.Redis.Addresses) == 0 {
		return nil, fmt.Errorf("redis addresses not configured")
	}

	opts := &redis.UniversalOptions{
		Addrs:      cfg.Redis.Addresses,
		Password:   cfg.Redis.Password,
		DB:         cfg.Redis.DB,
		MasterName: cfg.Redis.MasterName,
	}

	client := redis.NewUniversalClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	keyPrefix := cfg.Redis.KeyPrefix
	if keyPrefix == "" {
		keyPrefix = "authportal:state:"
	}

	ttl := cfg.TTL
	if ttl == 0 {
		ttl = 10 * time.Minute
	}

	return &RedisStore{
		client:    client,
		keyPrefix: keyPrefix,
		ttl:       ttl,
	}, nil
}

// Set stores a new state token
func (s *RedisStore) Set(state *OAuthState) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	key := s.keyPrefix + state.State
	if err := s.client.Set(ctx, key, data, s.ttl).Err(); err != nil {
		return fmt.Errorf("failed to store state: %w", err)
	}

	return nil
}

// Get retrieves and removes a state token (one-time use)
func (s *RedisStore) Get(stateToken string) (*OAuthState, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	key := s.keyPrefix + stateToken

	// Use GETDEL for atomic get-and-delete (Redis 6.2+)
	// Fall back to GET + DEL for older versions
	data, err := s.client.GetDel(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, false
		}
		// Log error but return not found
		return nil, false
	}

	var state OAuthState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, false
	}

	// Check if expired (defensive check, Redis TTL should handle this)
	if time.Since(state.CreatedAt) > s.ttl {
		return nil, false
	}

	return &state, true
}

// Validate checks if a state token exists without removing it
func (s *RedisStore) Validate(stateToken string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	key := s.keyPrefix + stateToken
	exists, err := s.client.Exists(ctx, key).Result()
	if err != nil {
		return false
	}
	return exists > 0
}

// Close closes the Redis client connection
func (s *RedisStore) Close() error {
	return s.client.Close()
}

// Name returns the store type name
func (s *RedisStore) Name() string {
	return "redis"
}
