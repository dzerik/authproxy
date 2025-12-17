package egress

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/pkg/logger"
)

// TokenStore provides storage for credentials.
type TokenStore interface {
	// Get retrieves credentials from store.
	Get(ctx context.Context, targetName string) (*Credentials, error)

	// Set stores credentials in store.
	Set(ctx context.Context, targetName string, creds *Credentials) error

	// Delete removes credentials from store.
	Delete(ctx context.Context, targetName string) error

	// Health checks if store is healthy.
	Health(ctx context.Context) error

	// Close closes the store.
	Close() error
}

// NewTokenStore creates a new token store based on configuration.
func NewTokenStore(cfg config.EgressTokenStoreConfig, log logger.Logger) (TokenStore, error) {
	switch cfg.Type {
	case "memory", "":
		return NewMemoryTokenStore(log), nil
	case "redis":
		return NewRedisTokenStore(cfg.Redis, log)
	default:
		return nil, fmt.Errorf("unsupported token store type: %s", cfg.Type)
	}
}

// =============================================================================
// Memory Token Store
// =============================================================================

// MemoryTokenStore is an in-memory token store.
type MemoryTokenStore struct {
	tokens map[string]*storedCredential
	mu     sync.RWMutex
	log    logger.Logger
}

type storedCredential struct {
	Credentials *Credentials
	StoredAt    time.Time
}

// NewMemoryTokenStore creates a new in-memory token store.
func NewMemoryTokenStore(log logger.Logger) *MemoryTokenStore {
	return &MemoryTokenStore{
		tokens: make(map[string]*storedCredential),
		log:    log,
	}
}

// Get retrieves credentials from memory.
func (s *MemoryTokenStore) Get(ctx context.Context, targetName string) (*Credentials, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stored, ok := s.tokens[targetName]
	if !ok {
		return nil, nil
	}

	// Check if expired
	if stored.Credentials.IsExpired() {
		return nil, nil
	}

	return stored.Credentials, nil
}

// Set stores credentials in memory.
func (s *MemoryTokenStore) Set(ctx context.Context, targetName string, creds *Credentials) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokens[targetName] = &storedCredential{
		Credentials: creds,
		StoredAt:    time.Now(),
	}

	return nil
}

// Delete removes credentials from memory.
func (s *MemoryTokenStore) Delete(ctx context.Context, targetName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.tokens, targetName)
	return nil
}

// Health returns nil as memory store is always healthy.
func (s *MemoryTokenStore) Health(ctx context.Context) error {
	return nil
}

// Close is a no-op for memory store.
func (s *MemoryTokenStore) Close() error {
	return nil
}

// =============================================================================
// Redis Token Store
// =============================================================================

// RedisTokenStore is a Redis-backed token store.
type RedisTokenStore struct {
	client    *redis.Client
	keyPrefix string
	log       logger.Logger
}

// NewRedisTokenStore creates a new Redis token store.
func NewRedisTokenStore(cfg config.EgressRedisConfig, log logger.Logger) (*RedisTokenStore, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Address,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	keyPrefix := cfg.KeyPrefix
	if keyPrefix == "" {
		keyPrefix = "egress:tokens:"
	}

	return &RedisTokenStore{
		client:    client,
		keyPrefix: keyPrefix,
		log:       log,
	}, nil
}

// redisCredential is the JSON representation of credentials for Redis.
type redisCredential struct {
	Type        string            `json:"type"`
	AccessToken string            `json:"access_token,omitempty"`
	ExpiresAt   int64             `json:"expires_at,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
}

// Get retrieves credentials from Redis.
func (s *RedisTokenStore) Get(ctx context.Context, targetName string) (*Credentials, error) {
	key := s.keyPrefix + targetName

	data, err := s.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials from Redis: %w", err)
	}

	var rc redisCredential
	if err := json.Unmarshal(data, &rc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credentials: %w", err)
	}

	var expiresAt time.Time
	if rc.ExpiresAt > 0 {
		expiresAt = time.Unix(rc.ExpiresAt, 0)
	}

	creds := &Credentials{
		Type:        CredentialType(rc.Type),
		AccessToken: rc.AccessToken,
		ExpiresAt:   expiresAt,
		Headers:     rc.Headers,
	}

	// Check if expired
	if creds.IsExpired() {
		// Delete expired credential
		_ = s.Delete(ctx, targetName)
		return nil, nil
	}

	return creds, nil
}

// Set stores credentials in Redis.
func (s *RedisTokenStore) Set(ctx context.Context, targetName string, creds *Credentials) error {
	key := s.keyPrefix + targetName

	rc := redisCredential{
		Type:        string(creds.Type),
		AccessToken: creds.AccessToken,
		Headers:     creds.Headers,
	}

	if !creds.ExpiresAt.IsZero() {
		rc.ExpiresAt = creds.ExpiresAt.Unix()
	}

	data, err := json.Marshal(rc)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	// Calculate TTL
	var ttl time.Duration
	if !creds.ExpiresAt.IsZero() {
		ttl = time.Until(creds.ExpiresAt)
		if ttl < 0 {
			ttl = 0
		}
	} else {
		// Default TTL for non-expiring credentials (e.g., API keys)
		ttl = 24 * time.Hour
	}

	if err := s.client.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("failed to store credentials in Redis: %w", err)
	}

	return nil
}

// Delete removes credentials from Redis.
func (s *RedisTokenStore) Delete(ctx context.Context, targetName string) error {
	key := s.keyPrefix + targetName

	if err := s.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete credentials from Redis: %w", err)
	}

	return nil
}

// Health checks if Redis is healthy.
func (s *RedisTokenStore) Health(ctx context.Context) error {
	return s.client.Ping(ctx).Err()
}

// Close closes the Redis client.
func (s *RedisTokenStore) Close() error {
	return s.client.Close()
}
