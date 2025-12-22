// Package state provides OAuth state storage implementations.
// CRIT-02 security fix: supports both in-memory and Redis-based storage for HA deployments.
package state

import (
	"errors"
	"time"
)

var (
	// ErrStateNotFound is returned when a state token doesn't exist
	ErrStateNotFound = errors.New("state not found")
	// ErrStateExpired is returned when a state token has expired
	ErrStateExpired = errors.New("state expired")
)

// OAuthState represents an OAuth flow state
type OAuthState struct {
	State       string    `json:"state"`
	Nonce       string    `json:"nonce"`
	RedirectURL string    `json:"redirect_url"`
	Provider    string    `json:"provider"`
	CreatedAt   time.Time `json:"created_at"`
}

// Store defines the interface for OAuth state storage.
// Implementations must be safe for concurrent use.
type Store interface {
	// Set stores a new state token
	Set(state *OAuthState) error

	// Get retrieves and removes a state token (one-time use)
	Get(stateToken string) (*OAuthState, bool)

	// Validate checks if a state token exists without removing it
	Validate(stateToken string) bool

	// Close releases any resources held by the store
	Close() error

	// Name returns the store type name
	Name() string
}

// Config holds state store configuration
type Config struct {
	// Type is the store type: "memory" or "redis"
	Type string
	// TTL is the state token lifetime
	TTL time.Duration
	// Redis configuration (used when Type is "redis")
	Redis RedisConfig
}

// RedisConfig holds Redis-specific state store configuration
type RedisConfig struct {
	// Addresses is a list of Redis addresses
	Addresses []string
	// Password is the Redis password
	Password string
	// DB is the Redis database number
	DB int
	// KeyPrefix is the prefix for state keys
	KeyPrefix string
	// MasterName is the Sentinel master name (for Sentinel mode)
	MasterName string
}

// DefaultConfig returns default state store configuration
func DefaultConfig() Config {
	return Config{
		Type: "memory",
		TTL:  10 * time.Minute,
		Redis: RedisConfig{
			KeyPrefix: "authportal:state:",
		},
	}
}
