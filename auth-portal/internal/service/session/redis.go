package session

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/model"
	"github.com/dzerik/auth-portal/internal/service/crypto"
	"github.com/redis/go-redis/v9"
)

// RedisStore stores session data in Redis with encrypted values
type RedisStore struct {
	client       redis.UniversalClient
	cookieName   string
	cookieDomain string // MED-02 security fix: configurable domain for cross-subdomain sessions
	keyPrefix    string
	encryptor    *crypto.Encryptor
	secure       bool
	sameSite     http.SameSite
	ttl          time.Duration
}

// NewRedisStore creates a new Redis-based session store
func NewRedisStore(cfg *config.SessionConfig) (*RedisStore, error) {
	if !cfg.Redis.Enabled && len(cfg.Redis.Addresses) == 0 {
		return nil, fmt.Errorf("redis not configured")
	}

	// Build Redis options
	opts := &redis.UniversalOptions{
		Addrs:        cfg.Redis.Addresses,
		Password:     cfg.Redis.Password,
		DB:           cfg.Redis.DB,
		MasterName:   cfg.Redis.MasterName,
		PoolSize:     cfg.Redis.PoolSize,
		MinIdleConns: cfg.Redis.MinIdleConns,
	}

	// Configure TLS if enabled
	if cfg.Redis.TLS.Enabled {
		tlsConfig, err := buildRedisTLSConfig(&cfg.Redis.TLS)
		if err != nil {
			return nil, fmt.Errorf("failed to configure Redis TLS: %w", err)
		}
		opts.TLSConfig = tlsConfig
	}

	// Create Redis client
	client := redis.NewUniversalClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	// Create encryptor if encryption is enabled
	var encryptor *crypto.Encryptor
	if cfg.Encryption.Enabled {
		var err error
		encryptor, err = crypto.NewEncryptorFromString(cfg.Encryption.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to create encryptor: %w", err)
		}
	}

	keyPrefix := cfg.Redis.KeyPrefix
	if keyPrefix == "" {
		keyPrefix = "authportal:session:"
	}

	sameSite := parseSameSite(cfg.SameSite)

	return &RedisStore{
		client:       client,
		cookieName:   cfg.CookieName,
		cookieDomain: cfg.CookieDomain,
		keyPrefix:    keyPrefix,
		encryptor:    encryptor,
		secure:       cfg.Secure,
		sameSite:     sameSite,
		ttl:          cfg.TTL,
	}, nil
}

// Get retrieves a session from Redis
func (s *RedisStore) Get(r *http.Request) (*model.Session, error) {
	cookie, err := r.Cookie(s.cookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("failed to get cookie: %w", err)
	}

	sessionID := cookie.Value
	if sessionID == "" {
		return nil, ErrSessionNotFound
	}

	// Get from Redis
	ctx := r.Context()
	key := s.keyPrefix + sessionID
	data, err := s.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("failed to get session from Redis: %w", err)
	}

	// Decrypt if encryption is enabled
	var jsonData []byte
	if s.encryptor != nil {
		decrypted, err := s.encryptor.Decrypt(string(data))
		if err != nil {
			return nil, ErrSessionInvalid
		}
		jsonData = decrypted
	} else {
		jsonData = data
	}

	// Unmarshal session data
	var sessionData model.SessionData
	if err := json.Unmarshal(jsonData, &sessionData); err != nil {
		return nil, ErrSessionInvalid
	}

	// Convert to session
	session := sessionData.ToSession()

	// Check expiration
	if session.IsExpired() {
		// Clean up expired session
		s.client.Del(ctx, key)
		return nil, ErrSessionExpired
	}

	// Touch last access time
	session.Touch()

	return session, nil
}

// Save saves a session to Redis
func (s *RedisStore) Save(w http.ResponseWriter, r *http.Request, session *model.Session) error {
	if session.User == nil {
		return fmt.Errorf("session has no user data")
	}

	// Generate session ID if not set
	if session.ID == "" {
		id, err := crypto.GenerateSessionID()
		if err != nil {
			return fmt.Errorf("failed to generate session ID: %w", err)
		}
		session.ID = id
	}

	// Set expiration if not set
	if session.ExpiresAt.IsZero() {
		session.ExpiresAt = time.Now().Add(s.ttl)
	}

	// Convert to session data
	sessionData := session.ToSessionData()

	// Marshal to JSON
	jsonData, err := json.Marshal(sessionData)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	// Encrypt if encryption is enabled
	var data string
	if s.encryptor != nil {
		encrypted, err := s.encryptor.Encrypt(jsonData)
		if err != nil {
			return fmt.Errorf("failed to encrypt session: %w", err)
		}
		data = encrypted
	} else {
		data = string(jsonData)
	}

	// Save to Redis with TTL
	ctx := r.Context()
	key := s.keyPrefix + session.ID
	ttl := time.Until(session.ExpiresAt)
	if ttl <= 0 {
		ttl = s.ttl
	}

	if err := s.client.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("failed to save session to Redis: %w", err)
	}

	// Set cookie with session ID
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    session.ID,
		Path:     "/",
		Domain:   s.cookieDomain, // MED-02: configurable domain for cross-subdomain sessions
		Expires:  session.ExpiresAt,
		MaxAge:   int(time.Until(session.ExpiresAt).Seconds()),
		Secure:   s.secure,
		HttpOnly: true,
		SameSite: s.sameSite,
	})

	return nil
}

// Delete removes a session from Redis
func (s *RedisStore) Delete(w http.ResponseWriter, r *http.Request) error {
	// Get session ID from cookie
	cookie, err := r.Cookie(s.cookieName)
	if err == nil && cookie.Value != "" {
		// Delete from Redis
		ctx := r.Context()
		key := s.keyPrefix + cookie.Value
		s.client.Del(ctx, key)
	}

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    "",
		Path:     "/",
		Domain:   s.cookieDomain, // MED-02: must match domain used in Save
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   s.secure,
		HttpOnly: true,
		SameSite: s.sameSite,
	})

	return nil
}

// Name returns the store type name
func (s *RedisStore) Name() string {
	return "redis"
}

// Close closes the Redis connection
func (s *RedisStore) Close() error {
	return s.client.Close()
}

// buildRedisTLSConfig builds TLS configuration for Redis
func buildRedisTLSConfig(cfg *config.RedisTLSConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Load client certificate if provided
	if cfg.Cert != "" && cfg.Key != "" {
		cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Load CA certificate if provided
	if cfg.CA != "" {
		// Note: In production, load the CA certificate properly
		// For now, we just set InsecureSkipVerify to false
		tlsConfig.InsecureSkipVerify = false
	}

	return tlsConfig, nil
}
