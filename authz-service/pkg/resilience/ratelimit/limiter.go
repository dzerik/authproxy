// Package ratelimit provides HTTP rate limiting middleware using ulule/limiter.
package ratelimit

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/redis/go-redis/v9"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	redisstore "github.com/ulule/limiter/v3/drivers/store/redis"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/pkg/logger"
)

// Limiter wraps the ulule/limiter with configuration.
type Limiter struct {
	cfg      config.RateLimitConfig
	instance *limiter.Limiter
	store    limiter.Store

	// Per-endpoint limiters
	endpointLimiters map[string]*limiter.Limiter
}

// NewLimiter creates a new rate limiter from configuration.
func NewLimiter(cfg config.RateLimitConfig) (*Limiter, error) {
	l := &Limiter{
		cfg:              cfg,
		endpointLimiters: make(map[string]*limiter.Limiter),
	}

	// Create store
	var err error
	l.store, err = l.createStore()
	if err != nil {
		return nil, err
	}

	// Parse default rate
	rate, err := limiter.NewRateFromFormatted(cfg.Rate)
	if err != nil {
		return nil, err
	}

	// Create main limiter instance
	l.instance = limiter.New(l.store, rate)

	// Create per-endpoint limiters if enabled
	if cfg.ByEndpoint && len(cfg.EndpointRates) > 0 {
		for endpoint, rateStr := range cfg.EndpointRates {
			endpointRate, err := limiter.NewRateFromFormatted(rateStr)
			if err != nil {
				logger.Warn("invalid endpoint rate, using default",
					logger.String("endpoint", endpoint),
					logger.String("rate", rateStr),
					logger.Err(err),
				)
				continue
			}
			l.endpointLimiters[endpoint] = limiter.New(l.store, endpointRate)
		}
	}

	return l, nil
}

// createStore creates the appropriate store based on configuration.
func (l *Limiter) createStore() (limiter.Store, error) {
	switch l.cfg.Store {
	case "redis":
		client := redis.NewClient(&redis.Options{
			Addr:     l.cfg.Redis.Address,
			Password: l.cfg.Redis.Password,
			DB:       l.cfg.Redis.DB,
		})

		// Test connection
		if _, err := client.Ping(context.Background()).Result(); err != nil {
			return nil, err
		}

		return redisstore.NewStoreWithOptions(client, limiter.StoreOptions{
			Prefix: l.cfg.Redis.KeyPrefix,
		})

	default:
		return memory.NewStore(), nil
	}
}

// Middleware returns an HTTP middleware that applies rate limiting.
func (l *Limiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if path is excluded
			if l.isExcluded(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// Get the appropriate limiter for this request
			instance := l.getLimiterForPath(r.URL.Path)

			// Get client key
			clientKey := l.getClientKey(r)

			// Check rate limit
			ctx := r.Context()
			limitContext, err := instance.Get(ctx, clientKey)
			if err != nil {
				logger.Error("rate limiter error", logger.Err(err))
				// On error, allow the request to proceed
				next.ServeHTTP(w, r)
				return
			}

			// Add rate limit headers if enabled
			if l.cfg.Headers.Enabled {
				w.Header().Set(l.cfg.Headers.LimitHeader, strconv.FormatInt(limitContext.Limit, 10))
				w.Header().Set(l.cfg.Headers.RemainingHeader, strconv.FormatInt(limitContext.Remaining, 10))
				w.Header().Set(l.cfg.Headers.ResetHeader, strconv.FormatInt(limitContext.Reset, 10))
			}

			// Check if limit exceeded
			if limitContext.Reached {
				logger.Warn("rate limit exceeded",
					logger.String("client_key", clientKey),
					logger.String("path", r.URL.Path),
					logger.Int64("limit", limitContext.Limit),
				)
				http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// getLimiterForPath returns the appropriate limiter for the given path.
func (l *Limiter) getLimiterForPath(path string) *limiter.Limiter {
	if !l.cfg.ByEndpoint {
		return l.instance
	}

	// Find matching endpoint limiter
	for endpoint, endpointLimiter := range l.endpointLimiters {
		if strings.HasPrefix(path, endpoint) {
			return endpointLimiter
		}
	}

	return l.instance
}

// getClientKey determines the client identifier for rate limiting.
func (l *Limiter) getClientKey(r *http.Request) string {
	if l.cfg.TrustForwardedFor {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Take the first IP from X-Forwarded-For
			if idx := strings.Index(xff, ","); idx != -1 {
				return strings.TrimSpace(xff[:idx])
			}
			return strings.TrimSpace(xff)
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

// isExcluded checks if the path should be excluded from rate limiting.
func (l *Limiter) isExcluded(path string) bool {
	for _, excluded := range l.cfg.ExcludePaths {
		if strings.HasPrefix(path, excluded) {
			return true
		}
	}
	return false
}

// Get manually checks the rate limit for a key without incrementing.
func (l *Limiter) Get(ctx context.Context, key string) (limiter.Context, error) {
	return l.instance.Peek(ctx, key)
}

// Increment manually increments the rate limit counter.
func (l *Limiter) Increment(ctx context.Context, key string, count int64) (limiter.Context, error) {
	return l.instance.Increment(ctx, key, count)
}

// Reset resets the rate limit for a specific key.
func (l *Limiter) Reset(ctx context.Context, key string) (limiter.Context, error) {
	return l.instance.Reset(ctx, key)
}
