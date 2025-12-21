// Package ratelimit provides HTTP rate limiting middleware using ulule/limiter.
package ratelimit

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	"go.uber.org/zap"

	"github.com/dzerik/auth-portal/pkg/logger"
)

// Config holds rate limiting configuration.
type Config struct {
	// Enabled enables rate limiting
	Enabled bool `yaml:"enabled" mapstructure:"enabled"`
	// Rate is the rate limit in format 'requests-period' (e.g. '100-S' for 100 requests per second)
	Rate string `yaml:"rate" mapstructure:"rate"`
	// TrustForwardedFor trusts X-Forwarded-For header for client IP
	TrustForwardedFor bool `yaml:"trust_forwarded_for" mapstructure:"trust_forwarded_for"`
	// ExcludePaths excludes paths from rate limiting
	ExcludePaths []string `yaml:"exclude_paths" mapstructure:"exclude_paths"`
	// ByEndpoint enables per-endpoint rate limiting
	ByEndpoint bool `yaml:"by_endpoint" mapstructure:"by_endpoint"`
	// EndpointRates defines per-endpoint rate limits
	EndpointRates map[string]string `yaml:"endpoint_rates" mapstructure:"endpoint_rates"`
	// Headers configuration for rate limit response headers
	Headers HeadersConfig `yaml:"headers" mapstructure:"headers"`
	// FailClose denies requests when rate limiter encounters an error (secure default)
	FailClose bool `yaml:"fail_close" mapstructure:"fail_close"`
}

// HeadersConfig holds rate limit headers configuration.
type HeadersConfig struct {
	// Enabled enables rate limit headers in response
	Enabled bool `yaml:"enabled" mapstructure:"enabled"`
	// LimitHeader is the header name for rate limit
	LimitHeader string `yaml:"limit_header" mapstructure:"limit_header"`
	// RemainingHeader is the header name for remaining requests
	RemainingHeader string `yaml:"remaining_header" mapstructure:"remaining_header"`
	// ResetHeader is the header name for reset timestamp
	ResetHeader string `yaml:"reset_header" mapstructure:"reset_header"`
}

// DefaultConfig returns default rate limiting configuration.
func DefaultConfig() Config {
	return Config{
		Enabled:           true,
		Rate:              "100-S",
		TrustForwardedFor: true,
		ExcludePaths:      []string{"/health", "/ready", "/metrics"},
		ByEndpoint:        false,
		EndpointRates:     make(map[string]string),
		Headers: HeadersConfig{
			Enabled:         true,
			LimitHeader:     "X-RateLimit-Limit",
			RemainingHeader: "X-RateLimit-Remaining",
			ResetHeader:     "X-RateLimit-Reset",
		},
		FailClose: true,
	}
}

// Limiter wraps the ulule/limiter with configuration.
type Limiter struct {
	cfg      Config
	instance *limiter.Limiter
	store    limiter.Store

	// Per-endpoint limiters
	endpointLimiters map[string]*limiter.Limiter
}

// NewLimiter creates a new rate limiter from configuration.
func NewLimiter(cfg Config) (*Limiter, error) {
	l := &Limiter{
		cfg:              cfg,
		endpointLimiters: make(map[string]*limiter.Limiter),
	}

	// Create in-memory store
	l.store = memory.NewStore()

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
					zap.String("endpoint", endpoint),
					zap.String("rate", rateStr),
					zap.Error(err),
				)
				continue
			}
			l.endpointLimiters[endpoint] = limiter.New(l.store, endpointRate)
		}
	}

	return l, nil
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
				logger.Error("rate limiter error", zap.Error(err))
				// Fail-close (default): deny request on error (secure)
				// Fail-open: allow request on error (less secure but more available)
				if l.cfg.FailClose {
					http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
					return
				}
				// Fail-open: allow the request to proceed
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
					zap.String("client_key", clientKey),
					zap.String("path", r.URL.Path),
					zap.Int64("limit", limitContext.Limit),
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
