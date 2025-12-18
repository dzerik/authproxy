package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/your-org/authz-service/internal/config"
)

func TestNewLimiter(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled: true,
		Rate:    "100-S", // 100 requests per second
		Store:   "memory",
	}

	limiter, err := NewLimiter(cfg)
	require.NoError(t, err)
	require.NotNil(t, limiter)
}

func TestNewLimiter_InvalidRate(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled: true,
		Rate:    "invalid-rate",
		Store:   "memory",
	}

	limiter, err := NewLimiter(cfg)
	assert.Error(t, err)
	assert.Nil(t, limiter)
}

func TestNewLimiter_WithEndpointRates(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:    true,
		Rate:       "100-S",
		Store:      "memory",
		ByEndpoint: true,
		EndpointRates: map[string]string{
			"/api/v1/authorize": "50-S",
			"/api/v1/token":     "20-S",
		},
	}

	limiter, err := NewLimiter(cfg)
	require.NoError(t, err)
	require.NotNil(t, limiter)
	assert.Len(t, limiter.endpointLimiters, 2)
}

func TestNewLimiter_WithInvalidEndpointRate(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:    true,
		Rate:       "100-S",
		Store:      "memory",
		ByEndpoint: true,
		EndpointRates: map[string]string{
			"/api/v1/authorize": "invalid",
		},
	}

	// Should not fail, just skip invalid endpoint rate
	limiter, err := NewLimiter(cfg)
	require.NoError(t, err)
	require.NotNil(t, limiter)
	assert.Len(t, limiter.endpointLimiters, 0)
}

func TestLimiter_Middleware(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled: true,
		Rate:    "10-S", // 10 requests per second
		Store:   "memory",
		Headers: config.RateLimitHeadersConfig{
			Enabled:         true,
			LimitHeader:     "X-RateLimit-Limit",
			RemainingHeader: "X-RateLimit-Remaining",
			ResetHeader:     "X-RateLimit-Reset",
		},
	}

	limiter, err := NewLimiter(cfg)
	require.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	middleware := limiter.Middleware()
	wrappedHandler := middleware(handler)

	// First request should succeed
	req := httptest.NewRequest("GET", "/api/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rr := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.NotEmpty(t, rr.Header().Get("X-RateLimit-Limit"))
	assert.NotEmpty(t, rr.Header().Get("X-RateLimit-Remaining"))
	assert.NotEmpty(t, rr.Header().Get("X-RateLimit-Reset"))
}

func TestLimiter_Middleware_RateLimitExceeded(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled: true,
		Rate:    "2-S", // 2 requests per second - very low for testing
		Store:   "memory",
	}

	limiter, err := NewLimiter(cfg)
	require.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := limiter.Middleware()
	wrappedHandler := middleware(handler)

	// Send multiple requests from same IP
	var lastStatus int
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.RemoteAddr = "192.168.1.100:12345"
		rr := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rr, req)
		lastStatus = rr.Code
	}

	// After exceeding limit, should get 429
	assert.Equal(t, http.StatusTooManyRequests, lastStatus)
}

func TestLimiter_Middleware_ExcludedPath(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:      true,
		Rate:         "1-S", // Very restrictive
		Store:        "memory",
		ExcludePaths: []string{"/health", "/metrics"},
	}

	limiter, err := NewLimiter(cfg)
	require.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := limiter.Middleware()
	wrappedHandler := middleware(handler)

	// Excluded paths should always succeed
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/health", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rr := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	}
}

func TestLimiter_GetClientKey(t *testing.T) {
	tests := []struct {
		name               string
		trustForwardedFor  bool
		remoteAddr         string
		xForwardedFor      string
		xRealIP            string
		expectedKey        string
	}{
		{
			name:              "use RemoteAddr when trust disabled",
			trustForwardedFor: false,
			remoteAddr:        "192.168.1.1:12345",
			xForwardedFor:     "10.0.0.1",
			expectedKey:       "192.168.1.1",
		},
		{
			name:              "use X-Forwarded-For when trusted",
			trustForwardedFor: true,
			remoteAddr:        "192.168.1.1:12345",
			xForwardedFor:     "10.0.0.1",
			expectedKey:       "10.0.0.1",
		},
		{
			name:              "use first IP from X-Forwarded-For chain",
			trustForwardedFor: true,
			remoteAddr:        "192.168.1.1:12345",
			xForwardedFor:     "10.0.0.1, 10.0.0.2, 10.0.0.3",
			expectedKey:       "10.0.0.1",
		},
		{
			name:              "use X-Real-IP as fallback",
			trustForwardedFor: true,
			remoteAddr:        "192.168.1.1:12345",
			xRealIP:           "10.0.0.5",
			expectedKey:       "10.0.0.5",
		},
		{
			name:              "fallback to RemoteAddr when no headers",
			trustForwardedFor: true,
			remoteAddr:        "192.168.1.1:12345",
			expectedKey:       "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.RateLimitConfig{
				Enabled:           true,
				Rate:              "100-S",
				Store:             "memory",
				TrustForwardedFor: tt.trustForwardedFor,
			}

			limiter, err := NewLimiter(cfg)
			require.NoError(t, err)

			req := httptest.NewRequest("GET", "/api/test", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			key := limiter.getClientKey(req)
			assert.Equal(t, tt.expectedKey, key)
		})
	}
}

func TestLimiter_GetLimiterForPath(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:    true,
		Rate:       "100-S",
		Store:      "memory",
		ByEndpoint: true,
		EndpointRates: map[string]string{
			"/api/v1/authorize": "50-S",
			"/api/v2":           "25-S",
		},
	}

	limiter, err := NewLimiter(cfg)
	require.NoError(t, err)

	tests := []struct {
		path        string
		isDefault   bool
	}{
		{"/api/v1/authorize", false},
		{"/api/v1/authorize/batch", false},
		{"/api/v2/something", false},
		{"/api/v3/other", true}, // Should use default
		{"/health", true},       // Should use default
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := limiter.getLimiterForPath(tt.path)
			if tt.isDefault {
				assert.Equal(t, limiter.instance, result)
			} else {
				assert.NotEqual(t, limiter.instance, result)
			}
		})
	}
}

func TestLimiter_IsExcluded(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:      true,
		Rate:         "100-S",
		Store:        "memory",
		ExcludePaths: []string{"/health", "/metrics", "/api/internal"},
	}

	limiter, err := NewLimiter(cfg)
	require.NoError(t, err)

	tests := []struct {
		path     string
		excluded bool
	}{
		{"/health", true},
		{"/healthz", true},
		{"/metrics", true},
		{"/metrics/prometheus", true},
		{"/api/internal", true},
		{"/api/internal/status", true},
		{"/api/v1/authorize", false},
		{"/api/external", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := limiter.isExcluded(tt.path)
			assert.Equal(t, tt.excluded, result)
		})
	}
}

func BenchmarkLimiter_Middleware(b *testing.B) {
	cfg := config.RateLimitConfig{
		Enabled: true,
		Rate:    "1000000-S", // High limit for benchmark
		Store:   "memory",
	}

	limiter, _ := NewLimiter(cfg)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := limiter.Middleware()
	wrappedHandler := middleware(handler)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rr := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rr, req)
	}
}

func BenchmarkLimiter_GetClientKey(b *testing.B) {
	cfg := config.RateLimitConfig{
		Enabled:           true,
		Rate:              "100-S",
		Store:             "memory",
		TrustForwardedFor: true,
	}

	limiter, _ := NewLimiter(cfg)

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		limiter.getClientKey(req)
	}
}
