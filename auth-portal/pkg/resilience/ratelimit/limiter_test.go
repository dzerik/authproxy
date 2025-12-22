package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.True(t, cfg.Enabled)
	assert.Equal(t, "100-S", cfg.Rate)
	assert.True(t, cfg.TrustForwardedFor)

	expectedPaths := []string{"/health", "/ready", "/metrics"}
	require.Len(t, cfg.ExcludePaths, len(expectedPaths))

	for i, path := range expectedPaths {
		assert.Equal(t, path, cfg.ExcludePaths[i])
	}

	assert.False(t, cfg.ByEndpoint)
	assert.True(t, cfg.Headers.Enabled)
	assert.Equal(t, "X-RateLimit-Limit", cfg.Headers.LimitHeader)
	assert.Equal(t, "X-RateLimit-Remaining", cfg.Headers.RemainingHeader)
	assert.Equal(t, "X-RateLimit-Reset", cfg.Headers.ResetHeader)
	assert.True(t, cfg.FailClose)
}

func TestNewLimiter(t *testing.T) {
	cfg := DefaultConfig()
	l, err := NewLimiter(cfg)

	require.NoError(t, err)
	require.NotNil(t, l)
	assert.NotNil(t, l.instance)
	assert.NotNil(t, l.store)
}

func TestNewLimiter_InvalidRate(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Rate = "invalid-rate"

	_, err := NewLimiter(cfg)
	assert.Error(t, err)
}

func TestNewLimiter_EndpointRates(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ByEndpoint = true
	cfg.EndpointRates = map[string]string{
		"/api":   "50-S",
		"/login": "10-S",
	}

	l, err := NewLimiter(cfg)
	require.NoError(t, err)
	assert.Len(t, l.endpointLimiters, 2)
}

func TestNewLimiter_InvalidEndpointRate(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ByEndpoint = true
	cfg.EndpointRates = map[string]string{
		"/api":   "invalid",
		"/login": "10-S",
	}

	l, err := NewLimiter(cfg)
	require.NoError(t, err)

	// Should only have one valid endpoint limiter
	assert.Len(t, l.endpointLimiters, 1)
}

func TestLimiter_Middleware_AllowsRequest(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Rate = "100-S"
	l, err := NewLimiter(cfg)
	require.NoError(t, err)

	handler := l.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestLimiter_Middleware_ExcludedPath(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Rate = "1-S" // Very restrictive
	l, err := NewLimiter(cfg)
	require.NoError(t, err)

	handler := l.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Make many requests to excluded paths - should all succeed
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/health", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Request %d to excluded path should succeed", i)
	}
}

func TestLimiter_Middleware_Headers(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Rate = "100-S"
	l, err := NewLimiter(cfg)
	require.NoError(t, err)

	handler := l.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Check rate limit headers
	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Limit"))
	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Remaining"))
	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Reset"))

	// Verify header values
	limit, err := strconv.ParseInt(w.Header().Get("X-RateLimit-Limit"), 10, 64)
	require.NoError(t, err)
	assert.Equal(t, int64(100), limit)

	remaining, err := strconv.ParseInt(w.Header().Get("X-RateLimit-Remaining"), 10, 64)
	require.NoError(t, err)
	assert.Equal(t, int64(99), remaining)
}

func TestLimiter_Middleware_HeadersDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Headers.Enabled = false
	l, err := NewLimiter(cfg)
	require.NoError(t, err)

	handler := l.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Headers should not be present
	assert.Empty(t, w.Header().Get("X-RateLimit-Limit"))
}

func TestLimiter_getClientKey(t *testing.T) {
	tests := []struct {
		name               string
		trustForwardedFor  bool
		remoteAddr         string
		xForwardedFor      string
		xRealIP            string
		expectedKey        string
	}{
		{
			name:              "remote addr only",
			trustForwardedFor: false,
			remoteAddr:        "192.168.1.1:12345",
			expectedKey:       "192.168.1.1",
		},
		{
			name:              "X-Forwarded-For trusted",
			trustForwardedFor: true,
			remoteAddr:        "10.0.0.1:12345",
			xForwardedFor:     "203.0.113.50",
			expectedKey:       "203.0.113.50",
		},
		{
			name:              "X-Forwarded-For with multiple IPs",
			trustForwardedFor: true,
			remoteAddr:        "10.0.0.1:12345",
			xForwardedFor:     "203.0.113.50, 70.41.3.18, 150.172.238.178",
			expectedKey:       "203.0.113.50",
		},
		{
			name:              "X-Real-IP trusted",
			trustForwardedFor: true,
			remoteAddr:        "10.0.0.1:12345",
			xRealIP:           "203.0.113.100",
			expectedKey:       "203.0.113.100",
		},
		{
			name:              "X-Forwarded-For takes priority over X-Real-IP",
			trustForwardedFor: true,
			remoteAddr:        "10.0.0.1:12345",
			xForwardedFor:     "203.0.113.50",
			xRealIP:           "203.0.113.100",
			expectedKey:       "203.0.113.50",
		},
		{
			name:              "Fallback to remote addr when headers empty",
			trustForwardedFor: true,
			remoteAddr:        "192.168.1.1:12345",
			expectedKey:       "192.168.1.1",
		},
		{
			name:              "IPv6 remote addr",
			trustForwardedFor: false,
			remoteAddr:        "[::1]:12345",
			expectedKey:       "[::1]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.TrustForwardedFor = tt.trustForwardedFor
			l, _ := NewLimiter(cfg)

			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			key := l.getClientKey(req)
			assert.Equal(t, tt.expectedKey, key)
		})
	}
}

func TestLimiter_isExcluded(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ExcludePaths = []string{"/health", "/ready", "/metrics", "/api/public"}
	l, _ := NewLimiter(cfg)

	tests := []struct {
		path     string
		excluded bool
	}{
		{"/health", true},
		{"/health/check", true},
		{"/ready", true},
		{"/metrics", true},
		{"/metrics/prometheus", true},
		{"/api/public", true},
		{"/api/public/data", true},
		{"/api/private", false},
		{"/login", false},
		{"/", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := l.isExcluded(tt.path)
			assert.Equal(t, tt.excluded, result)
		})
	}
}

func TestLimiter_getLimiterForPath(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ByEndpoint = true
	cfg.EndpointRates = map[string]string{
		"/api":   "50-S",
		"/login": "10-S",
	}
	l, _ := NewLimiter(cfg)

	// Path with endpoint limiter should return that limiter
	apiLimiter := l.getLimiterForPath("/api/users")
	assert.NotEqual(t, l.instance, apiLimiter)

	loginLimiter := l.getLimiterForPath("/login")
	assert.NotEqual(t, l.instance, loginLimiter)

	// Path without endpoint limiter should return default
	defaultLimiter := l.getLimiterForPath("/other/path")
	assert.Equal(t, l.instance, defaultLimiter)
}

func TestLimiter_getLimiterForPath_ByEndpointDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ByEndpoint = false
	cfg.EndpointRates = map[string]string{
		"/api": "50-S",
	}
	l, _ := NewLimiter(cfg)

	// Should always return default limiter when ByEndpoint is disabled
	limiter := l.getLimiterForPath("/api/users")
	assert.Equal(t, l.instance, limiter)
}

func TestHeadersConfig(t *testing.T) {
	cfg := HeadersConfig{
		Enabled:         true,
		LimitHeader:     "Custom-Limit",
		RemainingHeader: "Custom-Remaining",
		ResetHeader:     "Custom-Reset",
	}

	assert.True(t, cfg.Enabled)
	assert.Equal(t, "Custom-Limit", cfg.LimitHeader)
	assert.Equal(t, "Custom-Remaining", cfg.RemainingHeader)
	assert.Equal(t, "Custom-Reset", cfg.ResetHeader)
}

func TestConfig(t *testing.T) {
	cfg := Config{
		Enabled:           true,
		Rate:              "50-S",
		TrustForwardedFor: false,
		ExcludePaths:      []string{"/health"},
		ByEndpoint:        true,
		EndpointRates:     map[string]string{"/api": "100-S"},
		FailClose:         false,
	}

	assert.True(t, cfg.Enabled)
	assert.Equal(t, "50-S", cfg.Rate)
	assert.False(t, cfg.TrustForwardedFor)
	assert.True(t, cfg.ByEndpoint)
	assert.False(t, cfg.FailClose)
}

func BenchmarkMiddleware(b *testing.B) {
	cfg := DefaultConfig()
	cfg.Rate = "10000-S"
	l, _ := NewLimiter(cfg)

	handler := l.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

func BenchmarkGetClientKey(b *testing.B) {
	cfg := DefaultConfig()
	l, _ := NewLimiter(cfg)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 70.41.3.18")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = l.getClientKey(req)
	}
}

func BenchmarkIsExcluded(b *testing.B) {
	cfg := DefaultConfig()
	l, _ := NewLimiter(cfg)

	paths := []string{"/health", "/api/users", "/metrics", "/login"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, path := range paths {
			_ = l.isExcluded(path)
		}
	}
}
