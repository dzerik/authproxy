package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if !cfg.Enabled {
		t.Error("DefaultConfig should have Enabled = true")
	}

	if cfg.Rate != "100-S" {
		t.Errorf("DefaultConfig.Rate = %s, want '100-S'", cfg.Rate)
	}

	if !cfg.TrustForwardedFor {
		t.Error("DefaultConfig should have TrustForwardedFor = true")
	}

	expectedPaths := []string{"/health", "/ready", "/metrics"}
	if len(cfg.ExcludePaths) != len(expectedPaths) {
		t.Errorf("DefaultConfig.ExcludePaths length = %d, want %d", len(cfg.ExcludePaths), len(expectedPaths))
	}

	for i, path := range expectedPaths {
		if cfg.ExcludePaths[i] != path {
			t.Errorf("DefaultConfig.ExcludePaths[%d] = %s, want %s", i, cfg.ExcludePaths[i], path)
		}
	}

	if cfg.ByEndpoint {
		t.Error("DefaultConfig should have ByEndpoint = false")
	}

	if !cfg.Headers.Enabled {
		t.Error("DefaultConfig.Headers should have Enabled = true")
	}

	if cfg.Headers.LimitHeader != "X-RateLimit-Limit" {
		t.Errorf("DefaultConfig.Headers.LimitHeader = %s, want 'X-RateLimit-Limit'", cfg.Headers.LimitHeader)
	}

	if cfg.Headers.RemainingHeader != "X-RateLimit-Remaining" {
		t.Errorf("DefaultConfig.Headers.RemainingHeader = %s, want 'X-RateLimit-Remaining'", cfg.Headers.RemainingHeader)
	}

	if cfg.Headers.ResetHeader != "X-RateLimit-Reset" {
		t.Errorf("DefaultConfig.Headers.ResetHeader = %s, want 'X-RateLimit-Reset'", cfg.Headers.ResetHeader)
	}

	if !cfg.FailClose {
		t.Error("DefaultConfig should have FailClose = true")
	}
}

func TestNewLimiter(t *testing.T) {
	cfg := DefaultConfig()
	l, err := NewLimiter(cfg)

	if err != nil {
		t.Fatalf("NewLimiter failed: %v", err)
	}

	if l == nil {
		t.Fatal("NewLimiter returned nil")
	}

	if l.instance == nil {
		t.Error("NewLimiter should initialize instance")
	}

	if l.store == nil {
		t.Error("NewLimiter should initialize store")
	}
}

func TestNewLimiter_InvalidRate(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Rate = "invalid-rate"

	_, err := NewLimiter(cfg)
	if err == nil {
		t.Error("NewLimiter should fail with invalid rate")
	}
}

func TestNewLimiter_EndpointRates(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ByEndpoint = true
	cfg.EndpointRates = map[string]string{
		"/api":   "50-S",
		"/login": "10-S",
	}

	l, err := NewLimiter(cfg)
	if err != nil {
		t.Fatalf("NewLimiter failed: %v", err)
	}

	if len(l.endpointLimiters) != 2 {
		t.Errorf("Expected 2 endpoint limiters, got %d", len(l.endpointLimiters))
	}
}

func TestNewLimiter_InvalidEndpointRate(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ByEndpoint = true
	cfg.EndpointRates = map[string]string{
		"/api":   "invalid",
		"/login": "10-S",
	}

	l, err := NewLimiter(cfg)
	if err != nil {
		t.Fatalf("NewLimiter should not fail, just skip invalid endpoint: %v", err)
	}

	// Should only have one valid endpoint limiter
	if len(l.endpointLimiters) != 1 {
		t.Errorf("Expected 1 valid endpoint limiter, got %d", len(l.endpointLimiters))
	}
}

func TestLimiter_Middleware_AllowsRequest(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Rate = "100-S"
	l, err := NewLimiter(cfg)
	if err != nil {
		t.Fatalf("NewLimiter failed: %v", err)
	}

	handler := l.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestLimiter_Middleware_ExcludedPath(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Rate = "1-S" // Very restrictive
	l, err := NewLimiter(cfg)
	if err != nil {
		t.Fatalf("NewLimiter failed: %v", err)
	}

	handler := l.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Make many requests to excluded paths - should all succeed
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/health", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d to excluded path should succeed, got %d", i, w.Code)
		}
	}
}

func TestLimiter_Middleware_Headers(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Rate = "100-S"
	l, err := NewLimiter(cfg)
	if err != nil {
		t.Fatalf("NewLimiter failed: %v", err)
	}

	handler := l.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Check rate limit headers
	if w.Header().Get("X-RateLimit-Limit") == "" {
		t.Error("Missing X-RateLimit-Limit header")
	}

	if w.Header().Get("X-RateLimit-Remaining") == "" {
		t.Error("Missing X-RateLimit-Remaining header")
	}

	if w.Header().Get("X-RateLimit-Reset") == "" {
		t.Error("Missing X-RateLimit-Reset header")
	}

	// Verify header values
	limit, err := strconv.ParseInt(w.Header().Get("X-RateLimit-Limit"), 10, 64)
	if err != nil {
		t.Errorf("Invalid X-RateLimit-Limit header: %v", err)
	}
	if limit != 100 {
		t.Errorf("X-RateLimit-Limit = %d, want 100", limit)
	}

	remaining, err := strconv.ParseInt(w.Header().Get("X-RateLimit-Remaining"), 10, 64)
	if err != nil {
		t.Errorf("Invalid X-RateLimit-Remaining header: %v", err)
	}
	if remaining != 99 {
		t.Errorf("X-RateLimit-Remaining = %d, want 99", remaining)
	}
}

func TestLimiter_Middleware_HeadersDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Headers.Enabled = false
	l, err := NewLimiter(cfg)
	if err != nil {
		t.Fatalf("NewLimiter failed: %v", err)
	}

	handler := l.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Headers should not be present
	if w.Header().Get("X-RateLimit-Limit") != "" {
		t.Error("X-RateLimit-Limit header should not be present when disabled")
	}
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
			if key != tt.expectedKey {
				t.Errorf("getClientKey() = %s, want %s", key, tt.expectedKey)
			}
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
			if result != tt.excluded {
				t.Errorf("isExcluded(%s) = %v, want %v", tt.path, result, tt.excluded)
			}
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
	if apiLimiter == l.instance {
		t.Error("Path /api/users should use endpoint limiter, not default")
	}

	loginLimiter := l.getLimiterForPath("/login")
	if loginLimiter == l.instance {
		t.Error("Path /login should use endpoint limiter, not default")
	}

	// Path without endpoint limiter should return default
	defaultLimiter := l.getLimiterForPath("/other/path")
	if defaultLimiter != l.instance {
		t.Error("Path /other/path should use default limiter")
	}
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
	if limiter != l.instance {
		t.Error("Should use default limiter when ByEndpoint is disabled")
	}
}

func TestHeadersConfig(t *testing.T) {
	cfg := HeadersConfig{
		Enabled:         true,
		LimitHeader:     "Custom-Limit",
		RemainingHeader: "Custom-Remaining",
		ResetHeader:     "Custom-Reset",
	}

	if !cfg.Enabled {
		t.Error("Enabled should be true")
	}
	if cfg.LimitHeader != "Custom-Limit" {
		t.Errorf("LimitHeader = %s, want Custom-Limit", cfg.LimitHeader)
	}
	if cfg.RemainingHeader != "Custom-Remaining" {
		t.Errorf("RemainingHeader = %s, want Custom-Remaining", cfg.RemainingHeader)
	}
	if cfg.ResetHeader != "Custom-Reset" {
		t.Errorf("ResetHeader = %s, want Custom-Reset", cfg.ResetHeader)
	}
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

	if !cfg.Enabled {
		t.Error("Enabled should be true")
	}
	if cfg.Rate != "50-S" {
		t.Errorf("Rate = %s, want 50-S", cfg.Rate)
	}
	if cfg.TrustForwardedFor {
		t.Error("TrustForwardedFor should be false")
	}
	if !cfg.ByEndpoint {
		t.Error("ByEndpoint should be true")
	}
	if cfg.FailClose {
		t.Error("FailClose should be false")
	}
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
