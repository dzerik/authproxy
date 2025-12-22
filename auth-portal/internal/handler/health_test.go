package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHealthHandler(t *testing.T) {
	cfg := &config.Config{}

	h := NewHealthHandler(cfg, nil)
	require.NotNil(t, h)
	assert.Equal(t, cfg, h.config)
	assert.False(t, h.startTime.IsZero(), "startTime should be set")
	assert.False(t, h.ready, "ready should be false initially")
}

func TestHealthHandler_SetReady(t *testing.T) {
	h := NewHealthHandler(&config.Config{}, nil)

	assert.False(t, h.IsReady(), "IsReady should return false initially")

	h.SetReady(true)
	assert.True(t, h.IsReady(), "IsReady should return true after SetReady(true)")

	h.SetReady(false)
	assert.False(t, h.IsReady(), "IsReady should return false after SetReady(false)")
}

func TestHealthHandler_HandleHealth(t *testing.T) {
	h := NewHealthHandler(&config.Config{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	h.HandleHealth(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var response HealthResponse
	err := json.NewDecoder(rr.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, "healthy", response.Status)
	assert.NotEmpty(t, response.Timestamp, "timestamp should be set")
	assert.NotEmpty(t, response.Uptime, "uptime should be set")
}

func TestHealthHandler_HandleReady_NotReady(t *testing.T) {
	h := NewHealthHandler(&config.Config{}, nil)
	// Not setting ready

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rr := httptest.NewRecorder()

	h.HandleReady(rr, req)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)

	var response HealthResponse
	err := json.NewDecoder(rr.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, "not ready", response.Status)
	assert.Equal(t, "not ready", response.Checks["startup"])
}

func TestHealthHandler_HandleReady_Ready(t *testing.T) {
	h := NewHealthHandler(&config.Config{}, nil)
	h.SetReady(true)

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rr := httptest.NewRecorder()

	h.HandleReady(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response HealthResponse
	err := json.NewDecoder(rr.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, "ready", response.Status)
	assert.Equal(t, "ok", response.Checks["startup"])
}

func TestHealthHandler_HandleMetrics(t *testing.T) {
	cfg := &config.Config{
		Mode: "portal",
		Session: config.SessionConfig{
			Store: "cookie",
		},
		Services: []config.ServiceConfig{
			{Name: "service1"},
			{Name: "service2"},
			{Name: "service3"},
		},
	}

	h := NewHealthHandler(cfg, nil)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()

	h.HandleMetrics(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var response MetricsResponse
	err := json.NewDecoder(rr.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, "cookie", response.SessionStore)
	assert.Equal(t, "portal", response.Mode)
	assert.Equal(t, 3, response.Services)
	assert.Greater(t, response.GoRoutines, 0, "GoRoutines should be positive")
	assert.NotZero(t, response.MemoryAlloc, "MemoryAlloc should be set")
}

func TestHealthHandler_HandlePrometheusMetrics(t *testing.T) {
	cfg := &config.Config{
		Services: []config.ServiceConfig{
			{Name: "service1"},
			{Name: "service2"},
		},
	}

	h := NewHealthHandler(cfg, nil)
	h.SetReady(true)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()

	h.HandlePrometheusMetrics(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.True(t, strings.HasPrefix(rr.Header().Get("Content-Type"), "text/plain"))

	body := rr.Body.String()

	// Check for required Prometheus metrics
	expectedMetrics := []string{
		"auth_portal_uptime_seconds",
		"auth_portal_goroutines",
		"auth_portal_memory_alloc_bytes",
		"auth_portal_memory_sys_bytes",
		"auth_portal_gc_runs_total",
		"auth_portal_services_count",
		"auth_portal_ready",
	}

	for _, metric := range expectedMetrics {
		assert.Contains(t, body, metric)
	}

	// Check services count
	assert.Contains(t, body, "auth_portal_services_count 2")

	// Check ready status is 1
	assert.Contains(t, body, "auth_portal_ready 1")
}

func TestHealthHandler_HandlePrometheusMetrics_NotReady(t *testing.T) {
	h := NewHealthHandler(&config.Config{}, nil)
	// Not setting ready

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()

	h.HandlePrometheusMetrics(rr, req)

	body := rr.Body.String()

	// Check ready status is 0
	assert.Contains(t, body, "auth_portal_ready 0")
}

func TestHealthHandler_Uptime(t *testing.T) {
	h := NewHealthHandler(&config.Config{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	h.HandleHealth(rr, req)

	var response HealthResponse
	err := json.NewDecoder(rr.Body).Decode(&response)
	require.NoError(t, err)

	// Uptime should be a valid duration string (may be "0s" if test runs fast)
	assert.NotEmpty(t, response.Uptime, "uptime should not be empty")

	// Parse uptime to ensure it's a valid duration
	_, err = time.ParseDuration(response.Uptime)
	require.NoError(t, err, "uptime should be a valid duration")
}

func TestHealthHandler_Concurrency(t *testing.T) {
	h := NewHealthHandler(&config.Config{}, nil)

	done := make(chan bool)

	// Concurrent read/write to ready status
	for i := 0; i < 10; i++ {
		go func(i int) {
			h.SetReady(i%2 == 0)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		go func() {
			_ = h.IsReady()
			done <- true
		}()
	}

	for i := 0; i < 20; i++ {
		<-done
	}
}

func TestHealthResponse_Struct(t *testing.T) {
	response := HealthResponse{
		Status:    "healthy",
		Timestamp: "2024-01-01T00:00:00Z",
		Uptime:    "1h0m0s",
		Version:   "1.0.0",
		Checks: map[string]string{
			"nginx":   "ok",
			"startup": "ok",
		},
	}

	assert.Equal(t, "healthy", response.Status)
	assert.Len(t, response.Checks, 2)
}

func TestMetricsResponse_Struct(t *testing.T) {
	response := MetricsResponse{
		Uptime:       3600,
		GoRoutines:   10,
		MemoryAlloc:  1024,
		MemorySys:    2048,
		NumGC:        5,
		SessionStore: "cookie",
		Mode:         "portal",
		Services:     3,
		Custom: map[string]int64{
			"custom_metric": 42,
		},
	}

	assert.Equal(t, int64(3600), response.Uptime)
	assert.Equal(t, int64(42), response.Custom["custom_metric"])
}

func BenchmarkHandleHealth(b *testing.B) {
	h := NewHealthHandler(&config.Config{}, nil)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		h.HandleHealth(rr, req)
	}
}

func BenchmarkHandlePrometheusMetrics(b *testing.B) {
	h := NewHealthHandler(&config.Config{
		Services: []config.ServiceConfig{
			{Name: "service1"},
			{Name: "service2"},
		},
	}, nil)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		h.HandlePrometheusMetrics(rr, req)
	}
}
