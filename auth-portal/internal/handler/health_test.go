package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dzerik/auth-portal/internal/config"
)

func TestNewHealthHandler(t *testing.T) {
	cfg := &config.Config{}

	h := NewHealthHandler(cfg, nil)
	if h == nil {
		t.Fatal("NewHealthHandler returned nil")
	}
	if h.config != cfg {
		t.Error("config not set correctly")
	}
	if h.startTime.IsZero() {
		t.Error("startTime should be set")
	}
	if h.ready {
		t.Error("ready should be false initially")
	}
}

func TestHealthHandler_SetReady(t *testing.T) {
	h := NewHealthHandler(&config.Config{}, nil)

	if h.IsReady() {
		t.Error("IsReady should return false initially")
	}

	h.SetReady(true)
	if !h.IsReady() {
		t.Error("IsReady should return true after SetReady(true)")
	}

	h.SetReady(false)
	if h.IsReady() {
		t.Error("IsReady should return false after SetReady(false)")
	}
}

func TestHealthHandler_HandleHealth(t *testing.T) {
	h := NewHealthHandler(&config.Config{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	h.HandleHealth(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %s, want application/json", ct)
	}

	var response HealthResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.Status != "healthy" {
		t.Errorf("status = %s, want healthy", response.Status)
	}
	if response.Timestamp == "" {
		t.Error("timestamp should be set")
	}
	if response.Uptime == "" {
		t.Error("uptime should be set")
	}
}

func TestHealthHandler_HandleReady_NotReady(t *testing.T) {
	h := NewHealthHandler(&config.Config{}, nil)
	// Not setting ready

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rr := httptest.NewRecorder()

	h.HandleReady(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}

	var response HealthResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.Status != "not ready" {
		t.Errorf("status = %s, want 'not ready'", response.Status)
	}
	if response.Checks["startup"] != "not ready" {
		t.Errorf("startup check = %s, want 'not ready'", response.Checks["startup"])
	}
}

func TestHealthHandler_HandleReady_Ready(t *testing.T) {
	h := NewHealthHandler(&config.Config{}, nil)
	h.SetReady(true)

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rr := httptest.NewRecorder()

	h.HandleReady(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var response HealthResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.Status != "ready" {
		t.Errorf("status = %s, want 'ready'", response.Status)
	}
	if response.Checks["startup"] != "ok" {
		t.Errorf("startup check = %s, want 'ok'", response.Checks["startup"])
	}
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

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %s, want application/json", ct)
	}

	var response MetricsResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.SessionStore != "cookie" {
		t.Errorf("SessionStore = %s, want cookie", response.SessionStore)
	}
	if response.Mode != "portal" {
		t.Errorf("Mode = %s, want portal", response.Mode)
	}
	if response.Services != 3 {
		t.Errorf("Services = %d, want 3", response.Services)
	}
	if response.GoRoutines <= 0 {
		t.Error("GoRoutines should be positive")
	}
	if response.MemoryAlloc == 0 {
		t.Error("MemoryAlloc should be set")
	}
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

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %s, want text/plain", ct)
	}

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
		if !strings.Contains(body, metric) {
			t.Errorf("body should contain %s", metric)
		}
	}

	// Check services count
	if !strings.Contains(body, "auth_portal_services_count 2") {
		t.Error("should have services_count 2")
	}

	// Check ready status is 1
	if !strings.Contains(body, "auth_portal_ready 1") {
		t.Error("should have ready 1")
	}
}

func TestHealthHandler_HandlePrometheusMetrics_NotReady(t *testing.T) {
	h := NewHealthHandler(&config.Config{}, nil)
	// Not setting ready

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()

	h.HandlePrometheusMetrics(rr, req)

	body := rr.Body.String()

	// Check ready status is 0
	if !strings.Contains(body, "auth_portal_ready 0") {
		t.Error("should have ready 0")
	}
}

func TestHealthHandler_Uptime(t *testing.T) {
	h := NewHealthHandler(&config.Config{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	h.HandleHealth(rr, req)

	var response HealthResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Uptime should be a valid duration string (may be "0s" if test runs fast)
	if response.Uptime == "" {
		t.Error("uptime should not be empty")
	}

	// Parse uptime to ensure it's a valid duration
	_, err := time.ParseDuration(response.Uptime)
	if err != nil {
		t.Errorf("uptime %q is not a valid duration: %v", response.Uptime, err)
	}
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

	if response.Status != "healthy" {
		t.Errorf("Status = %s, want healthy", response.Status)
	}
	if len(response.Checks) != 2 {
		t.Errorf("Checks length = %d, want 2", len(response.Checks))
	}
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

	if response.Uptime != 3600 {
		t.Errorf("Uptime = %d, want 3600", response.Uptime)
	}
	if response.Custom["custom_metric"] != 42 {
		t.Errorf("Custom[custom_metric] = %d, want 42", response.Custom["custom_metric"])
	}
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
