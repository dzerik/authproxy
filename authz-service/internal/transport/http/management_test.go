package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/pkg/logger"
)

func init() {
	// Initialize logger for tests
	_ = logger.Init(logger.DefaultConfig())
}

// =============================================================================
// Mock AppInfo
// =============================================================================

type mockAppInfo struct {
	services  []ServiceHealth
	listeners []ListenerInfo
	healthy   bool
	ready     bool
}

func (m *mockAppInfo) GetServices() []ServiceHealth {
	if m.services != nil {
		return m.services
	}
	return []ServiceHealth{}
}

func (m *mockAppInfo) GetListeners() []ListenerInfo {
	if m.listeners != nil {
		return m.listeners
	}
	return []ListenerInfo{}
}

func (m *mockAppInfo) IsHealthy() bool {
	return m.healthy
}

func (m *mockAppInfo) IsReady() bool {
	return m.ready
}

// =============================================================================
// ManagementServer Tests
// =============================================================================

func TestNewManagementServer(t *testing.T) {
	cfg := config.ManagementServerConfig{
		Enabled:    true,
		AdminAddr:  ":15000",
		HealthAddr: ":15020",
		ReadyAddr:  ":15021",
	}

	app := &mockAppInfo{healthy: true, ready: true}
	buildInfo := BuildInfo{
		Version:   "1.0.0",
		BuildTime: "2025-01-01",
		GitCommit: "abc123",
	}

	m := NewManagementServer(cfg, nil, app, buildInfo)

	require.NotNil(t, m)
	assert.Equal(t, "1.0.0", m.buildInfo.Version)
	assert.True(t, m.forceHealthy.Load())
	assert.False(t, m.draining.Load())
}

func TestManagementServer_GetUptime(t *testing.T) {
	cfg := config.ManagementServerConfig{
		Enabled:    true,
		AdminAddr:  ":15000",
		HealthAddr: ":15020",
		ReadyAddr:  ":15021",
	}

	m := NewManagementServer(cfg, nil, nil, BuildInfo{})

	// Wait a bit
	time.Sleep(10 * time.Millisecond)

	uptime := m.GetUptime()
	assert.True(t, uptime >= 10*time.Millisecond)
}

// =============================================================================
// Admin Handler Tests
// =============================================================================

func TestManagementServer_handleServerInfo(t *testing.T) {
	cfg := config.ManagementServerConfig{
		Enabled:    true,
		AdminAddr:  ":15000",
		HealthAddr: ":15020",
		ReadyAddr:  ":15021",
	}

	buildInfo := BuildInfo{
		Version:   "1.2.3",
		BuildTime: "2025-01-01T00:00:00Z",
		GitCommit: "abc123def",
	}

	m := NewManagementServer(cfg, nil, nil, buildInfo)

	req := httptest.NewRequest(http.MethodGet, "/server_info", nil)
	w := httptest.NewRecorder()

	m.handleServerInfo(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ServerInfoResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "1.2.3", resp.Version)
	assert.Equal(t, "abc123def", resp.GitCommit)
}

func TestManagementServer_handleHelp(t *testing.T) {
	cfg := config.ManagementServerConfig{
		Enabled:    true,
		AdminAddr:  ":15000",
		HealthAddr: ":15020",
		ReadyAddr:  ":15021",
	}

	m := NewManagementServer(cfg, nil, nil, BuildInfo{})

	req := httptest.NewRequest(http.MethodGet, "/help", nil)
	w := httptest.NewRecorder()

	m.handleHelp(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "/server_info")
	assert.Contains(t, w.Body.String(), "/config_dump")
	assert.Contains(t, w.Body.String(), "/logging")
}

func TestManagementServer_handleConfigDump_NoLoader(t *testing.T) {
	cfg := config.ManagementServerConfig{
		Enabled:    true,
		AdminAddr:  ":15000",
		HealthAddr: ":15020",
		ReadyAddr:  ":15021",
	}

	m := NewManagementServer(cfg, nil, nil, BuildInfo{})

	req := httptest.NewRequest(http.MethodGet, "/config_dump", nil)
	w := httptest.NewRecorder()

	m.handleConfigDump(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ConfigDumpResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	// All configs should be nil when loader is nil
	assert.Nil(t, resp.Configs.Environment)
	assert.Nil(t, resp.Configs.Services)
	assert.Nil(t, resp.Configs.Rules)
}

func TestManagementServer_handleListeners(t *testing.T) {
	cfg := config.ManagementServerConfig{
		Enabled:    true,
		AdminAddr:  ":15000",
		HealthAddr: ":15020",
		ReadyAddr:  ":15021",
	}

	app := &mockAppInfo{
		listeners: []ListenerInfo{
			{Name: "http", Type: "http", Address: ":8080", Status: "running"},
			{Name: "admin", Type: "management", Address: ":15000", Status: "running"},
		},
	}

	m := NewManagementServer(cfg, nil, app, BuildInfo{})

	req := httptest.NewRequest(http.MethodGet, "/listeners", nil)
	w := httptest.NewRecorder()

	m.handleListeners(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ListenersResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, 2, resp.Total)
	assert.Len(t, resp.Listeners, 2)
}

func TestManagementServer_handleLogging(t *testing.T) {
	cfg := config.ManagementServerConfig{
		Enabled:    true,
		AdminAddr:  ":15000",
		HealthAddr: ":15020",
		ReadyAddr:  ":15021",
	}

	m := NewManagementServer(cfg, nil, nil, BuildInfo{})

	t.Run("GET current level", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/logging", nil)
		w := httptest.NewRecorder()

		m.handleLoggingGet(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp LoggingResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.Level)
	})

	t.Run("POST change level", func(t *testing.T) {
		body := strings.NewReader(`{"level": "debug"}`)
		req := httptest.NewRequest(http.MethodPost, "/logging", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		m.handleLoggingPost(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp LoggingResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "debug", resp.Level)
	})

	t.Run("POST invalid level", func(t *testing.T) {
		body := strings.NewReader(`{"level": "invalid"}`)
		req := httptest.NewRequest(http.MethodPost, "/logging", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		m.handleLoggingPost(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestManagementServer_handleHealthControls(t *testing.T) {
	cfg := config.ManagementServerConfig{
		Enabled:    true,
		AdminAddr:  ":15000",
		HealthAddr: ":15020",
		ReadyAddr:  ":15021",
	}

	m := NewManagementServer(cfg, nil, nil, BuildInfo{})

	t.Run("healthcheck/fail", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/healthcheck/fail", nil)
		w := httptest.NewRecorder()

		m.handleHealthFail(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.False(t, m.forceHealthy.Load())
	})

	t.Run("healthcheck/ok", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/healthcheck/ok", nil)
		w := httptest.NewRecorder()

		m.handleHealthOk(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.True(t, m.forceHealthy.Load())
	})

	t.Run("drain", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/drain", nil)
		w := httptest.NewRecorder()

		m.handleDrain(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.True(t, m.draining.Load())
	})
}

// =============================================================================
// Health Handler Tests
// =============================================================================

func TestManagementServer_handleReady(t *testing.T) {
	cfg := config.ManagementServerConfig{
		Enabled:    true,
		AdminAddr:  ":15000",
		HealthAddr: ":15020",
		ReadyAddr:  ":15021",
	}

	t.Run("healthy and ready", func(t *testing.T) {
		app := &mockAppInfo{healthy: true, ready: true}
		m := NewManagementServer(cfg, nil, app, BuildInfo{})

		req := httptest.NewRequest(http.MethodGet, "/healthz/ready", nil)
		w := httptest.NewRecorder()

		m.handleReady(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp HealthResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "ready", resp.Status)
	})

	t.Run("draining", func(t *testing.T) {
		app := &mockAppInfo{healthy: true, ready: true}
		m := NewManagementServer(cfg, nil, app, BuildInfo{})
		m.draining.Store(true)

		req := httptest.NewRequest(http.MethodGet, "/healthz/ready", nil)
		w := httptest.NewRecorder()

		m.handleReady(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)

		var resp HealthResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "not_ready", resp.Status)
	})

	t.Run("forced unhealthy", func(t *testing.T) {
		app := &mockAppInfo{healthy: true, ready: true}
		m := NewManagementServer(cfg, nil, app, BuildInfo{})
		m.forceHealthy.Store(false)

		req := httptest.NewRequest(http.MethodGet, "/healthz/ready", nil)
		w := httptest.NewRecorder()

		m.handleReady(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("app not ready", func(t *testing.T) {
		app := &mockAppInfo{
			healthy: true,
			ready:   false,
			services: []ServiceHealth{
				{Name: "policy", Status: "unhealthy", Message: "not ready"},
			},
		}
		m := NewManagementServer(cfg, nil, app, BuildInfo{})

		req := httptest.NewRequest(http.MethodGet, "/healthz/ready", nil)
		w := httptest.NewRecorder()

		m.handleReady(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)

		var resp HealthResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "not_ready", resp.Status)
		assert.Contains(t, resp.Checks, "policy")
	})
}

func TestManagementServer_handleLightweightReady(t *testing.T) {
	cfg := config.ManagementServerConfig{
		Enabled:    true,
		AdminAddr:  ":15000",
		HealthAddr: ":15020",
		ReadyAddr:  ":15021",
	}

	t.Run("ready", func(t *testing.T) {
		app := &mockAppInfo{ready: true}
		m := NewManagementServer(cfg, nil, app, BuildInfo{})

		req := httptest.NewRequest(http.MethodGet, "/healthz/ready", nil)
		w := httptest.NewRecorder()

		m.handleLightweightReady(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "OK", w.Body.String())
	})

	t.Run("not ready", func(t *testing.T) {
		app := &mockAppInfo{ready: false}
		m := NewManagementServer(cfg, nil, app, BuildInfo{})

		req := httptest.NewRequest(http.MethodGet, "/healthz/ready", nil)
		w := httptest.NewRecorder()

		m.handleLightweightReady(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.Equal(t, "NOT READY", w.Body.String())
	})
}

func TestManagementServer_handleComponentLive(t *testing.T) {
	cfg := config.ManagementServerConfig{
		Enabled:    true,
		AdminAddr:  ":15000",
		HealthAddr: ":15020",
		ReadyAddr:  ":15021",
	}

	app := &mockAppInfo{
		services: []ServiceHealth{
			{Name: "policy", Status: "healthy"},
			{Name: "cache", Status: "unhealthy", Message: "connection lost"},
		},
	}
	m := NewManagementServer(cfg, nil, app, BuildInfo{})

	t.Run("healthy component", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/app-health/policy/livez", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("component", "policy")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		w := httptest.NewRecorder()

		m.handleComponentLive(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "OK", w.Body.String())
	})

	t.Run("unhealthy component", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/app-health/cache/livez", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("component", "cache")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		w := httptest.NewRecorder()

		m.handleComponentLive(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.Equal(t, "connection lost", w.Body.String())
	})

	t.Run("unknown component", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/app-health/unknown/livez", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("component", "unknown")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		w := httptest.NewRecorder()

		m.handleComponentLive(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "OK", w.Body.String())
	})
}

func TestManagementServer_handleStats(t *testing.T) {
	cfg := config.ManagementServerConfig{
		Enabled:    true,
		AdminAddr:  ":15000",
		HealthAddr: ":15020",
		ReadyAddr:  ":15021",
	}

	m := NewManagementServer(cfg, nil, nil, BuildInfo{})

	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	w := httptest.NewRecorder()

	m.handleStats(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp StatsResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp.Stats, "uptime_seconds")
	assert.Contains(t, resp.Stats, "go_goroutines")
	assert.Contains(t, resp.Stats, "memory")
}

func TestManagementServer_handleStatsPrometheus(t *testing.T) {
	cfg := config.ManagementServerConfig{
		Enabled:    true,
		AdminAddr:  ":15000",
		HealthAddr: ":15020",
		ReadyAddr:  ":15021",
	}

	m := NewManagementServer(cfg, nil, nil, BuildInfo{})

	req := httptest.NewRequest(http.MethodGet, "/stats/prometheus", nil)
	w := httptest.NewRecorder()

	m.handleStatsPrometheus(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// Prometheus format uses text/plain with version
	assert.Contains(t, w.Header().Get("Content-Type"), "text/plain")

	body := w.Body.String()
	assert.Contains(t, body, "authz_uptime_seconds")
	assert.Contains(t, body, "authz_draining")
	assert.Contains(t, body, "authz_healthy")
}
