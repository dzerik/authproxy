package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/pkg/logger"
)

// BuildInfo contains build-time information.
type BuildInfo struct {
	Version   string
	BuildTime string
	GitCommit string
}

// ServiceHealth represents health status of a service component.
type ServiceHealth struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // healthy, unhealthy, degraded
	Message string `json:"message,omitempty"`
}

// ListenerInfo represents information about an active listener.
type ListenerInfo struct {
	Name    string `json:"name"`
	Type    string `json:"type"` // http, grpc, proxy, egress
	Address string `json:"address"`
	Status  string `json:"status"` // running, stopped, draining
}

// AppInfo interface for accessing application status.
type AppInfo interface {
	GetServices() []ServiceHealth
	GetListeners() []ListenerInfo
	IsHealthy() bool
	IsReady() bool
}

// ManagementServer manages Istio-style admin endpoints on separate ports.
type ManagementServer struct {
	adminServer  *http.Server // :15000 - config_dump, stats, logging
	healthServer *http.Server // :15020 - aggregated health, metrics, pprof
	readyServer  *http.Server // :15021 - lightweight readiness probe

	cfg             config.ManagementServerConfig
	loader          *config.Loader
	app             AppInfo
	listenerManager *ListenerManager
	cacheService    CacheService
	log             logger.Logger
	buildInfo       BuildInfo

	// Runtime state
	draining     atomic.Bool
	forceHealthy atomic.Bool
	startTime    time.Time
	shutdownCh   chan struct{}
}

// NewManagementServer creates a new management server with all admin endpoints.
func NewManagementServer(
	cfg config.ManagementServerConfig,
	loader *config.Loader,
	app AppInfo,
	buildInfo BuildInfo,
) *ManagementServer {
	m := &ManagementServer{
		cfg:        cfg,
		loader:     loader,
		app:        app,
		buildInfo:  buildInfo,
		startTime:  time.Now(),
		shutdownCh: make(chan struct{}),
	}

	// Default to healthy
	m.forceHealthy.Store(true)

	// Setup all servers
	m.setupAdminServer()
	m.setupHealthServer()
	m.setupReadyServer()

	return m
}

// SetListenerManager sets the listener manager for dynamic listener management.
func (m *ManagementServer) SetListenerManager(lm *ListenerManager) {
	m.listenerManager = lm
}

// SetCacheService sets the cache service for cache management endpoints.
func (m *ManagementServer) SetCacheService(cs CacheService) {
	m.cacheService = cs
}

// setupAdminServer configures the admin server on :15000.
func (m *ManagementServer) setupAdminServer() {
	r := chi.NewRouter()

	// Minimal middleware for admin
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)

	// Admin endpoints
	r.Get("/", m.handleRoot)
	r.Get("/help", m.handleHelp)
	r.Get("/server_info", m.handleServerInfo)
	r.Get("/config_dump", m.handleConfigDump)
	r.Get("/listeners", m.handleListeners)
	r.Get("/clusters", m.handleClusters)
	r.Get("/stats", m.handleStats)
	r.Get("/stats/prometheus", m.handleStatsPrometheus)
	r.Get("/logging", m.handleLoggingGet)
	r.Post("/logging", m.handleLoggingPost)
	r.Get("/runtime", m.handleRuntime)
	r.Post("/healthcheck/fail", m.handleHealthFail)
	r.Post("/healthcheck/ok", m.handleHealthOk)
	r.Post("/drain", m.handleDrain)
	r.Post("/quitquitquit", m.handleQuit)

	// Cache management
	r.Post("/cache/invalidate", m.handleCacheInvalidate)
	r.Get("/cache/stats", m.handleCacheStats)

	// Schema endpoints
	r.Get("/schema", m.handleSchemaList)
	r.Get("/schema/environment", m.handleSchemaEnvironment)
	r.Get("/schema/services", m.handleSchemaServices)
	r.Get("/schema/rules", m.handleSchemaRules)

	m.adminServer = &http.Server{
		Addr:         m.cfg.AdminAddr,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// setupHealthServer configures the health/metrics server on :15020.
func (m *ManagementServer) setupHealthServer() {
	r := chi.NewRouter()

	// Minimal middleware
	r.Use(middleware.Recoverer)

	// Health endpoints
	r.Get("/healthz/ready", m.handleReady)
	r.Get("/stats/prometheus", m.handleStatsPrometheus)

	// App health per component
	r.Get("/app-health/{component}/livez", m.handleComponentLive)
	r.Get("/app-health/{component}/readyz", m.handleComponentReady)

	// Debug endpoints (pprof)
	r.HandleFunc("/debug/pprof/", m.handlePprofIndex)
	r.HandleFunc("/debug/pprof/cmdline", m.handlePprofCmdline)
	r.HandleFunc("/debug/pprof/profile", m.handlePprofProfile)
	r.HandleFunc("/debug/pprof/symbol", m.handlePprofSymbol)
	r.HandleFunc("/debug/pprof/trace", m.handlePprofTrace)
	r.HandleFunc("/debug/pprof/heap", m.handlePprofHeap)
	r.HandleFunc("/debug/pprof/goroutine", m.handlePprofGoroutine)
	r.HandleFunc("/debug/pprof/allocs", m.handlePprofAllocs)
	r.HandleFunc("/debug/pprof/block", m.handlePprofBlock)
	r.HandleFunc("/debug/pprof/mutex", m.handlePprofMutex)
	r.HandleFunc("/debug/pprof/threadcreate", m.handlePprofThreadcreate)

	m.healthServer = &http.Server{
		Addr:         m.cfg.HealthAddr,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 60 * time.Second, // Longer for pprof
		IdleTimeout:  120 * time.Second,
	}
}

// setupReadyServer configures the lightweight readiness server on :15021.
func (m *ManagementServer) setupReadyServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz/ready", m.handleLightweightReady)

	m.readyServer = &http.Server{
		Addr:         m.cfg.ReadyAddr,
		Handler:      mux,
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
		IdleTimeout:  5 * time.Second,
	}
}

// Start starts all management servers.
func (m *ManagementServer) Start() error {
	errCh := make(chan error, 3)

	// Start admin server
	go func() {
		logger.Info("starting admin server",
			logger.String("addr", m.cfg.AdminAddr),
		)
		if err := m.adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("admin server error: %w", err)
		}
	}()

	// Start health server
	go func() {
		logger.Info("starting health server",
			logger.String("addr", m.cfg.HealthAddr),
		)
		if err := m.healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("health server error: %w", err)
		}
	}()

	// Start ready server
	go func() {
		logger.Info("starting readiness server",
			logger.String("addr", m.cfg.ReadyAddr),
		)
		if err := m.readyServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("ready server error: %w", err)
		}
	}()

	// Wait for error or shutdown
	select {
	case err := <-errCh:
		return err
	case <-m.shutdownCh:
		return nil
	}
}

// Shutdown gracefully shuts down all management servers.
func (m *ManagementServer) Shutdown(ctx context.Context) error {
	close(m.shutdownCh)

	var errs []error

	// Shutdown admin server
	if err := m.adminServer.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("admin server shutdown: %w", err))
	}

	// Shutdown health server
	if err := m.healthServer.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("health server shutdown: %w", err))
	}

	// Shutdown ready server
	if err := m.readyServer.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("ready server shutdown: %w", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("management server shutdown errors: %v", errs)
	}

	logger.Info("management servers stopped")
	return nil
}

// IsDraining returns true if the server is in drain mode.
func (m *ManagementServer) IsDraining() bool {
	return m.draining.Load()
}

// writeJSON writes a JSON response.
func (m *ManagementServer) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		logger.Error("failed to encode JSON response", logger.Err(err))
	}
}

// writeText writes a plain text response.
func (m *ManagementServer) writeText(w http.ResponseWriter, status int, text string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	w.Write([]byte(text))
}

// GetStartTime returns server start time.
func (m *ManagementServer) GetStartTime() time.Time {
	return m.startTime
}

// GetUptime returns server uptime duration.
func (m *ManagementServer) GetUptime() time.Duration {
	return time.Since(m.startTime)
}

// GetGoVersion returns Go runtime version.
func (m *ManagementServer) GetGoVersion() string {
	return runtime.Version()
}
