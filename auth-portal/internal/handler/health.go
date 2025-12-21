package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/nginx"
)

// HealthHandler handles health check endpoints
type HealthHandler struct {
	config       *config.Config
	nginxManager *nginx.Manager
	startTime    time.Time
	mu           sync.RWMutex
	ready        bool
}

// NewHealthHandler creates a new health handler
func NewHealthHandler(cfg *config.Config, nginxMgr *nginx.Manager) *HealthHandler {
	return &HealthHandler{
		config:       cfg,
		nginxManager: nginxMgr,
		startTime:    time.Now(),
		ready:        false,
	}
}

// SetReady marks the service as ready
func (h *HealthHandler) SetReady(ready bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ready = ready
}

// IsReady returns the ready status
func (h *HealthHandler) IsReady() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.ready
}

// HealthResponse represents a health check response
type HealthResponse struct {
	Status    string            `json:"status"`
	Timestamp string            `json:"timestamp"`
	Uptime    string            `json:"uptime"`
	Version   string            `json:"version,omitempty"`
	Checks    map[string]string `json:"checks,omitempty"`
}

// HandleHealth handles the /health endpoint (liveness probe)
func (h *HealthHandler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	response := HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Uptime:    time.Since(h.startTime).Round(time.Second).String(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// HandleReady handles the /ready endpoint (readiness probe)
func (h *HealthHandler) HandleReady(w http.ResponseWriter, r *http.Request) {
	checks := make(map[string]string)
	allHealthy := true

	// Check if service is marked as ready
	if !h.IsReady() {
		checks["startup"] = "not ready"
		allHealthy = false
	} else {
		checks["startup"] = "ok"
	}

	// Check nginx if manager is configured
	if h.nginxManager != nil {
		if h.nginxManager.IsRunning() {
			if err := h.nginxManager.HealthCheck(); err != nil {
				checks["nginx"] = err.Error()
				allHealthy = false
			} else {
				checks["nginx"] = "ok"
			}
		} else {
			checks["nginx"] = "not running"
			allHealthy = false
		}
	}

	response := HealthResponse{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Uptime:    time.Since(h.startTime).Round(time.Second).String(),
		Checks:    checks,
	}

	if allHealthy {
		response.Status = "ready"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	} else {
		response.Status = "not ready"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	json.NewEncoder(w).Encode(response)
}

// MetricsResponse represents metrics data
type MetricsResponse struct {
	Uptime       int64            `json:"uptime_seconds"`
	GoRoutines   int              `json:"goroutines"`
	MemoryAlloc  uint64           `json:"memory_alloc_bytes"`
	MemorySys    uint64           `json:"memory_sys_bytes"`
	NumGC        uint32           `json:"num_gc"`
	SessionStore string           `json:"session_store"`
	Mode         string           `json:"mode"`
	Services     int              `json:"services_count"`
	Custom       map[string]int64 `json:"custom,omitempty"`
}

// HandleMetrics handles the /metrics endpoint
// Returns metrics in JSON format (for Prometheus, use a proper exporter)
func (h *HealthHandler) HandleMetrics(w http.ResponseWriter, r *http.Request) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	response := MetricsResponse{
		Uptime:       int64(time.Since(h.startTime).Seconds()),
		GoRoutines:   runtime.NumGoroutine(),
		MemoryAlloc:  memStats.Alloc,
		MemorySys:    memStats.Sys,
		NumGC:        memStats.NumGC,
		SessionStore: h.config.Session.Store,
		Mode:         h.config.Mode,
		Services:     len(h.config.Services),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandlePrometheusMetrics handles /metrics in Prometheus format
func (h *HealthHandler) HandlePrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")

	// Basic metrics in Prometheus format
	fmt.Fprintf(w, "# HELP auth_portal_uptime_seconds Time since service start\n")
	fmt.Fprintf(w, "# TYPE auth_portal_uptime_seconds counter\n")
	fmt.Fprintf(w, "auth_portal_uptime_seconds %d\n", int64(time.Since(h.startTime).Seconds()))

	fmt.Fprintf(w, "# HELP auth_portal_goroutines Number of goroutines\n")
	fmt.Fprintf(w, "# TYPE auth_portal_goroutines gauge\n")
	fmt.Fprintf(w, "auth_portal_goroutines %d\n", runtime.NumGoroutine())

	fmt.Fprintf(w, "# HELP auth_portal_memory_alloc_bytes Allocated memory in bytes\n")
	fmt.Fprintf(w, "# TYPE auth_portal_memory_alloc_bytes gauge\n")
	fmt.Fprintf(w, "auth_portal_memory_alloc_bytes %d\n", memStats.Alloc)

	fmt.Fprintf(w, "# HELP auth_portal_memory_sys_bytes System memory in bytes\n")
	fmt.Fprintf(w, "# TYPE auth_portal_memory_sys_bytes gauge\n")
	fmt.Fprintf(w, "auth_portal_memory_sys_bytes %d\n", memStats.Sys)

	fmt.Fprintf(w, "# HELP auth_portal_gc_runs_total Total number of GC runs\n")
	fmt.Fprintf(w, "# TYPE auth_portal_gc_runs_total counter\n")
	fmt.Fprintf(w, "auth_portal_gc_runs_total %d\n", memStats.NumGC)

	fmt.Fprintf(w, "# HELP auth_portal_services_count Number of configured services\n")
	fmt.Fprintf(w, "# TYPE auth_portal_services_count gauge\n")
	fmt.Fprintf(w, "auth_portal_services_count %d\n", len(h.config.Services))

	// Ready status
	ready := 0
	if h.IsReady() {
		ready = 1
	}
	fmt.Fprintf(w, "# HELP auth_portal_ready Service readiness status\n")
	fmt.Fprintf(w, "# TYPE auth_portal_ready gauge\n")
	fmt.Fprintf(w, "auth_portal_ready %d\n", ready)

	// Nginx status
	if h.nginxManager != nil {
		nginxRunning := 0
		if h.nginxManager.IsRunning() {
			nginxRunning = 1
		}
		fmt.Fprintf(w, "# HELP auth_portal_nginx_running Nginx running status\n")
		fmt.Fprintf(w, "# TYPE auth_portal_nginx_running gauge\n")
		fmt.Fprintf(w, "auth_portal_nginx_running %d\n", nginxRunning)
	}
}

