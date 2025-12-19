package http

import (
	"net/http"
	"net/http/pprof"
	"time"

	"github.com/go-chi/chi/v5"
)

// handleReady handles GET /healthz/ready on :15020.
// Uses HealthResponse and CheckResult types from dto.go.
func (m *ManagementServer) handleReady(w http.ResponseWriter, r *http.Request) {
	// Check if draining
	if m.draining.Load() {
		m.writeJSON(w, http.StatusServiceUnavailable, HealthResponse{
			Status:    "not_ready",
			Timestamp: time.Now(),
			Checks: map[string]CheckResult{
				"draining": {Status: "unhealthy", Message: "server is draining"},
			},
		})
		return
	}

	// Check if forced unhealthy
	if !m.forceHealthy.Load() {
		m.writeJSON(w, http.StatusServiceUnavailable, HealthResponse{
			Status:    "not_ready",
			Timestamp: time.Now(),
			Checks: map[string]CheckResult{
				"forced": {Status: "unhealthy", Message: "health check forced to fail"},
			},
		})
		return
	}

	// Check app readiness
	if m.app != nil && !m.app.IsReady() {
		services := m.app.GetServices()
		checks := make(map[string]CheckResult)
		for _, svc := range services {
			checks[svc.Name] = CheckResult{
				Status:  svc.Status,
				Message: svc.Message,
			}
		}

		m.writeJSON(w, http.StatusServiceUnavailable, HealthResponse{
			Status:    "not_ready",
			Checks:    checks,
			Timestamp: time.Now(),
		})
		return
	}

	// All checks passed
	m.writeJSON(w, http.StatusOK, HealthResponse{
		Status:    "ready",
		Timestamp: time.Now(),
	})
}

// handleLightweightReady handles GET /healthz/ready on :15021.
// This is a lightweight version for kubelet probes.
func (m *ManagementServer) handleLightweightReady(w http.ResponseWriter, r *http.Request) {
	// Quick checks only
	if m.draining.Load() || !m.forceHealthy.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("NOT READY"))
		return
	}

	if m.app != nil && !m.app.IsReady() {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("NOT READY"))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// handleComponentLive handles GET /app-health/{component}/livez.
func (m *ManagementServer) handleComponentLive(w http.ResponseWriter, r *http.Request) {
	component := chi.URLParam(r, "component")

	if m.app != nil {
		services := m.app.GetServices()
		for _, svc := range services {
			if svc.Name == component {
				if svc.Status == "healthy" {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("OK"))
					return
				}
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte(svc.Message))
				return
			}
		}
	}

	// Component not found - assume alive
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// handleComponentReady handles GET /app-health/{component}/readyz.
func (m *ManagementServer) handleComponentReady(w http.ResponseWriter, r *http.Request) {
	component := chi.URLParam(r, "component")

	if m.draining.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("DRAINING"))
		return
	}

	if m.app != nil {
		services := m.app.GetServices()
		for _, svc := range services {
			if svc.Name == component {
				if svc.Status == "healthy" {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("OK"))
					return
				}
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte(svc.Message))
				return
			}
		}
	}

	// Component not found - assume ready
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// Pprof handlers - wrappers around net/http/pprof

// handlePprofIndex handles GET /debug/pprof/.
func (m *ManagementServer) handlePprofIndex(w http.ResponseWriter, r *http.Request) {
	pprof.Index(w, r)
}

// handlePprofCmdline handles GET /debug/pprof/cmdline.
func (m *ManagementServer) handlePprofCmdline(w http.ResponseWriter, r *http.Request) {
	pprof.Cmdline(w, r)
}

// handlePprofProfile handles GET /debug/pprof/profile.
func (m *ManagementServer) handlePprofProfile(w http.ResponseWriter, r *http.Request) {
	pprof.Profile(w, r)
}

// handlePprofSymbol handles GET /debug/pprof/symbol.
func (m *ManagementServer) handlePprofSymbol(w http.ResponseWriter, r *http.Request) {
	pprof.Symbol(w, r)
}

// handlePprofTrace handles GET /debug/pprof/trace.
func (m *ManagementServer) handlePprofTrace(w http.ResponseWriter, r *http.Request) {
	pprof.Trace(w, r)
}

// handlePprofHeap handles GET /debug/pprof/heap.
func (m *ManagementServer) handlePprofHeap(w http.ResponseWriter, r *http.Request) {
	pprof.Handler("heap").ServeHTTP(w, r)
}

// handlePprofGoroutine handles GET /debug/pprof/goroutine.
func (m *ManagementServer) handlePprofGoroutine(w http.ResponseWriter, r *http.Request) {
	pprof.Handler("goroutine").ServeHTTP(w, r)
}

// handlePprofAllocs handles GET /debug/pprof/allocs.
func (m *ManagementServer) handlePprofAllocs(w http.ResponseWriter, r *http.Request) {
	pprof.Handler("allocs").ServeHTTP(w, r)
}

// handlePprofBlock handles GET /debug/pprof/block.
func (m *ManagementServer) handlePprofBlock(w http.ResponseWriter, r *http.Request) {
	pprof.Handler("block").ServeHTTP(w, r)
}

// handlePprofMutex handles GET /debug/pprof/mutex.
func (m *ManagementServer) handlePprofMutex(w http.ResponseWriter, r *http.Request) {
	pprof.Handler("mutex").ServeHTTP(w, r)
}

// handlePprofThreadcreate handles GET /debug/pprof/threadcreate.
func (m *ManagementServer) handlePprofThreadcreate(w http.ResponseWriter, r *http.Request) {
	pprof.Handler("threadcreate").ServeHTTP(w, r)
}
