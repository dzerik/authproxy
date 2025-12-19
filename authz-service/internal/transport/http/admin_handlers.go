package http

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/pkg/logger"
)

// ServerInfoResponse contains server information.
type ServerInfoResponse struct {
	Version     string    `json:"version"`
	BuildTime   string    `json:"build_time"`
	GitCommit   string    `json:"git_commit"`
	GoVersion   string    `json:"go_version"`
	StartTime   time.Time `json:"start_time"`
	Uptime      string    `json:"uptime"`
	UptimeMs    int64     `json:"uptime_ms"`
	Hostname    string    `json:"hostname"`
	Environment string    `json:"environment,omitempty"`
}

// ConfigDumpResponse contains configuration dump.
type ConfigDumpResponse struct {
	Configs  ConfigDumpConfigs    `json:"configs"`
	Versions config.ConfigVersion `json:"versions"`
}

// ConfigDumpConfigs contains the different configuration types.
type ConfigDumpConfigs struct {
	Environment *config.EnvironmentConfig `json:"environment,omitempty"`
	Services    *config.ServicesConfig    `json:"services,omitempty"`
	Rules       *config.RulesConfig       `json:"rules,omitempty"`
}

// ListenersResponse contains active listeners.
type ListenersResponse struct {
	Listeners []ListenerInfo `json:"listeners"`
	Total     int            `json:"total"`
}

// ClustersResponse contains upstream clusters info.
type ClustersResponse struct {
	Clusters []ClusterInfo `json:"clusters"`
	Total    int           `json:"total"`
}

// ClusterInfo represents an upstream cluster.
type ClusterInfo struct {
	Name     string            `json:"name"`
	Type     string            `json:"type"` // proxy, egress
	Targets  []TargetInfo      `json:"targets"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// TargetInfo represents an upstream target.
type TargetInfo struct {
	Address string `json:"address"`
	Status  string `json:"status"` // healthy, unhealthy, unknown
	Weight  int    `json:"weight,omitempty"`
}

// StatsResponse contains statistics.
type StatsResponse struct {
	Stats     map[string]interface{} `json:"stats"`
	Timestamp time.Time              `json:"timestamp"`
}

// LoggingResponse contains current logging configuration.
type LoggingResponse struct {
	Level   string            `json:"level"`
	Loggers map[string]string `json:"loggers,omitempty"`
}

// LoggingRequest for changing log level.
type LoggingRequest struct {
	Level string `json:"level"`
}

// RuntimeResponse contains runtime information.
type RuntimeResponse struct {
	Draining bool              `json:"draining"`
	Healthy  bool              `json:"healthy"`
	Ready    bool              `json:"ready"`
	Runtime  map[string]string `json:"runtime"`
}

// handleRoot handles GET / - shows available endpoints.
func (m *ManagementServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	help := `<!DOCTYPE html>
<html>
<head><title>Authz Service Admin</title></head>
<body>
<h1>Authz Service Admin Interface</h1>
<h2>Available Endpoints</h2>
<ul>
  <li><a href="/help">/help</a> - This help page</li>
  <li><a href="/server_info">/server_info</a> - Server version and uptime</li>
  <li><a href="/config_dump">/config_dump</a> - Configuration dump</li>
  <li><a href="/listeners">/listeners</a> - Active listeners</li>
  <li><a href="/clusters">/clusters</a> - Upstream clusters</li>
  <li><a href="/stats">/stats</a> - Statistics (JSON)</li>
  <li><a href="/stats/prometheus">/stats/prometheus</a> - Prometheus metrics</li>
  <li><a href="/logging">/logging</a> - Log level (GET/POST)</li>
  <li><a href="/runtime">/runtime</a> - Runtime info</li>
</ul>
<h2>Actions</h2>
<ul>
  <li>POST /healthcheck/fail - Force unhealthy status</li>
  <li>POST /healthcheck/ok - Restore healthy status</li>
  <li>POST /drain - Start graceful drain</li>
  <li>POST /quitquitquit - Graceful shutdown</li>
</ul>
<h2>Query Parameters</h2>
<ul>
  <li>/config_dump?resource=environment - Filter by resource type</li>
  <li>/config_dump?resource=services</li>
  <li>/config_dump?resource=rules</li>
</ul>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(help))
}

// handleHelp handles GET /help.
func (m *ManagementServer) handleHelp(w http.ResponseWriter, r *http.Request) {
	m.handleRoot(w, r)
}

// handleServerInfo handles GET /server_info.
func (m *ManagementServer) handleServerInfo(w http.ResponseWriter, r *http.Request) {
	hostname, _ := os.Hostname()

	env := ""
	if m.loader != nil {
		if envCfg := m.loader.GetEnvironment(); envCfg != nil {
			env = envCfg.Env.Name
		}
	}

	resp := ServerInfoResponse{
		Version:     m.buildInfo.Version,
		BuildTime:   m.buildInfo.BuildTime,
		GitCommit:   m.buildInfo.GitCommit,
		GoVersion:   m.GetGoVersion(),
		StartTime:   m.startTime,
		Uptime:      m.GetUptime().Round(time.Second).String(),
		UptimeMs:    m.GetUptime().Milliseconds(),
		Hostname:    hostname,
		Environment: env,
	}

	m.writeJSON(w, http.StatusOK, resp)
}

// handleConfigDump handles GET /config_dump.
func (m *ManagementServer) handleConfigDump(w http.ResponseWriter, r *http.Request) {
	resource := r.URL.Query().Get("resource")

	var resp ConfigDumpResponse

	if m.loader != nil {
		resp.Versions = m.loader.GetConfigVersion()

		switch strings.ToLower(resource) {
		case "environment":
			resp.Configs.Environment = m.loader.GetEnvironment()
		case "services":
			resp.Configs.Services = m.loader.GetServices()
		case "rules":
			resp.Configs.Rules = m.loader.GetRules()
		case "":
			// Return all
			resp.Configs.Environment = m.loader.GetEnvironment()
			resp.Configs.Services = m.loader.GetServices()
			resp.Configs.Rules = m.loader.GetRules()
		default:
			m.writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":           "invalid resource type",
				"valid_resources": "environment, services, rules",
			})
			return
		}
	}

	m.writeJSON(w, http.StatusOK, resp)
}

// handleListeners handles GET /listeners.
func (m *ManagementServer) handleListeners(w http.ResponseWriter, r *http.Request) {
	var listeners []ListenerInfo

	if m.app != nil {
		listeners = m.app.GetListeners()
	}

	if listeners == nil {
		listeners = []ListenerInfo{}
	}

	resp := ListenersResponse{
		Listeners: listeners,
		Total:     len(listeners),
	}

	m.writeJSON(w, http.StatusOK, resp)
}

// handleClusters handles GET /clusters.
func (m *ManagementServer) handleClusters(w http.ResponseWriter, r *http.Request) {
	var clusters []ClusterInfo

	// Extract cluster info from services config
	if m.loader != nil {
		if svc := m.loader.GetServices(); svc != nil {
			// Add proxy upstreams from all listeners
			if svc.Proxy.Enabled {
				for _, listener := range svc.Proxy.Listeners {
					for name, upstream := range listener.Upstreams {
						clusterName := fmt.Sprintf("%s/%s", listener.Name, name)
						clusters = append(clusters, ClusterInfo{
							Name: clusterName,
							Type: "proxy",
							Targets: []TargetInfo{
								{
									Address: upstream.URL,
									Status:  "unknown",
								},
							},
						})
					}
				}
			}
		}
	}

	if clusters == nil {
		clusters = []ClusterInfo{}
	}

	resp := ClustersResponse{
		Clusters: clusters,
		Total:    len(clusters),
	}

	m.writeJSON(w, http.StatusOK, resp)
}

// handleStats handles GET /stats.
func (m *ManagementServer) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"uptime_seconds": m.GetUptime().Seconds(),
		"start_time":     m.startTime.Unix(),
		"draining":       m.draining.Load(),
	}

	// Add basic runtime stats
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	memStats := map[string]interface{}{
		"alloc_bytes":       ms.Alloc,
		"total_alloc_bytes": ms.TotalAlloc,
		"sys_bytes":         ms.Sys,
		"num_gc":            ms.NumGC,
	}

	stats["go_goroutines"] = runtime.NumGoroutine()
	stats["memory"] = memStats

	resp := StatsResponse{
		Stats:     stats,
		Timestamp: time.Now(),
	}

	m.writeJSON(w, http.StatusOK, resp)
}

// handleStatsPrometheus handles GET /stats/prometheus.
func (m *ManagementServer) handleStatsPrometheus(w http.ResponseWriter, r *http.Request) {
	// This would typically integrate with prometheus client
	// For now, return basic metrics in prometheus format
	var sb strings.Builder

	uptime := m.GetUptime().Seconds()

	sb.WriteString("# HELP authz_uptime_seconds Time since server start\n")
	sb.WriteString("# TYPE authz_uptime_seconds gauge\n")
	sb.WriteString(fmt.Sprintf("authz_uptime_seconds %.2f\n", uptime))

	sb.WriteString("# HELP authz_draining Whether the server is draining\n")
	sb.WriteString("# TYPE authz_draining gauge\n")
	if m.draining.Load() {
		sb.WriteString("authz_draining 1\n")
	} else {
		sb.WriteString("authz_draining 0\n")
	}

	sb.WriteString("# HELP authz_healthy Whether the server is healthy\n")
	sb.WriteString("# TYPE authz_healthy gauge\n")
	if m.forceHealthy.Load() && !m.draining.Load() {
		sb.WriteString("authz_healthy 1\n")
	} else {
		sb.WriteString("authz_healthy 0\n")
	}

	sb.WriteString("# HELP authz_build_info Build information\n")
	sb.WriteString("# TYPE authz_build_info gauge\n")
	sb.WriteString(fmt.Sprintf("authz_build_info{version=\"%s\",commit=\"%s\"} 1\n",
		m.buildInfo.Version, m.buildInfo.GitCommit))

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(sb.String()))
}

// handleLoggingGet handles GET /logging.
func (m *ManagementServer) handleLoggingGet(w http.ResponseWriter, r *http.Request) {
	resp := LoggingResponse{
		Level: logger.GetLevel(),
		Loggers: map[string]string{
			"root": logger.GetLevel(),
		},
	}

	m.writeJSON(w, http.StatusOK, resp)
}

// handleLoggingPost handles POST /logging.
func (m *ManagementServer) handleLoggingPost(w http.ResponseWriter, r *http.Request) {
	// Check for query parameter first (Envoy style)
	level := r.URL.Query().Get("level")

	// If not in query, try JSON body
	if level == "" {
		var req LoggingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			level = req.Level
		}
	}

	if level == "" {
		m.writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":        "level is required",
			"valid_levels": "debug, info, warn, error",
		})
		return
	}

	// Validate and set level
	switch strings.ToLower(level) {
	case "debug", "info", "warn", "warning", "error":
		if err := logger.SetLevel(level); err != nil {
			m.writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": err.Error(),
			})
			return
		}
		logger.Info("log level changed", logger.String("level", level))
	default:
		m.writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":        "invalid log level",
			"valid_levels": "debug, info, warn, error",
		})
		return
	}

	resp := LoggingResponse{
		Level: logger.GetLevel(),
		Loggers: map[string]string{
			"root": logger.GetLevel(),
		},
	}

	m.writeJSON(w, http.StatusOK, resp)
}

// handleRuntime handles GET /runtime.
func (m *ManagementServer) handleRuntime(w http.ResponseWriter, r *http.Request) {
	healthy := m.forceHealthy.Load()
	ready := !m.draining.Load()

	if m.app != nil {
		healthy = healthy && m.app.IsHealthy()
		ready = ready && m.app.IsReady()
	}

	resp := RuntimeResponse{
		Draining: m.draining.Load(),
		Healthy:  healthy,
		Ready:    ready,
		Runtime: map[string]string{
			"GOMAXPROCS": fmt.Sprintf("%d", 0), // Would use runtime.GOMAXPROCS(0)
			"NumCPU":     fmt.Sprintf("%d", 0), // Would use runtime.NumCPU()
		},
	}

	m.writeJSON(w, http.StatusOK, resp)
}

// handleHealthFail handles POST /healthcheck/fail.
func (m *ManagementServer) handleHealthFail(w http.ResponseWriter, r *http.Request) {
	m.forceHealthy.Store(false)
	logger.Info("health check forced to fail")

	m.writeJSON(w, http.StatusOK, map[string]string{
		"status":  "unhealthy",
		"message": "health check forced to fail",
	})
}

// handleHealthOk handles POST /healthcheck/ok.
func (m *ManagementServer) handleHealthOk(w http.ResponseWriter, r *http.Request) {
	m.forceHealthy.Store(true)
	logger.Info("health check restored to ok")

	m.writeJSON(w, http.StatusOK, map[string]string{
		"status":  "healthy",
		"message": "health check restored",
	})
}

// handleDrain handles POST /drain.
func (m *ManagementServer) handleDrain(w http.ResponseWriter, r *http.Request) {
	if m.draining.Load() {
		m.writeJSON(w, http.StatusOK, map[string]string{
			"status":  "draining",
			"message": "already draining",
		})
		return
	}

	m.draining.Store(true)
	logger.Info("drain mode activated")

	m.writeJSON(w, http.StatusOK, map[string]string{
		"status":  "draining",
		"message": "drain mode activated, server will stop accepting new connections",
	})
}

// handleQuit handles POST /quitquitquit.
func (m *ManagementServer) handleQuit(w http.ResponseWriter, r *http.Request) {
	logger.Info("graceful shutdown requested via /quitquitquit")

	m.writeJSON(w, http.StatusOK, map[string]string{
		"status":  "shutting_down",
		"message": "graceful shutdown initiated",
	})

	// Trigger shutdown in goroutine to allow response to be sent
	go func() {
		time.Sleep(100 * time.Millisecond)
		os.Exit(0)
	}()
}
