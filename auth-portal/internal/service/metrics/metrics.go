// Package metrics provides Prometheus metrics for the auth-portal service.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus metrics for the auth-portal service.
type Metrics struct {
	// Authentication metrics
	AuthRequestsTotal    *prometheus.CounterVec
	AuthDurationSeconds  *prometheus.HistogramVec
	AuthErrorsTotal      *prometheus.CounterVec
	TokenRefreshTotal    *prometheus.CounterVec
	TokenRefreshDuration *prometheus.HistogramVec

	// Session metrics
	ActiveSessions      prometheus.Gauge
	SessionCreatedTotal prometheus.Counter
	SessionExpiredTotal prometheus.Counter
	SessionErrorsTotal  *prometheus.CounterVec

	// HTTP metrics
	HTTPRequestsTotal    *prometheus.CounterVec
	HTTPRequestDuration  *prometheus.HistogramVec
	HTTPRequestsInFlight prometheus.Gauge
	HTTPResponseSize     *prometheus.HistogramVec

	// IdP metrics
	IdPRequestsTotal   *prometheus.CounterVec
	IdPRequestDuration *prometheus.HistogramVec
	IdPErrorsTotal     *prometheus.CounterVec

	// Registry for metrics
	Registry *prometheus.Registry
}

// New creates a new Metrics instance with all metrics registered.
func New() *Metrics {
	reg := prometheus.NewRegistry()

	// Register standard Go collectors
	reg.MustRegister(prometheus.NewGoCollector())
	reg.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	reg.MustRegister(prometheus.NewBuildInfoCollector())

	m := &Metrics{
		Registry: reg,

		// Authentication metrics
		AuthRequestsTotal: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_portal_auth_requests_total",
				Help: "Total number of authentication requests",
			},
			[]string{"provider", "type", "status"},
		),
		AuthDurationSeconds: promauto.With(reg).NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "auth_portal_auth_duration_seconds",
				Help:    "Authentication request duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"provider", "step"},
		),
		AuthErrorsTotal: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_portal_auth_errors_total",
				Help: "Total number of authentication errors",
			},
			[]string{"provider", "error_type"},
		),
		TokenRefreshTotal: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_portal_token_refresh_total",
				Help: "Total number of token refresh operations",
			},
			[]string{"status"},
		),
		TokenRefreshDuration: promauto.With(reg).NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "auth_portal_token_refresh_duration_seconds",
				Help:    "Token refresh duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"provider"},
		),

		// Session metrics
		ActiveSessions: promauto.With(reg).NewGauge(
			prometheus.GaugeOpts{
				Name: "auth_portal_active_sessions",
				Help: "Current number of active sessions",
			},
		),
		SessionCreatedTotal: promauto.With(reg).NewCounter(
			prometheus.CounterOpts{
				Name: "auth_portal_session_created_total",
				Help: "Total number of sessions created",
			},
		),
		SessionExpiredTotal: promauto.With(reg).NewCounter(
			prometheus.CounterOpts{
				Name: "auth_portal_session_expired_total",
				Help: "Total number of sessions expired",
			},
		),
		SessionErrorsTotal: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_portal_session_errors_total",
				Help: "Total number of session errors",
			},
			[]string{"error_type"},
		),

		// HTTP metrics
		HTTPRequestsTotal: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_portal_http_requests_total",
				Help: "Total number of HTTP requests",
			},
			[]string{"method", "path", "status"},
		),
		HTTPRequestDuration: promauto.With(reg).NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "auth_portal_http_request_duration_seconds",
				Help:    "HTTP request duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "path"},
		),
		HTTPRequestsInFlight: promauto.With(reg).NewGauge(
			prometheus.GaugeOpts{
				Name: "auth_portal_http_requests_in_flight",
				Help: "Current number of HTTP requests being processed",
			},
		),
		HTTPResponseSize: promauto.With(reg).NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "auth_portal_http_response_size_bytes",
				Help:    "HTTP response size in bytes",
				Buckets: prometheus.ExponentialBuckets(100, 10, 8),
			},
			[]string{"method", "path"},
		),

		// IdP metrics
		IdPRequestsTotal: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_portal_idp_requests_total",
				Help: "Total number of IdP requests",
			},
			[]string{"provider", "operation", "status"},
		),
		IdPRequestDuration: promauto.With(reg).NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "auth_portal_idp_request_duration_seconds",
				Help:    "IdP request duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"provider", "operation"},
		),
		IdPErrorsTotal: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_portal_idp_errors_total",
				Help: "Total number of IdP errors",
			},
			[]string{"provider", "error_type"},
		),
	}

	return m
}

// Handler returns an HTTP handler for serving Prometheus metrics.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{
		Registry:          m.Registry,
		EnableOpenMetrics: true,
	})
}

// RecordAuthRequest records an authentication request.
func (m *Metrics) RecordAuthRequest(provider, authType, status string) {
	m.AuthRequestsTotal.WithLabelValues(provider, authType, status).Inc()
}

// RecordAuthDuration records authentication duration.
func (m *Metrics) RecordAuthDuration(provider, step string, duration float64) {
	m.AuthDurationSeconds.WithLabelValues(provider, step).Observe(duration)
}

// RecordAuthError records an authentication error.
func (m *Metrics) RecordAuthError(provider, errorType string) {
	m.AuthErrorsTotal.WithLabelValues(provider, errorType).Inc()
}

// RecordTokenRefresh records a token refresh operation.
func (m *Metrics) RecordTokenRefresh(status string) {
	m.TokenRefreshTotal.WithLabelValues(status).Inc()
}

// RecordSessionCreated records a new session creation.
func (m *Metrics) RecordSessionCreated() {
	m.SessionCreatedTotal.Inc()
	m.ActiveSessions.Inc()
}

// RecordSessionExpired records a session expiration.
func (m *Metrics) RecordSessionExpired() {
	m.SessionExpiredTotal.Inc()
	m.ActiveSessions.Dec()
}

// RecordSessionError records a session error.
func (m *Metrics) RecordSessionError(errorType string) {
	m.SessionErrorsTotal.WithLabelValues(errorType).Inc()
}

// RecordHTTPRequest records an HTTP request.
func (m *Metrics) RecordHTTPRequest(method, path, status string) {
	m.HTTPRequestsTotal.WithLabelValues(method, path, status).Inc()
}

// RecordHTTPDuration records HTTP request duration.
func (m *Metrics) RecordHTTPDuration(method, path string, duration float64) {
	m.HTTPRequestDuration.WithLabelValues(method, path).Observe(duration)
}

// RecordHTTPResponseSize records HTTP response size.
func (m *Metrics) RecordHTTPResponseSize(method, path string, size float64) {
	m.HTTPResponseSize.WithLabelValues(method, path).Observe(size)
}

// RecordIdPRequest records an IdP request.
func (m *Metrics) RecordIdPRequest(provider, operation, status string) {
	m.IdPRequestsTotal.WithLabelValues(provider, operation, status).Inc()
}

// RecordIdPDuration records IdP request duration.
func (m *Metrics) RecordIdPDuration(provider, operation string, duration float64) {
	m.IdPRequestDuration.WithLabelValues(provider, operation).Observe(duration)
}

// RecordIdPError records an IdP error.
func (m *Metrics) RecordIdPError(provider, errorType string) {
	m.IdPErrorsTotal.WithLabelValues(provider, errorType).Inc()
}

// InFlightInc increments the in-flight request counter.
func (m *Metrics) InFlightInc() {
	m.HTTPRequestsInFlight.Inc()
}

// InFlightDec decrements the in-flight request counter.
func (m *Metrics) InFlightDec() {
	m.HTTPRequestsInFlight.Dec()
}
