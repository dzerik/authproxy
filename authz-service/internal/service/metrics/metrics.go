package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus metrics for the authorization service.
type Metrics struct {
	// Authorization metrics
	AuthzRequestsTotal   *prometheus.CounterVec
	AuthzDecisionsTotal  *prometheus.CounterVec
	AuthzDurationSeconds *prometheus.HistogramVec

	// JWT metrics
	JWTValidationsTotal *prometheus.CounterVec
	JWKSRefreshesTotal  *prometheus.CounterVec

	// Policy metrics
	PolicyEvaluationsTotal   *prometheus.CounterVec
	PolicyEvaluationDuration *prometheus.HistogramVec

	// Cache metrics
	CacheHitsTotal   *prometheus.CounterVec
	CacheMissesTotal *prometheus.CounterVec
	CacheSize        *prometheus.GaugeVec

	// HTTP metrics
	HTTPRequestsTotal   *prometheus.CounterVec
	HTTPRequestDuration *prometheus.HistogramVec
}

// DefaultMetrics is the global metrics instance.
var DefaultMetrics *Metrics

func init() {
	DefaultMetrics = NewMetrics()
}

// NewMetrics creates and registers all metrics.
func NewMetrics() *Metrics {
	return &Metrics{
		// Authorization metrics
		AuthzRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "authz",
				Name:      "requests_total",
				Help:      "Total number of authorization requests",
			},
			[]string{"method", "path"},
		),
		AuthzDecisionsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "authz",
				Name:      "decisions_total",
				Help:      "Total number of authorization decisions",
			},
			[]string{"allowed", "cached", "engine"},
		),
		AuthzDurationSeconds: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "authz",
				Name:      "duration_seconds",
				Help:      "Authorization request duration in seconds",
				Buckets:   []float64{.0001, .0005, .001, .005, .01, .05, .1, .5, 1},
			},
			[]string{"method"},
		),

		// JWT metrics
		JWTValidationsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "authz",
				Subsystem: "jwt",
				Name:      "validations_total",
				Help:      "Total number of JWT validations",
			},
			[]string{"issuer", "result"},
		),
		JWKSRefreshesTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "authz",
				Subsystem: "jwks",
				Name:      "refreshes_total",
				Help:      "Total number of JWKS refreshes",
			},
			[]string{"issuer", "result"},
		),

		// Policy metrics
		PolicyEvaluationsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "authz",
				Subsystem: "policy",
				Name:      "evaluations_total",
				Help:      "Total number of policy evaluations",
			},
			[]string{"engine", "result"},
		),
		PolicyEvaluationDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "authz",
				Subsystem: "policy",
				Name:      "evaluation_duration_seconds",
				Help:      "Policy evaluation duration in seconds",
				Buckets:   []float64{.00001, .00005, .0001, .0005, .001, .005, .01},
			},
			[]string{"engine"},
		),

		// Cache metrics
		CacheHitsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "authz",
				Subsystem: "cache",
				Name:      "hits_total",
				Help:      "Total number of cache hits",
			},
			[]string{"level"},
		),
		CacheMissesTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "authz",
				Subsystem: "cache",
				Name:      "misses_total",
				Help:      "Total number of cache misses",
			},
			[]string{"level"},
		),
		CacheSize: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "authz",
				Subsystem: "cache",
				Name:      "size",
				Help:      "Current number of items in cache",
			},
			[]string{"level"},
		),

		// HTTP metrics
		HTTPRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "authz",
				Subsystem: "http",
				Name:      "requests_total",
				Help:      "Total number of HTTP requests",
			},
			[]string{"method", "path", "status"},
		),
		HTTPRequestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "authz",
				Subsystem: "http",
				Name:      "request_duration_seconds",
				Help:      "HTTP request duration in seconds",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"method", "path"},
		),
	}
}

// RecordAuthzDecision records an authorization decision.
func (m *Metrics) RecordAuthzDecision(allowed, cached bool, engine string) {
	allowedStr := "false"
	if allowed {
		allowedStr = "true"
	}
	cachedStr := "false"
	if cached {
		cachedStr = "true"
	}
	m.AuthzDecisionsTotal.WithLabelValues(allowedStr, cachedStr, engine).Inc()
}

// RecordJWTValidation records a JWT validation result.
func (m *Metrics) RecordJWTValidation(issuer string, success bool) {
	result := "failure"
	if success {
		result = "success"
	}
	m.JWTValidationsTotal.WithLabelValues(issuer, result).Inc()
}

// RecordCacheHit records a cache hit.
func (m *Metrics) RecordCacheHit(level string) {
	m.CacheHitsTotal.WithLabelValues(level).Inc()
}

// RecordCacheMiss records a cache miss.
func (m *Metrics) RecordCacheMiss(level string) {
	m.CacheMissesTotal.WithLabelValues(level).Inc()
}

// SetCacheSize updates the cache size gauge.
func (m *Metrics) SetCacheSize(level string, size float64) {
	m.CacheSize.WithLabelValues(level).Set(size)
}
