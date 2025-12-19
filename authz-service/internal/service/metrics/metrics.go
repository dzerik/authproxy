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

	// SLI/SLO metrics
	SLOLatencyViolationsTotal   *prometheus.CounterVec   // Counts requests exceeding latency SLO
	SLOAvailabilityErrorsTotal  *prometheus.CounterVec   // Counts errors affecting availability SLO
	SLORequestDurationSummary   *prometheus.SummaryVec   // Precise percentiles for SLO calculation
	UpstreamErrorsTotal         *prometheus.CounterVec   // Upstream dependency errors (OPA, Redis, etc.)
	CircuitBreakerStateChanges  *prometheus.CounterVec   // Circuit breaker state transitions
	RequestsInFlight            prometheus.Gauge         // Current concurrent requests
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

		// SLI/SLO metrics
		SLOLatencyViolationsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "authz",
				Subsystem: "slo",
				Name:      "latency_violations_total",
				Help:      "Total number of requests exceeding latency SLO threshold",
			},
			[]string{"threshold", "endpoint"},
		),
		SLOAvailabilityErrorsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "authz",
				Subsystem: "slo",
				Name:      "availability_errors_total",
				Help:      "Total number of errors affecting availability SLO (5xx, timeouts)",
			},
			[]string{"error_type", "endpoint"},
		),
		SLORequestDurationSummary: promauto.NewSummaryVec(
			prometheus.SummaryOpts{
				Namespace:  "authz",
				Subsystem:  "slo",
				Name:       "request_duration_seconds",
				Help:       "Request duration summary for SLO percentile calculation",
				Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.95: 0.005, 0.99: 0.001, 0.999: 0.0001},
				MaxAge:     prometheus.DefMaxAge,
			},
			[]string{"endpoint"},
		),
		UpstreamErrorsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "authz",
				Subsystem: "slo",
				Name:      "upstream_errors_total",
				Help:      "Total number of upstream dependency errors",
			},
			[]string{"upstream", "error_type"},
		),
		CircuitBreakerStateChanges: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "authz",
				Subsystem: "resilience",
				Name:      "circuit_breaker_state_changes_total",
				Help:      "Total number of circuit breaker state transitions",
			},
			[]string{"service", "from_state", "to_state"},
		),
		RequestsInFlight: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "authz",
				Name:      "requests_in_flight",
				Help:      "Current number of requests being processed",
			},
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

// SLO latency thresholds in milliseconds
const (
	SLOLatencyP99Threshold  = 100  // 100ms for p99
	SLOLatencyP999Threshold = 500  // 500ms for p99.9
)

// RecordSLOLatency records request duration for SLO tracking.
// It automatically checks against SLO thresholds and records violations.
func (m *Metrics) RecordSLOLatency(endpoint string, durationMs float64) {
	// Record to summary for percentile calculation
	m.SLORequestDurationSummary.WithLabelValues(endpoint).Observe(durationMs / 1000)

	// Check SLO thresholds and record violations
	if durationMs > SLOLatencyP99Threshold {
		m.SLOLatencyViolationsTotal.WithLabelValues("p99", endpoint).Inc()
	}
	if durationMs > SLOLatencyP999Threshold {
		m.SLOLatencyViolationsTotal.WithLabelValues("p999", endpoint).Inc()
	}
}

// RecordSLOError records an error affecting availability SLO.
func (m *Metrics) RecordSLOError(errorType, endpoint string) {
	m.SLOAvailabilityErrorsTotal.WithLabelValues(errorType, endpoint).Inc()
}

// RecordUpstreamError records an upstream dependency error.
func (m *Metrics) RecordUpstreamError(upstream, errorType string) {
	m.UpstreamErrorsTotal.WithLabelValues(upstream, errorType).Inc()
}

// RecordCircuitBreakerStateChange records a circuit breaker state transition.
func (m *Metrics) RecordCircuitBreakerStateChange(service, fromState, toState string) {
	m.CircuitBreakerStateChanges.WithLabelValues(service, fromState, toState).Inc()
}

// IncRequestsInFlight increments the in-flight request counter.
func (m *Metrics) IncRequestsInFlight() {
	m.RequestsInFlight.Inc()
}

// DecRequestsInFlight decrements the in-flight request counter.
func (m *Metrics) DecRequestsInFlight() {
	m.RequestsInFlight.Dec()
}
