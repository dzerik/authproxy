package metrics

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMetrics(t *testing.T) {
	// Note: We can't actually create new metrics in each test because
	// Prometheus will complain about duplicate registration.
	// So we just test the default instance.

	require.NotNil(t, DefaultMetrics)
	assert.NotNil(t, DefaultMetrics.AuthzRequestsTotal)
	assert.NotNil(t, DefaultMetrics.AuthzDecisionsTotal)
	assert.NotNil(t, DefaultMetrics.AuthzDurationSeconds)
	assert.NotNil(t, DefaultMetrics.JWTValidationsTotal)
	assert.NotNil(t, DefaultMetrics.JWKSRefreshesTotal)
	assert.NotNil(t, DefaultMetrics.PolicyEvaluationsTotal)
	assert.NotNil(t, DefaultMetrics.PolicyEvaluationDuration)
	assert.NotNil(t, DefaultMetrics.CacheHitsTotal)
	assert.NotNil(t, DefaultMetrics.CacheMissesTotal)
	assert.NotNil(t, DefaultMetrics.CacheSize)
	assert.NotNil(t, DefaultMetrics.HTTPRequestsTotal)
	assert.NotNil(t, DefaultMetrics.HTTPRequestDuration)
}

func TestMetrics_RecordAuthzDecision(t *testing.T) {
	tests := []struct {
		name    string
		allowed bool
		cached  bool
		engine  string
	}{
		{"allowed not cached", true, false, "builtin"},
		{"allowed cached", true, true, "opa"},
		{"denied not cached", false, false, "builtin"},
		{"denied cached", false, true, "opa"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			DefaultMetrics.RecordAuthzDecision(tt.allowed, tt.cached, tt.engine)
		})
	}
}

func TestMetrics_RecordJWTValidation(t *testing.T) {
	tests := []struct {
		name    string
		issuer  string
		success bool
	}{
		{"success", "https://issuer.example.com", true},
		{"failure", "https://issuer.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			DefaultMetrics.RecordJWTValidation(tt.issuer, tt.success)
		})
	}
}

func TestMetrics_RecordCacheHit(t *testing.T) {
	// Should not panic
	DefaultMetrics.RecordCacheHit("l1")
	DefaultMetrics.RecordCacheHit("l2")
}

func TestMetrics_RecordCacheMiss(t *testing.T) {
	// Should not panic
	DefaultMetrics.RecordCacheMiss("l1")
	DefaultMetrics.RecordCacheMiss("l2")
}

func TestMetrics_SetCacheSize(t *testing.T) {
	// Should not panic
	DefaultMetrics.SetCacheSize("l1", 100)
	DefaultMetrics.SetCacheSize("l2", 500)
}

func BenchmarkRecordAuthzDecision(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DefaultMetrics.RecordAuthzDecision(true, false, "builtin")
	}
}

func BenchmarkRecordJWTValidation(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DefaultMetrics.RecordJWTValidation("https://issuer.example.com", true)
	}
}

func BenchmarkRecordCacheHit(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DefaultMetrics.RecordCacheHit("l1")
	}
}

func BenchmarkSetCacheSize(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DefaultMetrics.SetCacheSize("l1", float64(i%1000))
	}
}
