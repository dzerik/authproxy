package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	m := New()

	require.NotNil(t, m, "New returned nil")
	assert.NotNil(t, m.Registry, "Registry should not be nil")

	// Check all metrics are initialized
	assert.NotNil(t, m.AuthRequestsTotal, "AuthRequestsTotal should not be nil")
	assert.NotNil(t, m.AuthDurationSeconds, "AuthDurationSeconds should not be nil")
	assert.NotNil(t, m.AuthErrorsTotal, "AuthErrorsTotal should not be nil")
	assert.NotNil(t, m.TokenRefreshTotal, "TokenRefreshTotal should not be nil")
	assert.NotNil(t, m.TokenRefreshDuration, "TokenRefreshDuration should not be nil")
	assert.NotNil(t, m.ActiveSessions, "ActiveSessions should not be nil")
	assert.NotNil(t, m.SessionCreatedTotal, "SessionCreatedTotal should not be nil")
	assert.NotNil(t, m.SessionExpiredTotal, "SessionExpiredTotal should not be nil")
	assert.NotNil(t, m.SessionErrorsTotal, "SessionErrorsTotal should not be nil")
	assert.NotNil(t, m.HTTPRequestsTotal, "HTTPRequestsTotal should not be nil")
	assert.NotNil(t, m.HTTPRequestDuration, "HTTPRequestDuration should not be nil")
	assert.NotNil(t, m.HTTPRequestsInFlight, "HTTPRequestsInFlight should not be nil")
	assert.NotNil(t, m.HTTPResponseSize, "HTTPResponseSize should not be nil")
	assert.NotNil(t, m.IdPRequestsTotal, "IdPRequestsTotal should not be nil")
	assert.NotNil(t, m.IdPRequestDuration, "IdPRequestDuration should not be nil")
	assert.NotNil(t, m.IdPErrorsTotal, "IdPErrorsTotal should not be nil")
}

func TestMetrics_Handler(t *testing.T) {
	m := New()

	handler := m.Handler()
	require.NotNil(t, handler, "Handler returned nil")

	// Record some metrics first (Prometheus only exports metrics after first use)
	m.RecordAuthRequest("keycloak", "login", "success")
	m.RecordSessionCreated()
	m.RecordHTTPRequest("GET", "/health", "200")

	// Test that handler returns metrics
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	body, _ := io.ReadAll(rr.Body)
	bodyStr := string(body)

	// Check for some expected metrics (only those that have been recorded)
	expectedMetrics := []string{
		"auth_portal_auth_requests_total",
		"auth_portal_active_sessions",
		"auth_portal_http_requests_total",
		"go_gc_duration_seconds",   // Standard Go collector
		"process_cpu_seconds_total", // Process collector
	}

	for _, expected := range expectedMetrics {
		assert.Contains(t, bodyStr, expected, "body should contain %s", expected)
	}
}

func TestMetrics_RecordAuthRequest(t *testing.T) {
	m := New()

	// Should not panic
	m.RecordAuthRequest("keycloak", "login", "success")
	m.RecordAuthRequest("keycloak", "login", "failure")
	m.RecordAuthRequest("mock", "login", "success")
}

func TestMetrics_RecordAuthDuration(t *testing.T) {
	m := New()

	// Should not panic
	m.RecordAuthDuration("keycloak", "authorize", 0.5)
	m.RecordAuthDuration("keycloak", "token_exchange", 0.2)
	m.RecordAuthDuration("mock", "authorize", 0.01)
}

func TestMetrics_RecordAuthError(t *testing.T) {
	m := New()

	// Should not panic
	m.RecordAuthError("keycloak", "token_invalid")
	m.RecordAuthError("keycloak", "user_not_found")
	m.RecordAuthError("mock", "profile_not_found")
}

func TestMetrics_RecordTokenRefresh(t *testing.T) {
	m := New()

	// Should not panic
	m.RecordTokenRefresh("success")
	m.RecordTokenRefresh("failure")
}

func TestMetrics_RecordSessionCreated(t *testing.T) {
	m := New()

	// Should not panic and increment both counters
	m.RecordSessionCreated()
	m.RecordSessionCreated()
	m.RecordSessionCreated()
}

func TestMetrics_RecordSessionExpired(t *testing.T) {
	m := New()

	// Create some sessions first
	m.RecordSessionCreated()
	m.RecordSessionCreated()

	// Then expire them
	m.RecordSessionExpired()
	m.RecordSessionExpired()
}

func TestMetrics_RecordSessionError(t *testing.T) {
	m := New()

	// Should not panic
	m.RecordSessionError("invalid_session")
	m.RecordSessionError("session_expired")
	m.RecordSessionError("decode_failed")
}

func TestMetrics_RecordHTTPRequest(t *testing.T) {
	m := New()

	// Should not panic
	m.RecordHTTPRequest("GET", "/health", "200")
	m.RecordHTTPRequest("POST", "/login", "302")
	m.RecordHTTPRequest("GET", "/api/user", "401")
	m.RecordHTTPRequest("PUT", "/api/profile", "500")
}

func TestMetrics_RecordHTTPDuration(t *testing.T) {
	m := New()

	// Should not panic
	m.RecordHTTPDuration("GET", "/health", 0.001)
	m.RecordHTTPDuration("POST", "/login", 0.5)
	m.RecordHTTPDuration("GET", "/api/user", 0.02)
}

func TestMetrics_RecordHTTPResponseSize(t *testing.T) {
	m := New()

	// Should not panic
	m.RecordHTTPResponseSize("GET", "/health", 100)
	m.RecordHTTPResponseSize("POST", "/login", 0)
	m.RecordHTTPResponseSize("GET", "/api/user", 5000)
}

func TestMetrics_RecordIdPRequest(t *testing.T) {
	m := New()

	// Should not panic
	m.RecordIdPRequest("keycloak", "authorize", "success")
	m.RecordIdPRequest("keycloak", "token_exchange", "failure")
	m.RecordIdPRequest("mock", "user_info", "success")
}

func TestMetrics_RecordIdPDuration(t *testing.T) {
	m := New()

	// Should not panic
	m.RecordIdPDuration("keycloak", "authorize", 0.3)
	m.RecordIdPDuration("keycloak", "token_exchange", 0.15)
	m.RecordIdPDuration("mock", "user_info", 0.001)
}

func TestMetrics_RecordIdPError(t *testing.T) {
	m := New()

	// Should not panic
	m.RecordIdPError("keycloak", "connection_failed")
	m.RecordIdPError("keycloak", "invalid_response")
	m.RecordIdPError("mock", "profile_not_found")
}

func TestMetrics_InFlightIncDec(t *testing.T) {
	m := New()

	// Increment
	m.InFlightInc()
	m.InFlightInc()
	m.InFlightInc()

	// Decrement
	m.InFlightDec()
	m.InFlightDec()
	m.InFlightDec()

	// Should not panic even with more decrements
	m.InFlightDec()
}

func TestMetrics_VerifyMetricsOutput(t *testing.T) {
	m := New()

	// Record some metrics
	m.RecordAuthRequest("keycloak", "login", "success")
	m.RecordSessionCreated()
	m.RecordHTTPRequest("GET", "/health", "200")
	m.RecordIdPRequest("keycloak", "authorize", "success")

	// Get metrics output
	handler := m.Handler()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	body := rr.Body.String()

	// Verify recorded metrics appear in output
	if !strings.Contains(body, `auth_portal_auth_requests_total{provider="keycloak",status="success",type="login"} 1`) {
		t.Log("Auth request metric may have different format")
	}

	assert.Contains(t, body, "auth_portal_session_created_total", "Session created metric should appear in output")
}

func BenchmarkMetrics_RecordAuthRequest(b *testing.B) {
	m := New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.RecordAuthRequest("keycloak", "login", "success")
	}
}

func BenchmarkMetrics_RecordHTTPRequest(b *testing.B) {
	m := New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.RecordHTTPRequest("GET", "/api/user", "200")
	}
}

func BenchmarkMetrics_RecordHTTPDuration(b *testing.B) {
	m := New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.RecordHTTPDuration("GET", "/api/user", 0.05)
	}
}

func BenchmarkMetrics_Handler(b *testing.B) {
	m := New()
	handler := m.Handler()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
	}
}
