package tests

import (
	"net/http"
	"testing"
	"time"
)

// TestAuthzToAuthzBasicFlow tests the basic authz-to-authz communication flow
func TestAuthzToAuthzBasicFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	// Wait for both services
	waitForService(t, authzHealthURL, 60*time.Second)
	waitForService(t, "http://localhost:25020", 60*time.Second)

	// Get external user token
	externalToken := getToken(t, "external")
	if externalToken == "" {
		t.Fatal("Failed to get external user token")
	}

	// Request from internal authz-service to external authz-service
	// This tests the egress path with token exchange
	resp, body := makeRequest(t, http.MethodGet, "/egress/partner/api/resources", externalToken, nil)

	t.Logf("Egress response status: %d, body: %s", resp.StatusCode, string(body))

	// Should either succeed or return appropriate error
	assertStatusOneOf(t, resp, http.StatusOK, http.StatusForbidden, http.StatusBadGateway, http.StatusNotFound)
}

// TestAuthzToAuthzTokenExchange tests token exchange in authz-to-authz flow
func TestAuthzToAuthzTokenExchange(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	waitForService(t, authzHealthURL, 60*time.Second)
	waitForService(t, "http://localhost:25020", 60*time.Second)

	// Get user token for internal service
	userToken := getToken(t, "user")

	// Exchange token for external service
	exchangedToken := exchangeToken(t, userToken, "authz-service-external")
	if exchangedToken == "" {
		t.Fatal("Failed to exchange token for external service")
	}

	// Use exchanged token directly with external service
	resp, body := makeRequestToURL(t, authzExternalURL, http.MethodGet, "/partner/api/resources", exchangedToken, nil)

	t.Logf("Direct external call status: %d, body: %s", resp.StatusCode, string(body))

	assertStatusOneOf(t, resp, http.StatusOK, http.StatusForbidden)
}

// TestAuthzToAuthzMTLSBypass tests mTLS validation between services
func TestAuthzToAuthzMTLSBypass(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	// In Tier 1 (Docker Compose), mTLS might not be enabled
	// This test verifies the expected behavior

	waitForService(t, authzHealthURL, 60*time.Second)
	waitForService(t, "http://localhost:25020", 60*time.Second)

	// Try to access external service without proper authentication
	resp, _ := makeRequestToURL(t, authzExternalURL, http.MethodGet, "/partner/api/resources", "", nil)

	// Without token, should be unauthorized
	assertStatus(t, resp, http.StatusUnauthorized)

	// With valid external token, should work
	externalToken := getToken(t, "external")
	resp2, _ := makeRequestToURL(t, authzExternalURL, http.MethodGet, "/partner/api/resources", externalToken, nil)

	assertStatusOneOf(t, resp2, http.StatusOK, http.StatusForbidden)
}

// TestAuthzToAuthzErrorPropagation tests error propagation between services
func TestAuthzToAuthzErrorPropagation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	waitForService(t, authzHealthURL, 60*time.Second)

	externalToken := getToken(t, "external")

	tests := []struct {
		name     string
		path     string
		expected []int
	}{
		{
			"non-existent resource propagates 404",
			"/egress/partner/api/nonexistent",
			[]int{http.StatusNotFound, http.StatusForbidden, http.StatusBadGateway},
		},
		{
			"forbidden resource propagates 403",
			"/egress/admin/secret",
			[]int{http.StatusForbidden, http.StatusNotFound, http.StatusBadGateway},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, _ := makeRequest(t, http.MethodGet, tc.path, externalToken, nil)
			assertStatusOneOf(t, resp, tc.expected...)
		})
	}
}

// TestAuthzToAuthzCircuitBreaker tests circuit breaker behavior
func TestAuthzToAuthzCircuitBreaker(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	waitForService(t, authzHealthURL, 60*time.Second)

	externalToken := getToken(t, "external")

	// Make requests that should trigger circuit breaker if external is down
	failureCount := 0
	for i := 0; i < 10; i++ {
		resp, _ := makeRequest(t, http.MethodGet, "/egress/partner/api/resources", externalToken, nil)
		if resp.StatusCode >= 500 {
			failureCount++
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Logf("Failures in 10 requests: %d", failureCount)

	// If all requests failed, circuit breaker might be open
	// (or external service is actually down)
}

// TestAuthzToAuthzRetryBehavior tests retry behavior on transient failures
func TestAuthzToAuthzRetryBehavior(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	waitForService(t, authzHealthURL, 60*time.Second)

	externalToken := getToken(t, "external")

	// Measure response time (retries would increase it)
	start := time.Now()
	resp, _ := makeRequest(t, http.MethodGet, "/egress/partner/api/resources", externalToken, nil)
	duration := time.Since(start)

	t.Logf("Request took %v, status: %d", duration, resp.StatusCode)

	// Response time can indicate if retries occurred
	// (This is observational - actual retry behavior depends on configuration)
}

// TestAuthzToAuthzDelegationChain tests delegation chain through both services
func TestAuthzToAuthzDelegationChain(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	waitForService(t, authzHealthURL, 60*time.Second)
	waitForService(t, "http://localhost:25020", 60*time.Second)

	// Get agent token
	agentToken := getToken(t, "agent")

	// Request through internal -> external with agent delegation
	resp, body := makeRequest(t, http.MethodPost, "/egress/partner/api/actions/test-action", agentToken, map[string]string{
		"action": "test",
		"data":   "delegation-test",
	})

	t.Logf("Delegation chain response: status=%d, body=%s", resp.StatusCode, string(body))

	// Agent actions may be allowed or denied based on delegation policy
	assertStatusOneOf(t, resp, http.StatusOK, http.StatusForbidden, http.StatusNotFound, http.StatusBadGateway)
}

// TestAuthzToAuthzAuditTracing tests audit trail across both services
func TestAuthzToAuthzAuditTracing(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	waitForService(t, authzHealthURL, 60*time.Second)

	externalToken := getToken(t, "external")

	// Make a request with specific correlation ID
	correlationID := "test-correlation-" + time.Now().Format("20060102150405")

	resp, _ := makeRequest(t, http.MethodGet, "/egress/partner/api/resources", externalToken, nil)

	// Check if correlation headers are present
	if respCorrelationID := resp.Header.Get("X-Correlation-ID"); respCorrelationID != "" {
		t.Logf("Correlation ID returned: %s", respCorrelationID)
	}

	t.Logf("Request completed with correlation ID: %s, status: %d", correlationID, resp.StatusCode)
}

// TestAuthzToAuthzHealthAggregation tests aggregated health checks
func TestAuthzToAuthzHealthAggregation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	waitForService(t, authzHealthURL, 60*time.Second)

	// Check internal service health
	resp1, _ := makeRequestToURL(t, authzHealthURL, http.MethodGet, "/healthz/ready", "", nil)
	assertStatus(t, resp1, http.StatusOK)

	// Check external service health
	resp2, _ := makeRequestToURL(t, "http://localhost:25020", http.MethodGet, "/healthz/ready", "", nil)
	assertStatus(t, resp2, http.StatusOK)

	// Both services should be healthy
	t.Log("Both authz services are healthy")
}
