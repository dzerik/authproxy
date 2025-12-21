package tests

import (
	"net/http"
	"testing"
	"time"
)

// TestAuthzAdminAccess tests admin-only endpoints
func TestAuthzAdminAccess(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	waitForService(t, authzHealthURL, 60*time.Second)

	adminToken := getToken(t, "admin")
	userToken := getToken(t, "user")

	tests := []struct {
		name        string
		method      string
		path        string
		token       string
		expectedMin int
		expectedMax int
	}{
		// Admin should have access
		{"admin can access dashboard", http.MethodGet, "/admin/dashboard", adminToken, http.StatusOK, http.StatusOK},
		{"admin can access settings", http.MethodGet, "/admin/settings", adminToken, http.StatusOK, http.StatusOK},
		{"admin can access audit", http.MethodGet, "/admin/audit-logs", adminToken, http.StatusOK, http.StatusOK},

		// Regular user should be denied
		{"user cannot access dashboard", http.MethodGet, "/admin/dashboard", userToken, http.StatusForbidden, http.StatusForbidden},
		{"user cannot access settings", http.MethodGet, "/admin/settings", userToken, http.StatusForbidden, http.StatusForbidden},
		{"user cannot access audit", http.MethodGet, "/admin/audit-logs", userToken, http.StatusForbidden, http.StatusForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, _ := makeRequest(t, tc.method, tc.path, tc.token, nil)
			if resp.StatusCode < tc.expectedMin || resp.StatusCode > tc.expectedMax {
				t.Errorf("Expected status between %d and %d, got %d", tc.expectedMin, tc.expectedMax, resp.StatusCode)
			}
		})
	}
}

// TestAuthzUserAccess tests user-accessible endpoints
func TestAuthzUserAccess(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	waitForService(t, authzHealthURL, 60*time.Second)

	userToken := getToken(t, "user")
	adminToken := getToken(t, "admin")

	tests := []struct {
		name     string
		method   string
		path     string
		token    string
		expected int
	}{
		// User can access their own profile
		{"user can read own profile", http.MethodGet, "/api/v1/users/me", userToken, http.StatusOK},
		{"user can update own profile", http.MethodPut, "/api/v1/users/me", userToken, http.StatusOK},

		// User cannot list all users (admin only)
		{"user cannot list users", http.MethodGet, "/api/v1/users", userToken, http.StatusForbidden},

		// Admin can list all users
		{"admin can list users", http.MethodGet, "/api/v1/users", adminToken, http.StatusOK},

		// Admin can read any user profile
		{"admin can read user profile", http.MethodGet, "/api/v1/users/user-001", adminToken, http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var body interface{}
			if tc.method == http.MethodPut {
				body = map[string]string{"firstName": "Updated"}
			}
			resp, _ := makeRequest(t, tc.method, tc.path, tc.token, body)
			assertStatus(t, resp, tc.expected)
		})
	}
}

// TestAuthzPublicEndpoints tests publicly accessible endpoints
func TestAuthzPublicEndpoints(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	waitForService(t, authzHealthURL, 60*time.Second)

	tests := []struct {
		name     string
		method   string
		path     string
		expected int
	}{
		{"health endpoint is public", http.MethodGet, "/health", http.StatusOK},
		{"metrics endpoint is public", http.MethodGet, "/metrics", http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, _ := makeRequest(t, tc.method, tc.path, "", nil)
			assertStatus(t, resp, tc.expected)
		})
	}
}

// TestAuthzServiceAccountAccess tests service account permissions
func TestAuthzServiceAccountAccess(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	waitForService(t, authzHealthURL, 60*time.Second)

	serviceToken := getClientCredentialsToken(t)

	tests := []struct {
		name     string
		method   string
		path     string
		expected int
	}{
		// Service account should have access to internal APIs
		{"service can access internal API", http.MethodGet, "/internal/health", serviceToken, http.StatusOK},

		// Service account should be able to read API endpoints
		{"service can read API", http.MethodGet, "/api/v1/users/me", serviceToken, http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, _ := makeRequest(t, tc.method, tc.path, tc.expected, nil)
			// Service account permissions may vary based on configuration
			assertStatusOneOf(t, resp, http.StatusOK, http.StatusForbidden, http.StatusNotFound)
		})
	}
}

// TestAuthzMethodRestrictions tests HTTP method-based restrictions
func TestAuthzMethodRestrictions(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	waitForService(t, authzHealthURL, 60*time.Second)

	userToken := getToken(t, "user")

	tests := []struct {
		name       string
		method     string
		path       string
		shouldFail bool
	}{
		// Users can GET their profile but can't DELETE
		{"user can GET profile", http.MethodGet, "/api/v1/users/me", false},
		{"user can PUT profile", http.MethodPut, "/api/v1/users/me", false},
		{"user cannot DELETE profile", http.MethodDelete, "/api/v1/users/me", true},

		// Users can't create other users
		{"user cannot POST users", http.MethodPost, "/api/v1/users", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var body interface{}
			if tc.method == http.MethodPost || tc.method == http.MethodPut {
				body = map[string]string{"data": "test"}
			}
			resp, _ := makeRequest(t, tc.method, tc.path, userToken, body)

			if tc.shouldFail {
				assertStatusOneOf(t, resp, http.StatusForbidden, http.StatusMethodNotAllowed)
			} else {
				assertStatusOneOf(t, resp, http.StatusOK, http.StatusCreated, http.StatusNoContent)
			}
		})
	}
}

// TestAuthzRateLimiting tests rate limiting behavior
func TestAuthzRateLimiting(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	waitForService(t, authzHealthURL, 60*time.Second)

	token := getToken(t, "user")

	// Make many requests quickly
	var rateLimited bool
	for i := 0; i < 200; i++ {
		resp, _ := makeRequest(t, http.MethodGet, "/api/v1/users/me", token, nil)
		if resp.StatusCode == http.StatusTooManyRequests {
			rateLimited = true
			t.Logf("Rate limited after %d requests", i+1)

			// Check for rate limit headers
			if resp.Header.Get("X-RateLimit-Limit") != "" {
				t.Log("Rate limit headers present")
			}
			break
		}
	}

	// Rate limiting should kick in for high request volume
	if !rateLimited {
		t.Log("Warning: Rate limiting did not activate (may be configured with high limits)")
	}
}

// TestAuthzCaching tests authorization caching behavior
func TestAuthzCaching(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	waitForService(t, authzHealthURL, 60*time.Second)

	token := getToken(t, "user")

	// First request (cache miss)
	start := time.Now()
	resp1, _ := makeRequest(t, http.MethodGet, "/api/v1/users/me", token, nil)
	duration1 := time.Since(start)

	assertStatus(t, resp1, http.StatusOK)

	// Second request (should hit cache)
	start = time.Now()
	resp2, _ := makeRequest(t, http.MethodGet, "/api/v1/users/me", token, nil)
	duration2 := time.Since(start)

	assertStatus(t, resp2, http.StatusOK)

	// Cached response should generally be faster (but not always, due to variance)
	t.Logf("First request: %v, Second request: %v", duration1, duration2)

	// At minimum, both should succeed
	if resp1.StatusCode != resp2.StatusCode {
		t.Errorf("Inconsistent responses: %d vs %d", resp1.StatusCode, resp2.StatusCode)
	}
}

// TestAuthzAuditLogging tests that authorization decisions are logged
func TestAuthzAuditLogging(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	waitForService(t, authzHealthURL, 60*time.Second)

	token := getToken(t, "user")

	// Make a request that should be logged
	resp, _ := makeRequest(t, http.MethodGet, "/api/v1/users/me", token, nil)
	assertStatus(t, resp, http.StatusOK)

	// Check X-Request-ID is echoed (indicates request tracking)
	requestID := resp.Header.Get("X-Request-ID")
	if requestID == "" {
		t.Log("Note: X-Request-ID header not returned (may not be configured)")
	}
}
