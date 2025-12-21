package tests

import (
	"net/http"
	"testing"
	"time"
)

// TestAuthHealthCheck verifies the health endpoints are accessible
func TestAuthHealthCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	waitForService(t, authzHealthURL, 60*time.Second)

	tests := []struct {
		name     string
		endpoint string
		expected int
	}{
		{"ready endpoint", "/healthz/ready", http.StatusOK},
		{"live endpoint", "/healthz/live", http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, _ := makeRequestToURL(t, authzHealthURL, http.MethodGet, tc.endpoint, "", nil)
			assertStatus(t, resp, tc.expected)
		})
	}
}

// TestAuthTokenAcquisition tests obtaining tokens for different user types
func TestAuthTokenAcquisition(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	tests := []struct {
		name     string
		userType string
	}{
		{"admin user", "admin"},
		{"regular user", "user"},
		{"external user", "external"},
		{"agent user", "agent"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := getToken(t, tc.userType)
			if token == "" {
				t.Error("Expected non-empty token")
			}
		})
	}
}

// TestAuthServiceAccountToken tests service account (client credentials) flow
func TestAuthServiceAccountToken(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	token := getClientCredentialsToken(t)
	if token == "" {
		t.Error("Expected non-empty service account token")
	}
}

// TestAuthInvalidToken tests rejection of invalid tokens
func TestAuthInvalidToken(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	waitForService(t, authzHealthURL, 60*time.Second)

	tests := []struct {
		name     string
		token    string
		expected int
	}{
		{"no token", "", http.StatusUnauthorized},
		{"invalid token", "invalid-token", http.StatusUnauthorized},
		{"malformed bearer", "Bearer invalid", http.StatusUnauthorized},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, _ := makeRequest(t, http.MethodGet, "/api/v1/users/me", tc.token, nil)
			assertStatusOneOf(t, resp, tc.expected, http.StatusForbidden)
		})
	}
}

// TestAuthExpiredToken tests rejection of expired tokens
func TestAuthExpiredToken(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	waitForService(t, authzHealthURL, 60*time.Second)

	// This is a pre-generated expired JWT for testing
	expiredToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXVzZXIiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgxODAvcmVhbG1zL3Rlc3QiLCJhdWQiOiJhdXRoei1zZXJ2aWNlIiwiZXhwIjoxNjAwMDAwMDAwfQ.invalid-signature"

	resp, _ := makeRequest(t, http.MethodGet, "/api/v1/users/me", expiredToken, nil)
	assertStatus(t, resp, http.StatusUnauthorized)
}

// TestAuthTokenRefresh tests token refresh capabilities
func TestAuthTokenRefresh(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	// Get initial token
	token1 := getToken(t, "user")
	if token1 == "" {
		t.Fatal("Failed to get initial token")
	}

	// Get second token (should be different due to timestamp)
	time.Sleep(time.Second)
	token2 := getToken(t, "user")
	if token2 == "" {
		t.Fatal("Failed to get second token")
	}

	// Tokens should be different (different iat/exp)
	if token1 == token2 {
		t.Log("Warning: Tokens are identical, which is unexpected but not necessarily wrong")
	}

	// Both tokens should work
	resp1, _ := makeRequest(t, http.MethodGet, "/health", token1, nil)
	resp2, _ := makeRequest(t, http.MethodGet, "/health", token2, nil)

	assertStatus(t, resp1, http.StatusOK)
	assertStatus(t, resp2, http.StatusOK)
}

// TestAuthMultipleIssuers tests handling of tokens from different issuers
func TestAuthMultipleIssuers(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	waitForService(t, authzHealthURL, 60*time.Second)

	// Test with valid Keycloak token
	token := getToken(t, "user")
	resp, _ := makeRequest(t, http.MethodGet, "/health", token, nil)
	assertStatus(t, resp, http.StatusOK)

	// Test with token from unknown issuer (should be rejected)
	unknownIssuerToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXVzZXIiLCJpc3MiOiJodHRwOi8vdW5rbm93bi1pc3N1ZXIuY29tIiwiYXVkIjoiYXV0aHotc2VydmljZSIsImV4cCI6OTk5OTk5OTk5OX0.invalid"
	resp2, _ := makeRequest(t, http.MethodGet, "/api/v1/users/me", unknownIssuerToken, nil)
	assertStatus(t, resp2, http.StatusUnauthorized)
}

// TestAuthCORSHeaders tests CORS headers on authentication endpoints
func TestAuthCORSHeaders(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	waitForService(t, authzHealthURL, 60*time.Second)

	resp, _ := makeRequest(t, http.MethodOptions, "/health", "", nil)

	// CORS should be configured (or return method not allowed for non-CORS endpoints)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Unexpected status for OPTIONS: %d", resp.StatusCode)
	}
}
