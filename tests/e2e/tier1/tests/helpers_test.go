// Package tests contains E2E tests for Tier 1 (Docker/Podman Compose)
package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// Test environment configuration
var (
	keycloakURL     = getEnv("KEYCLOAK_URL", "http://localhost:8180")
	authzURL        = getEnv("AUTHZ_URL", "http://localhost:8080")
	authzExternalURL = getEnv("AUTHZ_EXTERNAL_URL", "http://localhost:9080")
	authzAdminURL   = getEnv("AUTHZ_ADMIN_URL", "http://localhost:15000")
	authzHealthURL  = getEnv("AUTHZ_HEALTH_URL", "http://localhost:15020")

	realm        = getEnv("REALM", "test")
	clientID     = getEnv("CLIENT_ID", "authz-service")
	clientSecret = getEnv("CLIENT_SECRET", "test-secret")

	httpClient = &http.Client{
		Timeout: 30 * time.Second,
	}
)

// User credentials for testing
type UserCredentials struct {
	Username string
	Password string
	Roles    []string
}

var testUsers = map[string]UserCredentials{
	"admin": {
		Username: "admin-user",
		Password: "admin-password",
		Roles:    []string{"admin", "user"},
	},
	"user": {
		Username: "test-user",
		Password: "test-password",
		Roles:    []string{"user"},
	},
	"external": {
		Username: "external-user",
		Password: "external-password",
		Roles:    []string{"external"},
	},
	"agent": {
		Username: "agent-user",
		Password: "agent-password",
		Roles:    []string{"agent"},
	},
}

// TokenResponse represents OAuth token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// AuthzResponse represents authorization decision response
type AuthzResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

// HealthResponse represents health check response
type HealthResponse struct {
	Status string `json:"status"`
}

// getEnv returns environment variable or default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getToken obtains access token from Keycloak
func getToken(t *testing.T, userType string) string {
	t.Helper()

	user, ok := testUsers[userType]
	if !ok {
		t.Fatalf("Unknown user type: %s", userType)
	}

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", keycloakURL, realm)

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("username", user.Username)
	data.Set("password", user.Password)
	data.Set("scope", "openid profile email")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		t.Fatalf("Failed to create token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("Failed to decode token response: %v", err)
	}

	return tokenResp.AccessToken
}

// getClientCredentialsToken obtains service account token
func getClientCredentialsToken(t *testing.T) string {
	t.Helper()

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", keycloakURL, realm)

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("scope", "openid")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		t.Fatalf("Failed to create token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("Failed to decode token response: %v", err)
	}

	return tokenResp.AccessToken
}

// exchangeToken performs token exchange (RFC 8693)
func exchangeToken(t *testing.T, subjectToken, targetAudience string) string {
	t.Helper()

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", keycloakURL, realm)

	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("subject_token", subjectToken)
	data.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	data.Set("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
	data.Set("audience", targetAudience)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		t.Fatalf("Failed to create exchange request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to exchange token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("Failed to decode exchange response: %v", err)
	}

	return tokenResp.AccessToken
}

// makeRequest makes HTTP request to authz-service
func makeRequest(t *testing.T, method, path, token string, body interface{}) (*http.Response, []byte) {
	t.Helper()
	return makeRequestToURL(t, authzURL, method, path, token, body)
}

// makeRequestToURL makes HTTP request to specified base URL
func makeRequestToURL(t *testing.T, baseURL, method, path, token string, body interface{}) (*http.Response, []byte) {
	t.Helper()

	fullURL := baseURL + path

	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("Failed to marshal request body: %v", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Request-ID", fmt.Sprintf("test-%d", time.Now().UnixNano()))

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	respBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	return resp, respBody
}

// assertStatus checks response status code
func assertStatus(t *testing.T, resp *http.Response, expected int) {
	t.Helper()
	if resp.StatusCode != expected {
		t.Errorf("Expected status %d, got %d", expected, resp.StatusCode)
	}
}

// assertStatusOneOf checks response status code is one of expected values
func assertStatusOneOf(t *testing.T, resp *http.Response, expected ...int) {
	t.Helper()
	for _, e := range expected {
		if resp.StatusCode == e {
			return
		}
	}
	t.Errorf("Expected status one of %v, got %d", expected, resp.StatusCode)
}

// waitForService waits for service to be healthy
func waitForService(t *testing.T, healthURL string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, healthURL+"/healthz/ready", nil)
		resp, err := httpClient.Do(req)
		cancel()

		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return
		}
		if resp != nil {
			resp.Body.Close()
		}

		time.Sleep(2 * time.Second)
	}

	t.Fatalf("Service at %s did not become healthy within %v", healthURL, timeout)
}
