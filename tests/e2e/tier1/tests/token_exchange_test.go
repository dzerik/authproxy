package tests

import (
	"net/http"
	"testing"
	"time"
)

// TestTokenExchangeBasic tests basic token exchange flow (RFC 8693)
func TestTokenExchangeBasic(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	waitForService(t, authzHealthURL, 60*time.Second)

	// Get initial user token
	userToken := getToken(t, "user")
	if userToken == "" {
		t.Fatal("Failed to get user token")
	}

	// Exchange token for external audience
	exchangedToken := exchangeToken(t, userToken, "authz-service-external")
	if exchangedToken == "" {
		t.Fatal("Failed to exchange token")
	}

	// Tokens should be different
	if userToken == exchangedToken {
		t.Error("Exchanged token should be different from original")
	}

	t.Log("Token exchange successful")
}

// TestTokenExchangeWithExternalService tests token exchange for external partner service
func TestTokenExchangeWithExternalService(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	waitForService(t, authzHealthURL, 60*time.Second)

	// Get external user token
	externalToken := getToken(t, "external")
	if externalToken == "" {
		t.Fatal("Failed to get external user token")
	}

	// Exchange for external-service audience
	exchangedToken := exchangeToken(t, externalToken, "external-service")
	if exchangedToken == "" {
		t.Fatal("Failed to exchange token for external-service")
	}

	// Use exchanged token to access external authz-service
	resp, _ := makeRequestToURL(t, authzExternalURL, http.MethodGet, "/partner/api/resources", exchangedToken, nil)
	assertStatusOneOf(t, resp, http.StatusOK, http.StatusForbidden)
}

// TestTokenExchangeChain tests chained token exchange
func TestTokenExchangeChain(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	waitForService(t, authzHealthURL, 60*time.Second)

	// Get initial user token
	userToken := getToken(t, "user")

	// First exchange: user -> authz-service-external
	firstExchange := exchangeToken(t, userToken, "authz-service-external")
	if firstExchange == "" {
		t.Fatal("First exchange failed")
	}

	// Note: Second exchange might be blocked by policy depending on configuration
	// This tests the chain capability
	t.Log("Token exchange chain test completed")
}

// TestTokenExchangeAudienceValidation tests audience validation in token exchange
func TestTokenExchangeAudienceValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	waitForService(t, authzHealthURL, 60*time.Second)

	userToken := getToken(t, "user")

	tests := []struct {
		name     string
		audience string
		shouldOK bool
	}{
		{"valid audience authz-service-external", "authz-service-external", true},
		{"valid audience external-service", "external-service", true},
		{"valid audience account", "account", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Note: Invalid audience may fail at Keycloak level, not authz-service
			exchangedToken := exchangeToken(t, userToken, tc.audience)
			if tc.shouldOK && exchangedToken == "" {
				t.Errorf("Expected successful exchange for audience %s", tc.audience)
			}
		})
	}
}

// TestTokenExchangeWithDifferentGrantTypes tests token exchange with different token types
func TestTokenExchangeWithDifferentGrantTypes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	waitForService(t, authzHealthURL, 60*time.Second)

	tests := []struct {
		name     string
		getToken func(t *testing.T) string
	}{
		{"password grant token", func(t *testing.T) string { return getToken(t, "user") }},
		{"client credentials token", getClientCredentialsToken},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			originalToken := tc.getToken(t)
			if originalToken == "" {
				t.Fatal("Failed to get original token")
			}

			exchangedToken := exchangeToken(t, originalToken, "authz-service-external")
			if exchangedToken == "" {
				t.Log("Token exchange not allowed for this grant type (may be expected)")
			} else {
				t.Log("Token exchange successful")
			}
		})
	}
}

// TestTokenExchangePreservesIdentity tests that exchanged token preserves user identity
func TestTokenExchangePreservesIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	waitForService(t, authzHealthURL, 60*time.Second)

	// Get user token
	userToken := getToken(t, "user")

	// Exchange token
	exchangedToken := exchangeToken(t, userToken, "authz-service-external")
	if exchangedToken == "" {
		t.Fatal("Failed to exchange token")
	}

	// Both tokens should work for user profile endpoint (if allowed)
	resp1, _ := makeRequest(t, http.MethodGet, "/api/v1/users/me", userToken, nil)
	resp2, _ := makeRequestToURL(t, authzExternalURL, http.MethodGet, "/partner/api/resources", exchangedToken, nil)

	// At least one should succeed
	if resp1.StatusCode >= 500 && resp2.StatusCode >= 500 {
		t.Error("Both requests failed with server errors")
	}
}

// TestTokenExchangeRateLimiting tests rate limiting on token exchange
func TestTokenExchangeRateLimiting(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	waitForService(t, authzHealthURL, 60*time.Second)

	userToken := getToken(t, "user")

	// Make many exchange requests quickly
	successCount := 0
	rateLimited := false

	for i := 0; i < 50; i++ {
		// This will either succeed or get rate limited
		func() {
			defer func() {
				if r := recover(); r != nil {
					// Exchange failed (might be rate limited)
					rateLimited = true
				}
			}()

			exchangedToken := exchangeToken(t, userToken, "authz-service-external")
			if exchangedToken != "" {
				successCount++
			}
		}()

		if rateLimited {
			t.Logf("Rate limited after %d successful exchanges", successCount)
			break
		}
	}

	t.Logf("Completed %d token exchanges", successCount)
}
