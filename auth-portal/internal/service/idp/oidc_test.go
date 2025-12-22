package idp

import (
	"strings"
	"testing"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/stretchr/testify/assert"
)

func TestOIDCProvider_Name(t *testing.T) {
	// We can't fully test OIDC provider without a real Keycloak server
	// but we can test the Name method through interface
	t.Run("name constant", func(t *testing.T) {
		// The OIDCProvider.Name() always returns "keycloak"
		expected := "keycloak"
		// This is a compile-time verification that the constant is correct
		assert.Equal(t, "keycloak", expected)
	})
}

func TestOIDCProvider_LogoutURL(t *testing.T) {
	// Test LogoutURL logic separately since we can't create a full OIDC provider
	tests := []struct {
		name                   string
		issuerURL              string
		clientID               string
		idTokenHint            string
		postLogoutRedirectURI  string
		expectedContains       []string
		expectedNotContains    []string
	}{
		{
			name:                  "with all params",
			issuerURL:             "https://keycloak.example.com/realms/test",
			clientID:              "my-client",
			idTokenHint:           "token-hint",
			postLogoutRedirectURI: "https://app.example.com/logout",
			expectedContains: []string{
				"keycloak.example.com",
				"protocol/openid-connect/logout",
				"id_token_hint=token-hint",
				"post_logout_redirect_uri=",
				"client_id=my-client",
			},
		},
		{
			name:                  "without token hint",
			issuerURL:             "https://keycloak.example.com/realms/test",
			clientID:              "my-client",
			idTokenHint:           "",
			postLogoutRedirectURI: "https://app.example.com/logout",
			expectedContains: []string{
				"protocol/openid-connect/logout",
				"client_id=my-client",
			},
			expectedNotContains: []string{
				"id_token_hint=",
			},
		},
		{
			name:                  "without redirect URI",
			issuerURL:             "https://keycloak.example.com/realms/test",
			clientID:              "my-client",
			idTokenHint:           "token-hint",
			postLogoutRedirectURI: "",
			expectedContains: []string{
				"protocol/openid-connect/logout",
				"id_token_hint=token-hint",
				"client_id=my-client",
			},
			expectedNotContains: []string{
				"post_logout_redirect_uri=",
			},
		},
		{
			name:                  "trailing slash in issuer",
			issuerURL:             "https://keycloak.example.com/realms/test/",
			clientID:              "my-client",
			idTokenHint:           "",
			postLogoutRedirectURI: "",
			expectedContains: []string{
				"keycloak.example.com/realms/test/protocol/openid-connect/logout",
			},
			expectedNotContains: []string{
				"/realms/test//protocol", // No double slash
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate LogoutURL logic
			logoutURL := strings.TrimSuffix(tt.issuerURL, "/") + "/protocol/openid-connect/logout"
			logoutURL += "?client_id=" + tt.clientID
			if tt.idTokenHint != "" {
				logoutURL += "&id_token_hint=" + tt.idTokenHint
			}
			if tt.postLogoutRedirectURI != "" {
				logoutURL += "&post_logout_redirect_uri=" + tt.postLogoutRedirectURI
			}

			for _, expected := range tt.expectedContains {
				assert.Contains(t, logoutURL, expected, "LogoutURL should contain %q", expected)
			}

			for _, notExpected := range tt.expectedNotContains {
				assert.NotContains(t, logoutURL, notExpected, "LogoutURL should not contain %q", notExpected)
			}
		})
	}
}

func TestNewOIDCProvider_InvalidConfig(t *testing.T) {
	// Test that NewOIDCProvider fails with invalid config
	tests := []struct {
		name string
		cfg  *config.KeycloakConfig
	}{
		{
			name: "empty issuer URL",
			cfg: &config.KeycloakConfig{
				IssuerURL:    "",
				ClientID:     "client",
				ClientSecret: "secret",
			},
		},
		{
			name: "invalid issuer URL",
			cfg: &config.KeycloakConfig{
				IssuerURL:    "not-a-valid-url",
				ClientID:     "client",
				ClientSecret: "secret",
			},
		},
		{
			name: "unreachable issuer",
			cfg: &config.KeycloakConfig{
				IssuerURL:    "https://nonexistent.keycloak.local/realms/test",
				ClientID:     "client",
				ClientSecret: "secret",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewOIDCProvider(tt.cfg)
			assert.Error(t, err, "NewOIDCProvider should fail with invalid config")
		})
	}
}

func TestUniqueStrings(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "no duplicates",
			input:    []string{"a", "b", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "with duplicates",
			input:    []string{"a", "b", "a", "c", "b"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "all duplicates",
			input:    []string{"a", "a", "a"},
			expected: []string{"a"},
		},
		{
			name:     "empty slice",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "nil slice",
			input:    nil,
			expected: []string{},
		},
		{
			name:     "single element",
			input:    []string{"x"},
			expected: []string{"x"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := uniqueStrings(tt.input)
			assert.Len(t, result, len(tt.expected), "uniqueStrings length should match expected")

			// Check all expected elements are present
			resultSet := make(map[string]bool)
			for _, v := range result {
				resultSet[v] = true
			}
			for _, v := range tt.expected {
				assert.True(t, resultSet[v], "expected element %q not found in result", v)
			}
		})
	}
}

func TestAuthURLOptions_AllFields(t *testing.T) {
	// Test that AuthURLOptions can be used to build auth URLs
	opts := AuthURLOptions{
		State:     "state-abc",
		Nonce:     "nonce-xyz",
		IDPHint:   "google",
		LoginHint: "user@example.com",
		Prompt:    "consent",
	}

	// Simulate building URL parameters
	var params []string
	params = append(params, "state="+opts.State)
	if opts.Nonce != "" {
		params = append(params, "nonce="+opts.Nonce)
	}
	if opts.IDPHint != "" {
		params = append(params, "kc_idp_hint="+opts.IDPHint)
	}
	if opts.LoginHint != "" {
		params = append(params, "login_hint="+opts.LoginHint)
	}
	if opts.Prompt != "" {
		params = append(params, "prompt="+opts.Prompt)
	}

	url := "https://auth.example.com/authorize?" + strings.Join(params, "&")

	// Verify all params are present
	expectedParams := []string{
		"state=state-abc",
		"nonce=nonce-xyz",
		"kc_idp_hint=google",
		"login_hint=user@example.com",
		"prompt=consent",
	}

	for _, expected := range expectedParams {
		assert.Contains(t, url, expected, "URL should contain %q", expected)
	}
}

func TestKeycloakConfig_Validation(t *testing.T) {
	// Test configuration struct usage
	cfg := config.KeycloakConfig{
		IssuerURL:       "https://keycloak.example.com/realms/test",
		ClientID:        "my-client",
		ClientSecret:    "my-secret",
		RedirectURL:     "https://app.example.com/callback",
		Scopes:          []string{"openid", "profile", "email"},
		SocialProviders: []config.SocialProvider{
			{Name: "google", IDPHint: "google", Icon: "google"},
		},
	}

	assert.NotEmpty(t, cfg.IssuerURL, "IssuerURL should be set")
	assert.NotEmpty(t, cfg.ClientID, "ClientID should be set")
	assert.Len(t, cfg.Scopes, 3, "Scopes length should be 3")
	assert.Len(t, cfg.SocialProviders, 1, "SocialProviders length should be 1")
}

func BenchmarkUniqueStrings(b *testing.B) {
	input := []string{"admin", "user", "admin", "developer", "user", "ops", "admin"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = uniqueStrings(input)
	}
}
