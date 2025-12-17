package egress

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/your-org/authz-service/internal/config"
)

func testLogger() *zap.Logger {
	logger, _ := zap.NewDevelopment()
	return logger
}

func TestCredentials_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		creds     *Credentials
		expected  bool
	}{
		{
			name: "not expired",
			creds: &Credentials{
				ExpiresAt: time.Now().Add(time.Hour),
			},
			expected: false,
		},
		{
			name: "expired",
			creds: &Credentials{
				ExpiresAt: time.Now().Add(-time.Hour),
			},
			expected: true,
		},
		{
			name: "no expiry (never expires)",
			creds: &Credentials{
				ExpiresAt: time.Time{},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.creds.IsExpired())
		})
	}
}

func TestCredentials_IsExpiringSoon(t *testing.T) {
	tests := []struct {
		name     string
		creds    *Credentials
		within   time.Duration
		expected bool
	}{
		{
			name: "not expiring soon",
			creds: &Credentials{
				ExpiresAt: time.Now().Add(time.Hour),
			},
			within:   5 * time.Minute,
			expected: false,
		},
		{
			name: "expiring soon",
			creds: &Credentials{
				ExpiresAt: time.Now().Add(3 * time.Minute),
			},
			within:   5 * time.Minute,
			expected: true,
		},
		{
			name: "already expired",
			creds: &Credentials{
				ExpiresAt: time.Now().Add(-time.Minute),
			},
			within:   5 * time.Minute,
			expected: true,
		},
		{
			name: "no expiry",
			creds: &Credentials{
				ExpiresAt: time.Time{},
			},
			within:   5 * time.Minute,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.creds.IsExpiringSoon(tt.within))
		})
	}
}

func TestAPIKeyFetcher(t *testing.T) {
	fetcher := &apiKeyFetcher{
		header: "X-API-Key",
		key:    "test-api-key-123",
	}

	creds, err := fetcher.fetch(context.Background())
	require.NoError(t, err)

	assert.Equal(t, CredentialTypeAPIKey, creds.Type)
	assert.Equal(t, "test-api-key-123", creds.Headers["X-API-Key"])
	assert.True(t, creds.ExpiresAt.IsZero(), "API key should not expire")
}

func TestBasicAuthFetcher(t *testing.T) {
	fetcher := &basicAuthFetcher{
		username: "user",
		password: "pass",
	}

	creds, err := fetcher.fetch(context.Background())
	require.NoError(t, err)

	assert.Equal(t, CredentialTypeBasic, creds.Type)
	assert.Contains(t, creds.Headers["Authorization"], "Basic ")
	// base64("user:pass") = "dXNlcjpwYXNz"
	assert.Equal(t, "Basic dXNlcjpwYXNz", creds.Headers["Authorization"])
}

func TestBearerTokenFetcher(t *testing.T) {
	fetcher := &bearerTokenFetcher{
		token: "my-bearer-token",
	}

	creds, err := fetcher.fetch(context.Background())
	require.NoError(t, err)

	assert.Equal(t, CredentialTypeBearer, creds.Type)
	assert.Equal(t, "my-bearer-token", creds.AccessToken)
	assert.Equal(t, "Bearer my-bearer-token", creds.Headers["Authorization"])
}

func TestNoAuthFetcher(t *testing.T) {
	fetcher := &noAuthFetcher{}

	creds, err := fetcher.fetch(context.Background())
	require.NoError(t, err)

	assert.Equal(t, CredentialTypeNone, creds.Type)
	assert.Empty(t, creds.AccessToken)
	assert.Empty(t, creds.Headers)
}

func TestOAuth2ClientCredentialsFetcher(t *testing.T) {
	// Create a mock OAuth2 token server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		err := r.ParseForm()
		require.NoError(t, err)

		assert.Equal(t, "client_credentials", r.Form.Get("grant_type"))
		assert.Equal(t, "test-client-id", r.Form.Get("client_id"))
		assert.Equal(t, "test-client-secret", r.Form.Get("client_secret"))
		assert.Equal(t, "read write", r.Form.Get("scope"))

		response := oauth2TokenResponse{
			AccessToken: "test-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			Scope:       "read write",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	fetcher := &oauth2ClientCredentialsFetcher{
		name:         "test-target",
		tokenURL:     server.URL,
		clientID:     "test-client-id",
		clientSecret: "test-client-secret",
		scopes:       []string{"read", "write"},
		httpClient:   http.DefaultClient,
		log:          testLogger(),
	}

	creds, err := fetcher.fetch(context.Background())
	require.NoError(t, err)

	assert.Equal(t, CredentialTypeOAuth2, creds.Type)
	assert.Equal(t, "test-access-token", creds.AccessToken)
	assert.Equal(t, "Bearer test-access-token", creds.Headers["Authorization"])
	assert.False(t, creds.ExpiresAt.IsZero())
	assert.True(t, creds.ExpiresAt.After(time.Now()))
}

func TestOAuth2ClientCredentialsFetcher_Error(t *testing.T) {
	// Create a mock server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "invalid_client"}`))
	}))
	defer server.Close()

	fetcher := &oauth2ClientCredentialsFetcher{
		name:         "test-target",
		tokenURL:     server.URL,
		clientID:     "wrong-client-id",
		clientSecret: "wrong-secret",
		httpClient:   http.DefaultClient,
		log:          testLogger(),
	}

	_, err := fetcher.fetch(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestCredentialManager_CreateFetcher(t *testing.T) {
	log := testLogger()
	tokenStore := NewMemoryTokenStore(log)

	cfg := config.EgressConfig{
		Targets: map[string]config.EgressTargetConfig{
			"api-key-target": {
				URL: "https://api.example.com",
				Auth: config.EgressAuthConfig{
					Type:   "api_key",
					Header: "X-API-Key",
					Key:    "secret-key",
				},
			},
			"basic-auth-target": {
				URL: "https://api2.example.com",
				Auth: config.EgressAuthConfig{
					Type:     "basic",
					Username: "user",
					Password: "pass",
				},
			},
			"bearer-target": {
				URL: "https://api3.example.com",
				Auth: config.EgressAuthConfig{
					Type:  "bearer",
					Token: "static-token",
				},
			},
			"no-auth-target": {
				URL: "https://public.example.com",
				Auth: config.EgressAuthConfig{
					Type: "none",
				},
			},
		},
	}

	cm, err := NewCredentialManager(cfg, tokenStore, log)
	require.NoError(t, err)

	// Test that all fetchers were created
	assert.Len(t, cm.providers, 4)

	// Test getting credentials for each target
	ctx := context.Background()

	creds, err := cm.GetCredentials(ctx, "api-key-target")
	require.NoError(t, err)
	assert.Equal(t, CredentialTypeAPIKey, creds.Type)

	creds, err = cm.GetCredentials(ctx, "basic-auth-target")
	require.NoError(t, err)
	assert.Equal(t, CredentialTypeBasic, creds.Type)

	creds, err = cm.GetCredentials(ctx, "bearer-target")
	require.NoError(t, err)
	assert.Equal(t, CredentialTypeBearer, creds.Type)

	creds, err = cm.GetCredentials(ctx, "no-auth-target")
	require.NoError(t, err)
	assert.Equal(t, CredentialTypeNone, creds.Type)
}

func TestCredentialManager_GetCredentials_Caching(t *testing.T) {
	log := testLogger()
	tokenStore := NewMemoryTokenStore(log)

	// Track how many times the OAuth server is called
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		response := oauth2TokenResponse{
			AccessToken: "test-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	cfg := config.EgressConfig{
		Targets: map[string]config.EgressTargetConfig{
			"oauth-target": {
				URL: "https://api.example.com",
				Auth: config.EgressAuthConfig{
					Type:         "oauth2_client_credentials",
					TokenURL:     server.URL,
					ClientID:     "client",
					ClientSecret: "secret",
				},
			},
		},
	}

	cm, err := NewCredentialManager(cfg, tokenStore, log)
	require.NoError(t, err)

	ctx := context.Background()

	// First call - should fetch from server
	_, err = cm.GetCredentials(ctx, "oauth-target")
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	// Second call - should use cache
	_, err = cm.GetCredentials(ctx, "oauth-target")
	require.NoError(t, err)
	assert.Equal(t, 1, callCount, "should use cached credentials")

	// Third call - should still use cache
	_, err = cm.GetCredentials(ctx, "oauth-target")
	require.NoError(t, err)
	assert.Equal(t, 1, callCount, "should still use cached credentials")
}

func TestCredentialManager_UnknownTarget(t *testing.T) {
	log := testLogger()
	tokenStore := NewMemoryTokenStore(log)

	cfg := config.EgressConfig{
		Targets: map[string]config.EgressTargetConfig{},
	}

	cm, err := NewCredentialManager(cfg, tokenStore, log)
	require.NoError(t, err)

	ctx := context.Background()
	_, err = cm.GetCredentials(ctx, "unknown-target")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown target")
}

func TestCredentialManager_UnsupportedAuthType(t *testing.T) {
	log := testLogger()
	tokenStore := NewMemoryTokenStore(log)

	cfg := config.EgressConfig{
		Targets: map[string]config.EgressTargetConfig{
			"bad-target": {
				URL: "https://api.example.com",
				Auth: config.EgressAuthConfig{
					Type: "unsupported-auth-type",
				},
			},
		},
	}

	_, err := NewCredentialManager(cfg, tokenStore, log)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported auth type")
}
