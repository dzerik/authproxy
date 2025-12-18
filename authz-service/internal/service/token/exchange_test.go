package token

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/your-org/authz-service/internal/domain"
)

func TestNewExchangeService(t *testing.T) {
	cfg := ExchangeConfig{
		TokenURL:     "https://auth.example.com/token",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Timeout:      30 * time.Second,
	}

	svc := NewExchangeService(cfg)

	require.NotNil(t, svc)
	assert.Equal(t, cfg.TokenURL, svc.tokenURL)
	assert.Equal(t, cfg.ClientID, svc.clientID)
	assert.Equal(t, cfg.ClientSecret, svc.clientSecret)
}

func TestNewExchangeService_DefaultTimeout(t *testing.T) {
	cfg := ExchangeConfig{
		TokenURL: "https://auth.example.com/token",
		// No timeout set
	}

	svc := NewExchangeService(cfg)

	require.NotNil(t, svc)
	// Default timeout should be 10 seconds
	assert.Equal(t, 10*time.Second, svc.client.Timeout)
}

func TestExchangeService_Exchange_Success(t *testing.T) {
	expectedResponse := ExchangeResponse{
		AccessToken:     "new-access-token",
		IssuedTokenType: TokenTypeAccessToken,
		TokenType:       "Bearer",
		ExpiresIn:       3600,
		Scope:           "openid profile",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		err := r.ParseForm()
		require.NoError(t, err)

		assert.Equal(t, "urn:ietf:params:oauth:grant-type:token-exchange", r.Form.Get("grant_type"))
		assert.Equal(t, "subject-token", r.Form.Get("subject_token"))
		assert.Equal(t, TokenTypeAccessToken, r.Form.Get("subject_token_type"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(expectedResponse)
	}))
	defer server.Close()

	svc := NewExchangeService(ExchangeConfig{
		TokenURL:     server.URL,
		ClientID:     "client",
		ClientSecret: "secret",
	})

	req := &ExchangeRequest{
		SubjectToken:     "subject-token",
		SubjectTokenType: TokenTypeAccessToken,
	}

	resp, err := svc.Exchange(context.Background(), req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "new-access-token", resp.AccessToken)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Equal(t, 3600, resp.ExpiresIn)
}

func TestExchangeService_Exchange_MissingSubjectToken(t *testing.T) {
	svc := NewExchangeService(ExchangeConfig{
		TokenURL: "https://auth.example.com/token",
	})

	req := &ExchangeRequest{
		SubjectToken: "", // Missing
	}

	resp, err := svc.Exchange(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "subject_token is required")
}

func TestExchangeService_Exchange_DefaultSubjectTokenType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		require.NoError(t, err)

		// Should default to access_token type
		assert.Equal(t, TokenTypeAccessToken, r.Form.Get("subject_token_type"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ExchangeResponse{AccessToken: "token"})
	}))
	defer server.Close()

	svc := NewExchangeService(ExchangeConfig{TokenURL: server.URL})

	req := &ExchangeRequest{
		SubjectToken: "subject-token",
		// SubjectTokenType not set
	}

	_, err := svc.Exchange(context.Background(), req)
	assert.NoError(t, err)
}

func TestExchangeService_Exchange_WithAllParameters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		require.NoError(t, err)

		assert.Equal(t, "subject-token", r.Form.Get("subject_token"))
		assert.Equal(t, TokenTypeAccessToken, r.Form.Get("subject_token_type"))
		assert.Equal(t, "actor-token", r.Form.Get("actor_token"))
		assert.Equal(t, TokenTypeAccessToken, r.Form.Get("actor_token_type"))
		assert.Equal(t, TokenTypeJWT, r.Form.Get("requested_token_type"))
		assert.Equal(t, "https://api.example.com", r.Form.Get("audience"))
		assert.Equal(t, "openid profile", r.Form.Get("scope"))
		assert.Equal(t, "https://resource.example.com", r.Form.Get("resource"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ExchangeResponse{AccessToken: "token"})
	}))
	defer server.Close()

	svc := NewExchangeService(ExchangeConfig{TokenURL: server.URL})

	req := &ExchangeRequest{
		SubjectToken:       "subject-token",
		SubjectTokenType:   TokenTypeAccessToken,
		ActorToken:         "actor-token",
		ActorTokenType:     TokenTypeAccessToken,
		RequestedTokenType: TokenTypeJWT,
		Audience:           "https://api.example.com",
		Scope:              "openid profile",
		Resource:           "https://resource.example.com",
	}

	_, err := svc.Exchange(context.Background(), req)
	assert.NoError(t, err)
}

func TestExchangeService_Exchange_WithBasicAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "client-id", username)
		assert.Equal(t, "client-secret", password)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ExchangeResponse{AccessToken: "token"})
	}))
	defer server.Close()

	svc := NewExchangeService(ExchangeConfig{
		TokenURL:     server.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	})

	req := &ExchangeRequest{SubjectToken: "subject-token"}
	_, err := svc.Exchange(context.Background(), req)
	assert.NoError(t, err)
}

func TestExchangeService_Exchange_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_request",
			"error_description": "The subject_token is invalid",
		})
	}))
	defer server.Close()

	svc := NewExchangeService(ExchangeConfig{TokenURL: server.URL})

	req := &ExchangeRequest{SubjectToken: "invalid-token"}
	resp, err := svc.Exchange(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid_request")
	assert.Contains(t, err.Error(), "The subject_token is invalid")
}

func TestExchangeService_Exchange_ErrorResponseWithoutBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	svc := NewExchangeService(ExchangeConfig{TokenURL: server.URL})

	req := &ExchangeRequest{SubjectToken: "token"}
	resp, err := svc.Exchange(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "500")
}

func TestExchangeService_Exchange_NetworkError(t *testing.T) {
	svc := NewExchangeService(ExchangeConfig{
		TokenURL: "http://localhost:1", // Should fail to connect
		Timeout:  100 * time.Millisecond,
	})

	req := &ExchangeRequest{SubjectToken: "token"}
	resp, err := svc.Exchange(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestExchangeService_ExchangeForAudience(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		require.NoError(t, err)

		assert.Equal(t, "subject-token", r.Form.Get("subject_token"))
		assert.Equal(t, "https://api.example.com", r.Form.Get("audience"))
		assert.Equal(t, TokenTypeAccessToken, r.Form.Get("requested_token_type"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ExchangeResponse{AccessToken: "new-token"})
	}))
	defer server.Close()

	svc := NewExchangeService(ExchangeConfig{TokenURL: server.URL})

	resp, err := svc.ExchangeForAudience(context.Background(), "subject-token", "https://api.example.com")

	require.NoError(t, err)
	assert.Equal(t, "new-token", resp.AccessToken)
}

func TestExchangeService_ExchangeWithDelegation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		require.NoError(t, err)

		assert.Equal(t, "subject-token", r.Form.Get("subject_token"))
		assert.Equal(t, "actor-token", r.Form.Get("actor_token"))
		assert.Equal(t, "https://api.example.com", r.Form.Get("audience"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ExchangeResponse{AccessToken: "delegated-token"})
	}))
	defer server.Close()

	svc := NewExchangeService(ExchangeConfig{TokenURL: server.URL})

	resp, err := svc.ExchangeWithDelegation(context.Background(), "subject-token", "actor-token", "https://api.example.com")

	require.NoError(t, err)
	assert.Equal(t, "delegated-token", resp.AccessToken)
}

func TestExchangeService_Impersonate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		require.NoError(t, err)

		assert.Equal(t, "subject-token", r.Form.Get("subject_token"))
		assert.Equal(t, "actor-token", r.Form.Get("actor_token"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ExchangeResponse{AccessToken: "impersonated-token"})
	}))
	defer server.Close()

	svc := NewExchangeService(ExchangeConfig{TokenURL: server.URL})

	resp, err := svc.Impersonate(context.Background(), "subject-token", "actor-token")

	require.NoError(t, err)
	assert.Equal(t, "impersonated-token", resp.AccessToken)
}

func TestParseDelegationChain_NoActClaim(t *testing.T) {
	token := &domain.TokenInfo{}

	chain := ParseDelegationChain(token)

	assert.Empty(t, chain)
}

func TestParseDelegationChain_SingleActor(t *testing.T) {
	token := &domain.TokenInfo{
		ExtraClaims: map[string]any{
			"act": map[string]any{
				"sub":       "service-account",
				"iss":       "https://auth.example.com",
				"client_id": "service-a",
			},
		},
	}

	chain := ParseDelegationChain(token)

	require.Len(t, chain, 1)
	assert.Equal(t, "service-account", chain[0].Subject)
	assert.Equal(t, "https://auth.example.com", chain[0].Issuer)
	assert.Equal(t, "service-a", chain[0].ClientID)
}

func TestParseDelegationChain_NestedActors(t *testing.T) {
	token := &domain.TokenInfo{
		ExtraClaims: map[string]any{
			"act": map[string]any{
				"sub": "service-b",
				"act": map[string]any{
					"sub": "service-a",
					"act": map[string]any{
						"sub": "original-user",
					},
				},
			},
		},
	}

	chain := ParseDelegationChain(token)

	require.Len(t, chain, 3)
	assert.Equal(t, "service-b", chain[0].Subject)
	assert.Equal(t, "service-a", chain[1].Subject)
	assert.Equal(t, "original-user", chain[2].Subject)
}

func TestParseDelegationChain_InvalidActClaim(t *testing.T) {
	token := &domain.TokenInfo{
		ExtraClaims: map[string]any{
			"act": "invalid-string", // Should be map
		},
	}

	chain := ParseDelegationChain(token)

	assert.Empty(t, chain)
}

func TestTokenTypeConstants(t *testing.T) {
	assert.Equal(t, "urn:ietf:params:oauth:token-type:access_token", TokenTypeAccessToken)
	assert.Equal(t, "urn:ietf:params:oauth:token-type:refresh_token", TokenTypeRefreshToken)
	assert.Equal(t, "urn:ietf:params:oauth:token-type:id_token", TokenTypeIDToken)
	assert.Equal(t, "urn:ietf:params:oauth:token-type:jwt", TokenTypeJWT)
	assert.Equal(t, "urn:ietf:params:oauth:token-type:saml1", TokenTypeSAML1)
	assert.Equal(t, "urn:ietf:params:oauth:token-type:saml2", TokenTypeSAML2)
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkExchangeService_Exchange(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ExchangeResponse{AccessToken: "token"})
	}))
	defer server.Close()

	svc := NewExchangeService(ExchangeConfig{TokenURL: server.URL})
	ctx := context.Background()
	req := &ExchangeRequest{SubjectToken: "token"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		svc.Exchange(ctx, req)
	}
}

func BenchmarkParseDelegationChain(b *testing.B) {
	token := &domain.TokenInfo{
		ExtraClaims: map[string]any{
			"act": map[string]any{
				"sub": "service-b",
				"act": map[string]any{
					"sub": "service-a",
				},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseDelegationChain(token)
	}
}
