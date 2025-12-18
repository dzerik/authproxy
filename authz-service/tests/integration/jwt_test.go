package integration

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/your-org/authz-service/internal/config"
	jwtservice "github.com/your-org/authz-service/internal/service/jwt"
)

func TestJWTService_ValidateToken_Success(t *testing.T) {
	// Generate test key pair
	keyPair, err := NewTestKeyPair()
	require.NoError(t, err)

	// Start mock JWKS server
	server := MockJWKSServer(t, keyPair)
	defer server.Close()

	// Create JWT service
	cfg := config.JWTConfig{
		Issuers: []config.IssuerConfig{
			{
				IssuerURL:  server.URL,
				JWKSURL:    server.URL + "/.well-known/jwks.json",
				Audience:   []string{"authz-service"},
				Algorithms: []string{"RS256"},
			},
		},
		Validation: config.ValidationConfig{ClockSkew: 30 * time.Second},
	}

	svc := jwtservice.NewService(cfg)
	ctx := NewTestContext(t)

	err = svc.Start(ctx)
	require.NoError(t, err)
	defer svc.Stop()

	// Create valid token
	claims := NewTestClaims(server.URL, "user-123", []string{"admin", "user"}, []string{"read", "write"})
	token, err := keyPair.SignToken(claims)
	require.NoError(t, err)

	// Validate token
	tokenInfo, err := svc.ValidateToken(ctx, token)
	require.NoError(t, err)
	assert.True(t, tokenInfo.Valid)
	assert.Equal(t, "user-123", tokenInfo.Subject)
	assert.Equal(t, server.URL, tokenInfo.Issuer)
	assert.Contains(t, tokenInfo.Roles, "admin")
	assert.Contains(t, tokenInfo.Roles, "user")
	assert.Contains(t, tokenInfo.Scopes, "read")
	assert.Contains(t, tokenInfo.Scopes, "write")
}

func TestJWTService_ValidateToken_ExpiredToken(t *testing.T) {
	keyPair, err := NewTestKeyPair()
	require.NoError(t, err)

	server := MockJWKSServer(t, keyPair)
	defer server.Close()

	cfg := config.JWTConfig{
		Issuers: []config.IssuerConfig{
			{
				IssuerURL:  server.URL,
				JWKSURL:    server.URL + "/.well-known/jwks.json",
				Audience:   []string{"authz-service"},
				Algorithms: []string{"RS256"},
			},
		},
	}

	svc := jwtservice.NewService(cfg)
	ctx := NewTestContext(t)
	require.NoError(t, svc.Start(ctx))
	defer svc.Stop()

	// Create expired token
	claims := jwt.MapClaims{
		"iss": server.URL,
		"sub": "user-123",
		"aud": []string{"authz-service"},
		"exp": time.Now().Add(-time.Hour).Unix(), // Expired
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
	}

	token, err := keyPair.SignToken(claims)
	require.NoError(t, err)

	// Should fail validation
	_, err = svc.ValidateToken(ctx, token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestJWTService_ValidateToken_WrongAudience(t *testing.T) {
	keyPair, err := NewTestKeyPair()
	require.NoError(t, err)

	server := MockJWKSServer(t, keyPair)
	defer server.Close()

	cfg := config.JWTConfig{
		Issuers: []config.IssuerConfig{
			{
				IssuerURL:  server.URL,
				JWKSURL:    server.URL + "/.well-known/jwks.json",
				Audience:   []string{"authz-service"},
				Algorithms: []string{"RS256"},
			},
		},
	}

	svc := jwtservice.NewService(cfg)
	ctx := NewTestContext(t)
	require.NoError(t, svc.Start(ctx))
	defer svc.Stop()

	// Create token with wrong audience
	claims := jwt.MapClaims{
		"iss": server.URL,
		"sub": "user-123",
		"aud": []string{"other-service"}, // Wrong audience
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}

	token, err := keyPair.SignToken(claims)
	require.NoError(t, err)

	_, err = svc.ValidateToken(ctx, token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "audience")
}

func TestJWTService_ValidateToken_UnknownIssuer(t *testing.T) {
	keyPair, err := NewTestKeyPair()
	require.NoError(t, err)

	server := MockJWKSServer(t, keyPair)
	defer server.Close()

	cfg := config.JWTConfig{
		Issuers: []config.IssuerConfig{
			{
				IssuerURL:  server.URL,
				JWKSURL:    server.URL + "/.well-known/jwks.json",
				Audience:   []string{"authz-service"},
				Algorithms: []string{"RS256"},
			},
		},
	}

	svc := jwtservice.NewService(cfg)
	ctx := NewTestContext(t)
	require.NoError(t, svc.Start(ctx))
	defer svc.Stop()

	// Create token with unknown issuer
	claims := jwt.MapClaims{
		"iss": "https://unknown-issuer.com",
		"sub": "user-123",
		"aud": []string{"authz-service"},
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}

	token, err := keyPair.SignToken(claims)
	require.NoError(t, err)

	_, err = svc.ValidateToken(ctx, token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "issuer")
}

func TestJWTService_ValidateToken_WithAgentClaims(t *testing.T) {
	keyPair, err := NewTestKeyPair()
	require.NoError(t, err)

	server := MockJWKSServer(t, keyPair)
	defer server.Close()

	cfg := config.JWTConfig{
		Issuers: []config.IssuerConfig{
			{
				IssuerURL:  server.URL,
				JWKSURL:    server.URL + "/.well-known/jwks.json",
				Audience:   []string{"authz-service"},
				Algorithms: []string{"RS256"},
			},
		},
	}

	svc := jwtservice.NewService(cfg)
	ctx := NewTestContext(t)
	require.NoError(t, svc.Start(ctx))
	defer svc.Stop()

	// Create agent token
	claims := NewAgentClaims(server.URL, "agent-001", "gpt-4")
	token, err := keyPair.SignToken(claims)
	require.NoError(t, err)

	tokenInfo, err := svc.ValidateToken(ctx, token)
	require.NoError(t, err)
	assert.True(t, tokenInfo.Valid)
	assert.Equal(t, "agent-001", tokenInfo.Subject)

	// Check extra claims
	agentType, ok := tokenInfo.GetExtraClaim("agent_type")
	assert.True(t, ok)
	assert.Equal(t, "llm_agent", agentType)

	agentModel, ok := tokenInfo.GetExtraClaim("agent_model")
	assert.True(t, ok)
	assert.Equal(t, "gpt-4", agentModel)
}

func TestJWTService_ValidateToken_WithDelegation(t *testing.T) {
	keyPair, err := NewTestKeyPair()
	require.NoError(t, err)

	server := MockJWKSServer(t, keyPair)
	defer server.Close()

	cfg := config.JWTConfig{
		Issuers: []config.IssuerConfig{
			{
				IssuerURL:  server.URL,
				JWKSURL:    server.URL + "/.well-known/jwks.json",
				Audience:   []string{"authz-service"},
				Algorithms: []string{"RS256"},
			},
		},
	}

	svc := jwtservice.NewService(cfg)
	ctx := NewTestContext(t)
	require.NoError(t, svc.Start(ctx))
	defer svc.Stop()

	// Create delegated token
	claims := NewDelegatedClaims(server.URL, "user-123", "agent-001")
	token, err := keyPair.SignToken(claims)
	require.NoError(t, err)

	tokenInfo, err := svc.ValidateToken(ctx, token)
	require.NoError(t, err)
	assert.True(t, tokenInfo.Valid)
	assert.Equal(t, "user-123", tokenInfo.Subject)

	// Check act claim
	actClaim, ok := tokenInfo.GetExtraClaim("act")
	assert.True(t, ok)
	assert.NotNil(t, actClaim)

	actMap, ok := actClaim.(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, "agent-001", actMap["sub"])
}

func TestJWTService_JWKS_Refresh(t *testing.T) {
	keyPair1, err := NewTestKeyPair()
	require.NoError(t, err)
	keyPair1.KeyID = "key-1"

	keyPair2, err := NewTestKeyPair()
	require.NoError(t, err)
	keyPair2.KeyID = "key-2"

	// Start with first key pair
	currentKeyPair := keyPair1
	server := MockJWKSServer(t, currentKeyPair)
	defer server.Close()

	cfg := config.JWTConfig{
		Issuers: []config.IssuerConfig{
			{
				IssuerURL:  server.URL,
				JWKSURL:    server.URL + "/.well-known/jwks.json",
				Audience:   []string{"authz-service"},
				Algorithms: []string{"RS256"},
			},
		},
		JWKSCache: config.JWKSCacheConfig{RefreshInterval: 100 * time.Millisecond}, // Short refresh for testing
	}

	svc := jwtservice.NewService(cfg)
	ctx := NewTestContext(t)
	require.NoError(t, svc.Start(ctx))
	defer svc.Stop()

	// Validate with first key
	claims := NewTestClaims(server.URL, "user-123", []string{"user"}, []string{"read"})
	token1, err := keyPair1.SignToken(claims)
	require.NoError(t, err)

	tokenInfo, err := svc.ValidateToken(ctx, token1)
	require.NoError(t, err)
	assert.True(t, tokenInfo.Valid)
}

func TestJWTService_MultipleIssuers(t *testing.T) {
	keyPair1, err := NewTestKeyPair()
	require.NoError(t, err)
	keyPair1.KeyID = "issuer1-key"

	keyPair2, err := NewTestKeyPair()
	require.NoError(t, err)
	keyPair2.KeyID = "issuer2-key"

	server1 := MockJWKSServer(t, keyPair1)
	defer server1.Close()

	server2 := MockJWKSServer(t, keyPair2)
	defer server2.Close()

	cfg := config.JWTConfig{
		Issuers: []config.IssuerConfig{
			{
				IssuerURL:  server1.URL,
				JWKSURL:    server1.URL + "/.well-known/jwks.json",
				Audience:   []string{"authz-service"},
				Algorithms: []string{"RS256"},
			},
			{
				IssuerURL:  server2.URL,
				JWKSURL:    server2.URL + "/.well-known/jwks.json",
				Audience:   []string{"authz-service"},
				Algorithms: []string{"RS256"},
			},
		},
	}

	svc := jwtservice.NewService(cfg)
	ctx := NewTestContext(t)
	require.NoError(t, svc.Start(ctx))
	defer svc.Stop()

	// Token from issuer 1
	claims1 := NewTestClaims(server1.URL, "user-from-issuer1", []string{"user"}, []string{"read"})
	token1, err := keyPair1.SignToken(claims1)
	require.NoError(t, err)

	tokenInfo1, err := svc.ValidateToken(ctx, token1)
	require.NoError(t, err)
	assert.True(t, tokenInfo1.Valid)
	assert.Equal(t, "user-from-issuer1", tokenInfo1.Subject)

	// Token from issuer 2
	claims2 := NewTestClaims(server2.URL, "user-from-issuer2", []string{"admin"}, []string{"write"})
	token2, err := keyPair2.SignToken(claims2)
	require.NoError(t, err)

	tokenInfo2, err := svc.ValidateToken(ctx, token2)
	require.NoError(t, err)
	assert.True(t, tokenInfo2.Valid)
	assert.Equal(t, "user-from-issuer2", tokenInfo2.Subject)
}
