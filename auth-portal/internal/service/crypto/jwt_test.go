package crypto

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewJWTManager_HS256(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		cfg := JWTConfig{
			Algorithm:  "HS256",
			SigningKey: "test-secret-key-for-testing-1234",
			Issuer:     "test-issuer",
		}

		m, err := NewJWTManager(cfg)
		require.NoError(t, err)
		require.NotNil(t, m)
		assert.Equal(t, "HS256", m.algorithm)
	})

	t.Run("empty algorithm defaults to HS256", func(t *testing.T) {
		cfg := JWTConfig{
			Algorithm:  "",
			SigningKey: "test-key",
		}

		m, err := NewJWTManager(cfg)
		require.NoError(t, err)
		assert.Equal(t, "HS256", m.algorithm)
	})

	t.Run("missing signing key", func(t *testing.T) {
		cfg := JWTConfig{
			Algorithm:  "HS256",
			SigningKey: "",
		}

		_, err := NewJWTManager(cfg)
		assert.Equal(t, ErrMissingKey, err)
	})
}

func TestNewJWTManager_RS256(t *testing.T) {
	t.Run("missing keys", func(t *testing.T) {
		cfg := JWTConfig{
			Algorithm: "RS256",
		}

		_, err := NewJWTManager(cfg)
		assert.Equal(t, ErrMissingKey, err)
	})

	t.Run("invalid private key path", func(t *testing.T) {
		cfg := JWTConfig{
			Algorithm:  "RS256",
			PrivateKey: "/nonexistent/path/private.pem",
		}

		_, err := NewJWTManager(cfg)
		assert.Error(t, err, "expected error for nonexistent private key")
	})

	t.Run("invalid public key path", func(t *testing.T) {
		cfg := JWTConfig{
			Algorithm: "RS256",
			PublicKey: "/nonexistent/path/public.pem",
		}

		_, err := NewJWTManager(cfg)
		assert.Error(t, err, "expected error for nonexistent public key")
	})
}

func TestNewJWTManager_InvalidAlgorithm(t *testing.T) {
	cfg := JWTConfig{
		Algorithm:  "INVALID",
		SigningKey: "key",
	}

	_, err := NewJWTManager(cfg)
	assert.Equal(t, ErrInvalidAlgorithm, err)
}

func TestJWTManager_SignVerify_HS256(t *testing.T) {
	cfg := JWTConfig{
		Algorithm:  "HS256",
		SigningKey: "test-secret-key-for-testing-1234",
		Issuer:     "test-issuer",
	}

	m, err := NewJWTManager(cfg)
	require.NoError(t, err)

	claims := CreateSessionClaims(
		"session-123",
		"user-456",
		"user@example.com",
		"Test User",
		[]string{"admin", "user"},
		[]string{"group1", "group2"},
		time.Hour,
	)

	// Sign
	token, err := m.Sign(claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Verify
	verifiedClaims, err := m.Verify(token)
	require.NoError(t, err)

	assert.Equal(t, "user-456", verifiedClaims.UserID)
	assert.Equal(t, "user@example.com", verifiedClaims.Email)
	assert.Equal(t, "Test User", verifiedClaims.Name)
	assert.Len(t, verifiedClaims.Roles, 2)
	assert.Len(t, verifiedClaims.Groups, 2)
	assert.Equal(t, "test-issuer", verifiedClaims.Issuer)
}

func TestJWTManager_Sign_SetsIssuer(t *testing.T) {
	cfg := JWTConfig{
		Algorithm:  "HS256",
		SigningKey: "test-key",
		Issuer:     "default-issuer",
	}

	m, err := NewJWTManager(cfg)
	require.NoError(t, err)

	// Claims without issuer should get issuer from manager
	claims := &SessionClaims{
		UserID: "user-1",
	}

	token, err := m.Sign(claims)
	require.NoError(t, err)

	verified, err := m.Verify(token)
	require.NoError(t, err)

	assert.Equal(t, "default-issuer", verified.Issuer)
}

func TestJWTManager_Verify_InvalidToken(t *testing.T) {
	cfg := JWTConfig{
		Algorithm:  "HS256",
		SigningKey: "test-key",
	}

	m, err := NewJWTManager(cfg)
	require.NoError(t, err)

	t.Run("malformed token", func(t *testing.T) {
		_, err := m.Verify("not-a-valid-jwt")
		assert.Error(t, err, "expected error for malformed token")
	})

	t.Run("wrong signature", func(t *testing.T) {
		// Create a token with a different key
		otherCfg := JWTConfig{
			Algorithm:  "HS256",
			SigningKey: "different-key",
		}
		otherManager, _ := NewJWTManager(otherCfg)

		claims := &SessionClaims{UserID: "user-1"}
		token, _ := otherManager.Sign(claims)

		// Try to verify with original manager (different key)
		_, err := m.Verify(token)
		assert.Error(t, err, "expected error for wrong signature")
	})

	t.Run("expired token", func(t *testing.T) {
		claims := &SessionClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)), // expired 1 hour ago
			},
			UserID: "user-1",
		}

		token, _ := m.Sign(claims)
		_, err := m.Verify(token)
		assert.Equal(t, ErrTokenExpired, err)
	})
}

func TestCreateSessionClaims(t *testing.T) {
	sessionID := "sess-123"
	userID := "user-456"
	email := "test@example.com"
	name := "Test User"
	roles := []string{"admin"}
	groups := []string{"team-a"}
	ttl := 2 * time.Hour

	claims := CreateSessionClaims(sessionID, userID, email, name, roles, groups, ttl)

	assert.Equal(t, sessionID, claims.ID)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, email, claims.Email)
	assert.Equal(t, name, claims.Name)
	assert.Len(t, claims.Roles, 1)
	assert.Equal(t, "admin", claims.Roles[0])
	assert.Len(t, claims.Groups, 1)
	assert.Equal(t, "team-a", claims.Groups[0])
	assert.NotNil(t, claims.IssuedAt)
	assert.NotNil(t, claims.ExpiresAt)
	assert.NotNil(t, claims.NotBefore)

	// Check TTL is approximately correct
	expectedExpiry := time.Now().Add(ttl)
	actualExpiry := claims.ExpiresAt.Time
	assert.WithinDuration(t, expectedExpiry, actualExpiry, time.Second)
}

func TestSessionClaims_TenantID(t *testing.T) {
	claims := &SessionClaims{
		UserID:   "user-1",
		TenantID: "tenant-abc",
	}

	assert.Equal(t, "tenant-abc", claims.TenantID)
}

func TestJWTConfig(t *testing.T) {
	cfg := JWTConfig{
		Algorithm:  "HS256",
		SigningKey: "my-key",
		PrivateKey: "/path/to/private.pem",
		PublicKey:  "/path/to/public.pem",
		Issuer:     "my-issuer",
	}

	assert.Equal(t, "HS256", cfg.Algorithm)
	assert.Equal(t, "my-key", cfg.SigningKey)
	assert.Equal(t, "/path/to/private.pem", cfg.PrivateKey)
	assert.Equal(t, "/path/to/public.pem", cfg.PublicKey)
	assert.Equal(t, "my-issuer", cfg.Issuer)
}

func TestJWTErrors(t *testing.T) {
	t.Run("ErrInvalidToken", func(t *testing.T) {
		assert.NotEmpty(t, ErrInvalidToken.Error())
	})

	t.Run("ErrTokenExpired", func(t *testing.T) {
		assert.NotEmpty(t, ErrTokenExpired.Error())
	})

	t.Run("ErrInvalidAlgorithm", func(t *testing.T) {
		assert.NotEmpty(t, ErrInvalidAlgorithm.Error())
	})

	t.Run("ErrMissingKey", func(t *testing.T) {
		assert.NotEmpty(t, ErrMissingKey.Error())
	})
}

func BenchmarkSign_HS256(b *testing.B) {
	cfg := JWTConfig{
		Algorithm:  "HS256",
		SigningKey: "test-secret-key-for-benchmarking",
	}
	m, _ := NewJWTManager(cfg)
	claims := CreateSessionClaims("sess", "user", "email", "name", nil, nil, time.Hour)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.Sign(claims)
	}
}

func BenchmarkVerify_HS256(b *testing.B) {
	cfg := JWTConfig{
		Algorithm:  "HS256",
		SigningKey: "test-secret-key-for-benchmarking",
	}
	m, _ := NewJWTManager(cfg)
	claims := CreateSessionClaims("sess", "user", "email", "name", nil, nil, time.Hour)
	token, _ := m.Sign(claims)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.Verify(token)
	}
}
