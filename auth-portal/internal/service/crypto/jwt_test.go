package crypto

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestNewJWTManager_HS256(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		cfg := JWTConfig{
			Algorithm:  "HS256",
			SigningKey: "test-secret-key-for-testing-1234",
			Issuer:     "test-issuer",
		}

		m, err := NewJWTManager(cfg)
		if err != nil {
			t.Fatalf("NewJWTManager failed: %v", err)
		}
		if m == nil {
			t.Fatal("NewJWTManager returned nil")
		}
		if m.algorithm != "HS256" {
			t.Errorf("algorithm = %s, want HS256", m.algorithm)
		}
	})

	t.Run("empty algorithm defaults to HS256", func(t *testing.T) {
		cfg := JWTConfig{
			Algorithm:  "",
			SigningKey: "test-key",
		}

		m, err := NewJWTManager(cfg)
		if err != nil {
			t.Fatalf("NewJWTManager failed: %v", err)
		}
		if m.algorithm != "HS256" {
			t.Errorf("algorithm = %s, want HS256", m.algorithm)
		}
	})

	t.Run("missing signing key", func(t *testing.T) {
		cfg := JWTConfig{
			Algorithm:  "HS256",
			SigningKey: "",
		}

		_, err := NewJWTManager(cfg)
		if err != ErrMissingKey {
			t.Errorf("expected ErrMissingKey, got %v", err)
		}
	})
}

func TestNewJWTManager_RS256(t *testing.T) {
	t.Run("missing keys", func(t *testing.T) {
		cfg := JWTConfig{
			Algorithm: "RS256",
		}

		_, err := NewJWTManager(cfg)
		if err != ErrMissingKey {
			t.Errorf("expected ErrMissingKey, got %v", err)
		}
	})

	t.Run("invalid private key path", func(t *testing.T) {
		cfg := JWTConfig{
			Algorithm:  "RS256",
			PrivateKey: "/nonexistent/path/private.pem",
		}

		_, err := NewJWTManager(cfg)
		if err == nil {
			t.Error("expected error for nonexistent private key")
		}
	})

	t.Run("invalid public key path", func(t *testing.T) {
		cfg := JWTConfig{
			Algorithm: "RS256",
			PublicKey: "/nonexistent/path/public.pem",
		}

		_, err := NewJWTManager(cfg)
		if err == nil {
			t.Error("expected error for nonexistent public key")
		}
	})
}

func TestNewJWTManager_InvalidAlgorithm(t *testing.T) {
	cfg := JWTConfig{
		Algorithm:  "INVALID",
		SigningKey: "key",
	}

	_, err := NewJWTManager(cfg)
	if err != ErrInvalidAlgorithm {
		t.Errorf("expected ErrInvalidAlgorithm, got %v", err)
	}
}

func TestJWTManager_SignVerify_HS256(t *testing.T) {
	cfg := JWTConfig{
		Algorithm:  "HS256",
		SigningKey: "test-secret-key-for-testing-1234",
		Issuer:     "test-issuer",
	}

	m, err := NewJWTManager(cfg)
	if err != nil {
		t.Fatalf("NewJWTManager failed: %v", err)
	}

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
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if token == "" {
		t.Error("Sign returned empty token")
	}

	// Verify
	verifiedClaims, err := m.Verify(token)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if verifiedClaims.UserID != "user-456" {
		t.Errorf("UserID = %s, want user-456", verifiedClaims.UserID)
	}
	if verifiedClaims.Email != "user@example.com" {
		t.Errorf("Email = %s, want user@example.com", verifiedClaims.Email)
	}
	if verifiedClaims.Name != "Test User" {
		t.Errorf("Name = %s, want Test User", verifiedClaims.Name)
	}
	if len(verifiedClaims.Roles) != 2 {
		t.Errorf("Roles length = %d, want 2", len(verifiedClaims.Roles))
	}
	if len(verifiedClaims.Groups) != 2 {
		t.Errorf("Groups length = %d, want 2", len(verifiedClaims.Groups))
	}
	if verifiedClaims.Issuer != "test-issuer" {
		t.Errorf("Issuer = %s, want test-issuer", verifiedClaims.Issuer)
	}
}

func TestJWTManager_Sign_SetsIssuer(t *testing.T) {
	cfg := JWTConfig{
		Algorithm:  "HS256",
		SigningKey: "test-key",
		Issuer:     "default-issuer",
	}

	m, err := NewJWTManager(cfg)
	if err != nil {
		t.Fatalf("NewJWTManager failed: %v", err)
	}

	// Claims without issuer should get issuer from manager
	claims := &SessionClaims{
		UserID: "user-1",
	}

	token, err := m.Sign(claims)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	verified, err := m.Verify(token)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if verified.Issuer != "default-issuer" {
		t.Errorf("Issuer = %s, want default-issuer", verified.Issuer)
	}
}

func TestJWTManager_Verify_InvalidToken(t *testing.T) {
	cfg := JWTConfig{
		Algorithm:  "HS256",
		SigningKey: "test-key",
	}

	m, err := NewJWTManager(cfg)
	if err != nil {
		t.Fatalf("NewJWTManager failed: %v", err)
	}

	t.Run("malformed token", func(t *testing.T) {
		_, err := m.Verify("not-a-valid-jwt")
		if err == nil {
			t.Error("expected error for malformed token")
		}
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
		if err == nil {
			t.Error("expected error for wrong signature")
		}
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
		if err != ErrTokenExpired {
			t.Errorf("expected ErrTokenExpired, got %v", err)
		}
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

	if claims.ID != sessionID {
		t.Errorf("ID = %s, want %s", claims.ID, sessionID)
	}
	if claims.UserID != userID {
		t.Errorf("UserID = %s, want %s", claims.UserID, userID)
	}
	if claims.Email != email {
		t.Errorf("Email = %s, want %s", claims.Email, email)
	}
	if claims.Name != name {
		t.Errorf("Name = %s, want %s", claims.Name, name)
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != "admin" {
		t.Errorf("Roles = %v, want [admin]", claims.Roles)
	}
	if len(claims.Groups) != 1 || claims.Groups[0] != "team-a" {
		t.Errorf("Groups = %v, want [team-a]", claims.Groups)
	}
	if claims.IssuedAt == nil {
		t.Error("IssuedAt should be set")
	}
	if claims.ExpiresAt == nil {
		t.Error("ExpiresAt should be set")
	}
	if claims.NotBefore == nil {
		t.Error("NotBefore should be set")
	}

	// Check TTL is approximately correct
	expectedExpiry := time.Now().Add(ttl)
	actualExpiry := claims.ExpiresAt.Time
	if actualExpiry.Sub(expectedExpiry) > time.Second {
		t.Errorf("ExpiresAt is incorrect, got %v, want approximately %v", actualExpiry, expectedExpiry)
	}
}

func TestSessionClaims_TenantID(t *testing.T) {
	claims := &SessionClaims{
		UserID:   "user-1",
		TenantID: "tenant-abc",
	}

	if claims.TenantID != "tenant-abc" {
		t.Errorf("TenantID = %s, want tenant-abc", claims.TenantID)
	}
}

func TestJWTConfig(t *testing.T) {
	cfg := JWTConfig{
		Algorithm:  "HS256",
		SigningKey: "my-key",
		PrivateKey: "/path/to/private.pem",
		PublicKey:  "/path/to/public.pem",
		Issuer:     "my-issuer",
	}

	if cfg.Algorithm != "HS256" {
		t.Errorf("Algorithm = %s, want HS256", cfg.Algorithm)
	}
	if cfg.SigningKey != "my-key" {
		t.Errorf("SigningKey = %s, want my-key", cfg.SigningKey)
	}
	if cfg.PrivateKey != "/path/to/private.pem" {
		t.Errorf("PrivateKey = %s, want /path/to/private.pem", cfg.PrivateKey)
	}
	if cfg.PublicKey != "/path/to/public.pem" {
		t.Errorf("PublicKey = %s, want /path/to/public.pem", cfg.PublicKey)
	}
	if cfg.Issuer != "my-issuer" {
		t.Errorf("Issuer = %s, want my-issuer", cfg.Issuer)
	}
}

func TestJWTErrors(t *testing.T) {
	t.Run("ErrInvalidToken", func(t *testing.T) {
		if ErrInvalidToken.Error() == "" {
			t.Error("ErrInvalidToken should have message")
		}
	})

	t.Run("ErrTokenExpired", func(t *testing.T) {
		if ErrTokenExpired.Error() == "" {
			t.Error("ErrTokenExpired should have message")
		}
	})

	t.Run("ErrInvalidAlgorithm", func(t *testing.T) {
		if ErrInvalidAlgorithm.Error() == "" {
			t.Error("ErrInvalidAlgorithm should have message")
		}
	})

	t.Run("ErrMissingKey", func(t *testing.T) {
		if ErrMissingKey.Error() == "" {
			t.Error("ErrMissingKey should have message")
		}
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
