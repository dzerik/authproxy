package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/your-org/authz-service/internal/config"
	authzErrors "github.com/your-org/authz-service/pkg/errors"
)

// =============================================================================
// Mock KeyProvider
// =============================================================================

type mockKeyProvider struct {
	key    jwk.Key
	err    error
	called int
}

func (m *mockKeyProvider) GetKey(ctx context.Context, issuerURL, keyID string) (jwk.Key, error) {
	m.called++
	return m.key, m.err
}

// newTestKeyPair generates an RSA key pair and returns JWK key for testing.
func newTestKeyPair(t *testing.T, kid string) (*rsa.PrivateKey, jwk.Key) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwkKey, err := jwk.FromRaw(privateKey.Public())
	require.NoError(t, err)
	require.NoError(t, jwkKey.Set(jwk.KeyIDKey, kid))
	require.NoError(t, jwkKey.Set(jwk.AlgorithmKey, "RS256"))
	require.NoError(t, jwkKey.Set(jwk.KeyUsageKey, "sig"))

	return privateKey, jwkKey
}

// createTestToken creates a signed JWT token for testing.
func createTestToken(t *testing.T, privateKey *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err)
	return tokenString
}

func TestNewValidator(t *testing.T) {
	jwtConfig := config.JWTConfig{
		Issuers: []config.IssuerConfig{
			{
				IssuerURL:  "https://auth.example.com",
				JWKSURL:    "https://auth.example.com/.well-known/jwks.json",
				Algorithms: []string{"RS256", "ES256"},
			},
		},
	}

	validator := NewValidator(nil, jwtConfig)

	require.NotNil(t, validator)
	assert.Len(t, validator.issuers, 1)
	assert.Contains(t, validator.issuers, "https://auth.example.com")
	assert.True(t, validator.allowedAlgos["RS256"])
	assert.True(t, validator.allowedAlgos["ES256"])
}

func TestNewValidator_DefaultAlgorithms(t *testing.T) {
	jwtConfig := config.JWTConfig{
		Issuers: []config.IssuerConfig{
			{
				IssuerURL: "https://auth.example.com",
				// No algorithms specified
			},
		},
	}

	validator := NewValidator(nil, jwtConfig)

	// Should have default algorithms
	assert.True(t, validator.allowedAlgos["RS256"])
	assert.True(t, validator.allowedAlgos["RS384"])
	assert.True(t, validator.allowedAlgos["RS512"])
	assert.True(t, validator.allowedAlgos["ES256"])
	assert.True(t, validator.allowedAlgos["ES384"])
	assert.True(t, validator.allowedAlgos["ES512"])
}

func TestNewValidator_MultipleIssuers(t *testing.T) {
	jwtConfig := config.JWTConfig{
		Issuers: []config.IssuerConfig{
			{
				IssuerURL:  "https://auth1.example.com",
				Algorithms: []string{"RS256"},
			},
			{
				IssuerURL:  "https://auth2.example.com",
				Algorithms: []string{"ES256"},
			},
		},
	}

	validator := NewValidator(nil, jwtConfig)

	assert.Len(t, validator.issuers, 2)
	assert.True(t, validator.allowedAlgos["RS256"])
	assert.True(t, validator.allowedAlgos["ES256"])
}

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestGetStringClaim(t *testing.T) {
	claims := jwt.MapClaims{
		"sub":       "user123",
		"client_id": "app1",
		"azp":       "app2",
		"number":    123,
	}

	tests := []struct {
		name     string
		keys     []string
		expected string
	}{
		{"single key exists", []string{"sub"}, "user123"},
		{"first key of multiple exists", []string{"client_id", "azp"}, "app1"},
		{"second key of multiple exists", []string{"missing", "azp"}, "app2"},
		{"key not found", []string{"nonexistent"}, ""},
		{"non-string value", []string{"number"}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getStringClaim(claims, tt.keys...)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetTimeClaim(t *testing.T) {
	now := time.Now().Unix()

	tests := []struct {
		name     string
		claims   jwt.MapClaims
		key      string
		expected bool // whether time should be valid (non-zero)
	}{
		{
			name:     "float64 value",
			claims:   jwt.MapClaims{"exp": float64(now)},
			key:      "exp",
			expected: true,
		},
		{
			name:     "json.Number value",
			claims:   jwt.MapClaims{"exp": json.Number("1234567890")},
			key:      "exp",
			expected: true,
		},
		{
			name:     "missing key",
			claims:   jwt.MapClaims{},
			key:      "exp",
			expected: false,
		},
		{
			name:     "invalid type",
			claims:   jwt.MapClaims{"exp": "invalid"},
			key:      "exp",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getTimeClaim(tt.claims, tt.key)
			if tt.expected {
				assert.False(t, result.IsZero())
			} else {
				assert.True(t, result.IsZero())
			}
		})
	}
}

func TestGetAudienceClaim(t *testing.T) {
	tests := []struct {
		name     string
		claims   jwt.MapClaims
		expected []string
	}{
		{
			name:     "string audience",
			claims:   jwt.MapClaims{"aud": "api.example.com"},
			expected: []string{"api.example.com"},
		},
		{
			name:     "array audience",
			claims:   jwt.MapClaims{"aud": []interface{}{"api1.example.com", "api2.example.com"}},
			expected: []string{"api1.example.com", "api2.example.com"},
		},
		{
			name:     "missing audience",
			claims:   jwt.MapClaims{},
			expected: nil,
		},
		{
			name:     "invalid type",
			claims:   jwt.MapClaims{"aud": 123},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getAudienceClaim(tt.claims)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHasValidAudience(t *testing.T) {
	tests := []struct {
		name        string
		tokenAud    []string
		expectedAud []string
		expected    bool
	}{
		{
			name:        "matching audience",
			tokenAud:    []string{"api.example.com"},
			expectedAud: []string{"api.example.com"},
			expected:    true,
		},
		{
			name:        "one of multiple matches",
			tokenAud:    []string{"api1.example.com", "api2.example.com"},
			expectedAud: []string{"api2.example.com"},
			expected:    true,
		},
		{
			name:        "no match",
			tokenAud:    []string{"api.example.com"},
			expectedAud: []string{"other.example.com"},
			expected:    false,
		},
		{
			name:        "empty token audience",
			tokenAud:    []string{},
			expectedAud: []string{"api.example.com"},
			expected:    false,
		},
		{
			name:        "empty expected audience",
			tokenAud:    []string{"api.example.com"},
			expectedAud: []string{},
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasValidAudience(tt.tokenAud, tt.expectedAud)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractRoles(t *testing.T) {
	tests := []struct {
		name     string
		claims   jwt.MapClaims
		expected []string
	}{
		{
			name: "realm_access roles",
			claims: jwt.MapClaims{
				"realm_access": map[string]interface{}{
					"roles": []interface{}{"admin", "user"},
				},
			},
			expected: []string{"admin", "user"},
		},
		{
			name: "resource_access roles",
			claims: jwt.MapClaims{
				"resource_access": map[string]interface{}{
					"my-app": map[string]interface{}{
						"roles": []interface{}{"app-admin"},
					},
				},
			},
			expected: []string{"my-app:app-admin"},
		},
		{
			name: "direct roles claim",
			claims: jwt.MapClaims{
				"roles": []interface{}{"role1", "role2"},
			},
			expected: []string{"role1", "role2"},
		},
		{
			name: "combined roles",
			claims: jwt.MapClaims{
				"realm_access": map[string]interface{}{
					"roles": []interface{}{"admin"},
				},
				"resource_access": map[string]interface{}{
					"app1": map[string]interface{}{
						"roles": []interface{}{"manager"},
					},
				},
				"roles": []interface{}{"direct-role"},
			},
			expected: []string{"admin", "app1:manager", "direct-role"},
		},
		{
			name:     "no roles",
			claims:   jwt.MapClaims{},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractRoles(tt.claims)
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}

func TestExtractScopes(t *testing.T) {
	tests := []struct {
		name     string
		claims   jwt.MapClaims
		expected []string
	}{
		{
			name:     "space-separated scope string",
			claims:   jwt.MapClaims{"scope": "openid profile email"},
			expected: []string{"openid", "profile", "email"},
		},
		{
			name:     "scp array claim",
			claims:   jwt.MapClaims{"scp": []interface{}{"read", "write"}},
			expected: []string{"read", "write"},
		},
		{
			name:     "no scope",
			claims:   jwt.MapClaims{},
			expected: nil,
		},
		{
			name:     "empty scope string",
			claims:   jwt.MapClaims{"scope": ""},
			expected: []string{""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractScopes(tt.claims)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkGetStringClaim(b *testing.B) {
	claims := jwt.MapClaims{
		"sub":       "user123",
		"client_id": "app1",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		getStringClaim(claims, "client_id", "azp")
	}
}

func BenchmarkExtractRoles(b *testing.B) {
	claims := jwt.MapClaims{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"admin", "user", "manager"},
		},
		"resource_access": map[string]interface{}{
			"app1": map[string]interface{}{
				"roles": []interface{}{"read", "write"},
			},
			"app2": map[string]interface{}{
				"roles": []interface{}{"admin"},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extractRoles(claims)
	}
}

func BenchmarkExtractScopes(b *testing.B) {
	claims := jwt.MapClaims{
		"scope": "openid profile email offline_access",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extractScopes(claims)
	}
}

func BenchmarkHasValidAudience(b *testing.B) {
	tokenAud := []string{"api1.example.com", "api2.example.com", "api3.example.com"}
	expectedAud := []string{"api4.example.com", "api3.example.com"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hasValidAudience(tokenAud, expectedAud)
	}
}

// =============================================================================
// Validate Method Tests
// =============================================================================

func TestValidator_Validate_Success(t *testing.T) {
	ctx := context.Background()
	kid := "test-key-1"
	issuerURL := "https://auth.example.com"

	privateKey, jwkKey := newTestKeyPair(t, kid)

	mockProvider := &mockKeyProvider{key: jwkKey}

	jwtConfig := config.JWTConfig{
		Issuers: []config.IssuerConfig{
			{
				IssuerURL:  issuerURL,
				Algorithms: []string{"RS256"},
			},
		},
	}

	validator := NewValidator(mockProvider, jwtConfig)

	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   issuerURL,
		"sub":   "user123",
		"aud":   []string{"api.example.com"},
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"nbf":   now.Unix(),
		"jti":   "token-id-123",
		"scope": "openid profile email",
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"admin", "user"},
		},
	}

	tokenString := createTestToken(t, privateKey, kid, claims)

	tokenInfo, err := validator.Validate(ctx, tokenString)
	require.NoError(t, err)
	require.NotNil(t, tokenInfo)

	assert.True(t, tokenInfo.Valid)
	assert.Equal(t, "user123", tokenInfo.Subject)
	assert.Equal(t, issuerURL, tokenInfo.Issuer)
	assert.Equal(t, "token-id-123", tokenInfo.JTI)
	assert.ElementsMatch(t, []string{"admin", "user"}, tokenInfo.Roles)
	assert.ElementsMatch(t, []string{"openid", "profile", "email"}, tokenInfo.Scopes)
	assert.Equal(t, tokenString, tokenInfo.Raw)
	assert.Equal(t, 1, mockProvider.called)
}

func TestValidator_Validate_ExpiredToken(t *testing.T) {
	ctx := context.Background()
	kid := "test-key-1"
	issuerURL := "https://auth.example.com"

	privateKey, jwkKey := newTestKeyPair(t, kid)
	mockProvider := &mockKeyProvider{key: jwkKey}

	jwtConfig := config.JWTConfig{
		Issuers: []config.IssuerConfig{
			{
				IssuerURL:  issuerURL,
				Algorithms: []string{"RS256"},
			},
		},
		Validation: config.ValidationConfig{
			RequireExpiration: true,
		},
	}

	validator := NewValidator(mockProvider, jwtConfig)

	// Create an expired token
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": issuerURL,
		"sub": "user123",
		"exp": now.Add(-time.Hour).Unix(), // Expired 1 hour ago
		"iat": now.Add(-2 * time.Hour).Unix(),
	}

	tokenString := createTestToken(t, privateKey, kid, claims)

	tokenInfo, err := validator.Validate(ctx, tokenString)
	assert.Nil(t, tokenInfo)
	assert.Error(t, err)

	var authzErr *authzErrors.AuthzError
	require.True(t, errors.As(err, &authzErr))
	assert.Equal(t, authzErrors.CodeTokenExpired, authzErr.Code)
}

func TestValidator_Validate_InvalidIssuer(t *testing.T) {
	ctx := context.Background()
	kid := "test-key-1"

	privateKey, jwkKey := newTestKeyPair(t, kid)
	mockProvider := &mockKeyProvider{key: jwkKey}

	jwtConfig := config.JWTConfig{
		Issuers: []config.IssuerConfig{
			{
				IssuerURL:  "https://trusted.example.com",
				Algorithms: []string{"RS256"},
			},
		},
	}

	validator := NewValidator(mockProvider, jwtConfig)

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": "https://untrusted.example.com", // Not in trusted issuers
		"sub": "user123",
		"exp": now.Add(time.Hour).Unix(),
	}

	tokenString := createTestToken(t, privateKey, kid, claims)

	tokenInfo, err := validator.Validate(ctx, tokenString)
	assert.Nil(t, tokenInfo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "untrusted issuer")
}

func TestValidator_Validate_MissingIssuer(t *testing.T) {
	ctx := context.Background()
	kid := "test-key-1"

	privateKey, jwkKey := newTestKeyPair(t, kid)
	mockProvider := &mockKeyProvider{key: jwkKey}

	jwtConfig := config.JWTConfig{
		Issuers: []config.IssuerConfig{
			{
				IssuerURL:  "https://auth.example.com",
				Algorithms: []string{"RS256"},
			},
		},
	}

	validator := NewValidator(mockProvider, jwtConfig)

	now := time.Now()
	claims := jwt.MapClaims{
		"sub": "user123",
		"exp": now.Add(time.Hour).Unix(),
		// No "iss" claim
	}

	tokenString := createTestToken(t, privateKey, kid, claims)

	tokenInfo, err := validator.Validate(ctx, tokenString)
	assert.Nil(t, tokenInfo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing issuer")
}

func TestValidator_Validate_MissingKeyID(t *testing.T) {
	ctx := context.Background()
	issuerURL := "https://auth.example.com"

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mockProvider := &mockKeyProvider{}

	jwtConfig := config.JWTConfig{
		Issuers: []config.IssuerConfig{
			{
				IssuerURL:  issuerURL,
				Algorithms: []string{"RS256"},
			},
		},
	}

	validator := NewValidator(mockProvider, jwtConfig)

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": issuerURL,
		"sub": "user123",
		"exp": now.Add(time.Hour).Unix(),
	}

	// Create token without kid in header
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// Don't set kid: token.Header["kid"] = kid
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err)

	tokenInfo, err := validator.Validate(ctx, tokenString)
	assert.Nil(t, tokenInfo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing key ID")
}

func TestValidator_Validate_DisallowedAlgorithm(t *testing.T) {
	ctx := context.Background()
	kid := "test-key-1"
	issuerURL := "https://auth.example.com"

	privateKey, jwkKey := newTestKeyPair(t, kid)
	mockProvider := &mockKeyProvider{key: jwkKey}

	jwtConfig := config.JWTConfig{
		Issuers: []config.IssuerConfig{
			{
				IssuerURL:  issuerURL,
				Algorithms: []string{"ES256"}, // Only ES256 allowed, but we sign with RS256
			},
		},
	}

	validator := NewValidator(mockProvider, jwtConfig)

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": issuerURL,
		"sub": "user123",
		"exp": now.Add(time.Hour).Unix(),
	}

	tokenString := createTestToken(t, privateKey, kid, claims)

	tokenInfo, err := validator.Validate(ctx, tokenString)
	assert.Nil(t, tokenInfo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "algorithm")
	assert.Contains(t, err.Error(), "not allowed")
}

func TestValidator_Validate_KeyProviderError(t *testing.T) {
	ctx := context.Background()
	kid := "test-key-1"
	issuerURL := "https://auth.example.com"

	privateKey, _ := newTestKeyPair(t, kid)
	mockProvider := &mockKeyProvider{
		key: nil,
		err: errors.New("key not found"),
	}

	jwtConfig := config.JWTConfig{
		Issuers: []config.IssuerConfig{
			{
				IssuerURL:  issuerURL,
				Algorithms: []string{"RS256"},
			},
		},
	}

	validator := NewValidator(mockProvider, jwtConfig)

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": issuerURL,
		"sub": "user123",
		"exp": now.Add(time.Hour).Unix(),
	}

	tokenString := createTestToken(t, privateKey, kid, claims)

	tokenInfo, err := validator.Validate(ctx, tokenString)
	assert.Nil(t, tokenInfo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signing key")
}

func TestValidator_Validate_InvalidSignature(t *testing.T) {
	ctx := context.Background()
	kid := "test-key-1"
	issuerURL := "https://auth.example.com"

	// Create two different key pairs - sign with one, validate with another
	signingKey, _ := newTestKeyPair(t, kid)
	_, validationJWK := newTestKeyPair(t, kid) // Different key!

	mockProvider := &mockKeyProvider{key: validationJWK}

	jwtConfig := config.JWTConfig{
		Issuers: []config.IssuerConfig{
			{
				IssuerURL:  issuerURL,
				Algorithms: []string{"RS256"},
			},
		},
	}

	validator := NewValidator(mockProvider, jwtConfig)

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": issuerURL,
		"sub": "user123",
		"exp": now.Add(time.Hour).Unix(),
	}

	tokenString := createTestToken(t, signingKey, kid, claims)

	tokenInfo, err := validator.Validate(ctx, tokenString)
	assert.Nil(t, tokenInfo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature")
}

func TestValidator_Validate_TokenNotYetValid(t *testing.T) {
	ctx := context.Background()
	kid := "test-key-1"
	issuerURL := "https://auth.example.com"

	privateKey, jwkKey := newTestKeyPair(t, kid)
	mockProvider := &mockKeyProvider{key: jwkKey}

	jwtConfig := config.JWTConfig{
		Issuers: []config.IssuerConfig{
			{
				IssuerURL:  issuerURL,
				Algorithms: []string{"RS256"},
			},
		},
	}

	validator := NewValidator(mockProvider, jwtConfig)

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": issuerURL,
		"sub": "user123",
		"exp": now.Add(2 * time.Hour).Unix(),
		"nbf": now.Add(time.Hour).Unix(), // Not valid for another hour
	}

	tokenString := createTestToken(t, privateKey, kid, claims)

	tokenInfo, err := validator.Validate(ctx, tokenString)
	assert.Nil(t, tokenInfo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not yet valid")
}

func TestValidator_Validate_AudienceValidation(t *testing.T) {
	ctx := context.Background()
	kid := "test-key-1"
	issuerURL := "https://auth.example.com"

	privateKey, jwkKey := newTestKeyPair(t, kid)
	mockProvider := &mockKeyProvider{key: jwkKey}

	jwtConfig := config.JWTConfig{
		Issuers: []config.IssuerConfig{
			{
				IssuerURL:  issuerURL,
				Algorithms: []string{"RS256"},
				Audience:   []string{"expected-audience"},
			},
		},
	}

	validator := NewValidator(mockProvider, jwtConfig)

	t.Run("valid_audience", func(t *testing.T) {
		mockProvider.called = 0
		now := time.Now()
		claims := jwt.MapClaims{
			"iss": issuerURL,
			"sub": "user123",
			"aud": "expected-audience",
			"exp": now.Add(time.Hour).Unix(),
		}

		tokenString := createTestToken(t, privateKey, kid, claims)

		tokenInfo, err := validator.Validate(ctx, tokenString)
		require.NoError(t, err)
		require.NotNil(t, tokenInfo)
		assert.Equal(t, []string{"expected-audience"}, tokenInfo.Audience)
	})

	t.Run("invalid_audience", func(t *testing.T) {
		mockProvider.called = 0
		now := time.Now()
		claims := jwt.MapClaims{
			"iss": issuerURL,
			"sub": "user123",
			"aud": "wrong-audience",
			"exp": now.Add(time.Hour).Unix(),
		}

		tokenString := createTestToken(t, privateKey, kid, claims)

		tokenInfo, err := validator.Validate(ctx, tokenString)
		assert.Nil(t, tokenInfo)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "audience")
	})
}

func TestValidator_Validate_ExtraClaims(t *testing.T) {
	ctx := context.Background()
	kid := "test-key-1"
	issuerURL := "https://auth.example.com"

	privateKey, jwkKey := newTestKeyPair(t, kid)
	mockProvider := &mockKeyProvider{key: jwkKey}

	jwtConfig := config.JWTConfig{
		Issuers: []config.IssuerConfig{
			{
				IssuerURL:  issuerURL,
				Algorithms: []string{"RS256"},
			},
		},
	}

	validator := NewValidator(mockProvider, jwtConfig)

	now := time.Now()
	claims := jwt.MapClaims{
		"iss":           issuerURL,
		"sub":           "user123",
		"exp":           now.Add(time.Hour).Unix(),
		"custom_claim":  "custom_value",
		"another_claim": 42,
		"nested": map[string]interface{}{
			"key": "value",
		},
	}

	tokenString := createTestToken(t, privateKey, kid, claims)

	tokenInfo, err := validator.Validate(ctx, tokenString)
	require.NoError(t, err)
	require.NotNil(t, tokenInfo)

	assert.Equal(t, "custom_value", tokenInfo.ExtraClaims["custom_claim"])
	assert.EqualValues(t, 42, tokenInfo.ExtraClaims["another_claim"])
	assert.NotNil(t, tokenInfo.ExtraClaims["nested"])
}

func TestValidator_Validate_ClockSkewTolerance(t *testing.T) {
	ctx := context.Background()
	kid := "test-key-1"
	issuerURL := "https://auth.example.com"

	privateKey, jwkKey := newTestKeyPair(t, kid)
	mockProvider := &mockKeyProvider{key: jwkKey}

	jwtConfig := config.JWTConfig{
		Issuers: []config.IssuerConfig{
			{
				IssuerURL:  issuerURL,
				Algorithms: []string{"RS256"},
			},
		},
		Validation: config.ValidationConfig{
			ClockSkew: 5 * time.Minute, // Allow 5 minute skew
		},
	}

	validator := NewValidator(mockProvider, jwtConfig)

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": issuerURL,
		"sub": "user123",
		"exp": now.Add(-2 * time.Minute).Unix(), // Expired 2 minutes ago but within 5 min skew
		"iat": now.Add(-time.Hour).Unix(),
	}

	tokenString := createTestToken(t, privateKey, kid, claims)

	// Should succeed because of clock skew tolerance
	tokenInfo, err := validator.Validate(ctx, tokenString)
	require.NoError(t, err)
	require.NotNil(t, tokenInfo)
}

func TestValidator_Validate_MalformedToken(t *testing.T) {
	ctx := context.Background()
	mockProvider := &mockKeyProvider{}

	jwtConfig := config.JWTConfig{
		Issuers: []config.IssuerConfig{
			{
				IssuerURL:  "https://auth.example.com",
				Algorithms: []string{"RS256"},
			},
		},
	}

	validator := NewValidator(mockProvider, jwtConfig)

	tests := []struct {
		name  string
		token string
	}{
		{"empty_token", ""},
		{"garbage", "not.a.valid.jwt"},
		{"only_header", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"},
		{"header_and_payload", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenInfo, err := validator.Validate(ctx, tt.token)
			assert.Nil(t, tokenInfo)
			assert.Error(t, err)
		})
	}
}

// =============================================================================
// Validate Method Benchmarks
// =============================================================================

func BenchmarkValidator_Validate(b *testing.B) {
	ctx := context.Background()
	kid := "test-key-1"
	issuerURL := "https://auth.example.com"

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}

	jwkKey, err := jwk.FromRaw(privateKey.Public())
	if err != nil {
		b.Fatal(err)
	}
	_ = jwkKey.Set(jwk.KeyIDKey, kid)
	_ = jwkKey.Set(jwk.AlgorithmKey, "RS256")

	mockProvider := &mockKeyProvider{key: jwkKey}

	jwtConfig := config.JWTConfig{
		Issuers: []config.IssuerConfig{
			{
				IssuerURL:  issuerURL,
				Algorithms: []string{"RS256"},
			},
		},
	}

	validator := NewValidator(mockProvider, jwtConfig)

	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   issuerURL,
		"sub":   "user123",
		"aud":   []string{"api.example.com"},
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"scope": "openid profile",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = validator.Validate(ctx, tokenString)
	}
}
