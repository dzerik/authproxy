package jwt

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/your-org/authz-service/internal/config"
)

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
