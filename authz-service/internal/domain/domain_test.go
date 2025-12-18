package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// TokenInfo Tests
// =============================================================================

func TestTokenInfo_HasRole(t *testing.T) {
	token := &TokenInfo{
		Roles: []string{"admin", "user", "editor"},
	}

	assert.True(t, token.HasRole("admin"))
	assert.True(t, token.HasRole("user"))
	assert.True(t, token.HasRole("editor"))
	assert.False(t, token.HasRole("superadmin"))
	assert.False(t, token.HasRole(""))
}

func TestTokenInfo_HasRole_EmptyRoles(t *testing.T) {
	token := &TokenInfo{}
	assert.False(t, token.HasRole("any"))
}

func TestTokenInfo_HasScope(t *testing.T) {
	token := &TokenInfo{
		Scopes: []string{"read", "write", "admin:read"},
	}

	assert.True(t, token.HasScope("read"))
	assert.True(t, token.HasScope("write"))
	assert.True(t, token.HasScope("admin:read"))
	assert.False(t, token.HasScope("delete"))
}

func TestTokenInfo_HasAnyRole(t *testing.T) {
	token := &TokenInfo{
		Roles: []string{"user", "editor"},
	}

	assert.True(t, token.HasAnyRole("admin", "user"))
	assert.True(t, token.HasAnyRole("editor", "viewer"))
	assert.False(t, token.HasAnyRole("admin", "superadmin"))
}

func TestTokenInfo_HasAnyRole_Empty(t *testing.T) {
	token := &TokenInfo{
		Roles: []string{"user"},
	}

	// No roles to check
	assert.False(t, token.HasAnyRole())
}

func TestTokenInfo_HasAllRoles(t *testing.T) {
	token := &TokenInfo{
		Roles: []string{"admin", "user", "editor"},
	}

	assert.True(t, token.HasAllRoles("admin", "user"))
	assert.True(t, token.HasAllRoles("admin"))
	assert.True(t, token.HasAllRoles()) // Empty list
	assert.False(t, token.HasAllRoles("admin", "superadmin"))
}

func TestTokenInfo_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{
			name:      "expired",
			expiresAt: time.Now().Add(-1 * time.Hour),
			expected:  true,
		},
		{
			name:      "not expired",
			expiresAt: time.Now().Add(1 * time.Hour),
			expected:  false,
		},
		{
			name:      "just expired",
			expiresAt: time.Now().Add(-1 * time.Millisecond),
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &TokenInfo{ExpiresAt: tt.expiresAt}
			assert.Equal(t, tt.expected, token.IsExpired())
		})
	}
}

func TestTokenInfo_TTL(t *testing.T) {
	futureTime := time.Now().Add(1 * time.Hour)
	token := &TokenInfo{ExpiresAt: futureTime}

	ttl := token.TTL()

	// TTL should be approximately 1 hour (allowing for test execution time)
	assert.True(t, ttl > 59*time.Minute)
	assert.True(t, ttl <= 1*time.Hour)
}

func TestTokenInfo_TTL_Expired(t *testing.T) {
	pastTime := time.Now().Add(-1 * time.Hour)
	token := &TokenInfo{ExpiresAt: pastTime}

	ttl := token.TTL()

	// TTL should be negative for expired tokens
	assert.True(t, ttl < 0)
}

func TestTokenInfo_GetExtraClaim(t *testing.T) {
	token := &TokenInfo{
		ExtraClaims: map[string]any{
			"custom_field": "custom_value",
			"number_field": 42,
			"bool_field":   true,
		},
	}

	val, ok := token.GetExtraClaim("custom_field")
	assert.True(t, ok)
	assert.Equal(t, "custom_value", val)

	val, ok = token.GetExtraClaim("number_field")
	assert.True(t, ok)
	assert.Equal(t, 42, val)

	val, ok = token.GetExtraClaim("nonexistent")
	assert.False(t, ok)
	assert.Nil(t, val)
}

func TestTokenInfo_GetExtraClaim_NilMap(t *testing.T) {
	token := &TokenInfo{}

	val, ok := token.GetExtraClaim("any")
	assert.False(t, ok)
	assert.Nil(t, val)
}

// =============================================================================
// Decision Tests
// =============================================================================

func TestDeny(t *testing.T) {
	decision := Deny("reason1", "reason2")

	assert.False(t, decision.Allowed)
	assert.Equal(t, []string{"reason1", "reason2"}, decision.Reasons)
	assert.False(t, decision.EvaluatedAt.IsZero())
}

func TestDeny_NoReasons(t *testing.T) {
	decision := Deny()

	assert.False(t, decision.Allowed)
	assert.Empty(t, decision.Reasons)
}

func TestAllow(t *testing.T) {
	decision := Allow("granted")

	assert.True(t, decision.Allowed)
	assert.Equal(t, []string{"granted"}, decision.Reasons)
	assert.False(t, decision.EvaluatedAt.IsZero())
}

func TestAllow_NoReasons(t *testing.T) {
	decision := Allow()

	assert.True(t, decision.Allowed)
	assert.Empty(t, decision.Reasons)
}

func TestAllowWithHeaders(t *testing.T) {
	headers := map[string]string{
		"X-User-ID": "123",
		"X-Role":    "admin",
	}

	decision := AllowWithHeaders(headers)

	assert.True(t, decision.Allowed)
	assert.Equal(t, headers, decision.HeadersToAdd)
	assert.False(t, decision.EvaluatedAt.IsZero())
}

func TestDecision_WithMetadata(t *testing.T) {
	decision := Allow().
		WithMetadata("rule", "allow-admin").
		WithMetadata("priority", 100)

	require.NotNil(t, decision.Metadata)
	assert.Equal(t, "allow-admin", decision.Metadata["rule"])
	assert.Equal(t, 100, decision.Metadata["priority"])
}

func TestDecision_WithReason(t *testing.T) {
	decision := Deny("initial").WithReason("additional")

	assert.Equal(t, []string{"initial", "additional"}, decision.Reasons)
}

// =============================================================================
// PolicyInput Tests
// =============================================================================

func TestPolicyInput_SetExtension(t *testing.T) {
	input := &PolicyInput{}

	input.SetExtension("agent_id", "agent-123")
	input.SetExtension("delegation", true)

	require.NotNil(t, input.Extensions)
	assert.Equal(t, "agent-123", input.Extensions["agent_id"])
	assert.Equal(t, true, input.Extensions["delegation"])
}

func TestPolicyInput_GetExtension(t *testing.T) {
	input := &PolicyInput{
		Extensions: map[string]any{
			"key1": "value1",
		},
	}

	val, ok := input.GetExtension("key1")
	assert.True(t, ok)
	assert.Equal(t, "value1", val)

	val, ok = input.GetExtension("nonexistent")
	assert.False(t, ok)
	assert.Nil(t, val)
}

func TestPolicyInput_GetExtension_NilMap(t *testing.T) {
	input := &PolicyInput{}

	val, ok := input.GetExtension("any")
	assert.False(t, ok)
	assert.Nil(t, val)
}

func TestPolicyInput_SetResource(t *testing.T) {
	input := &PolicyInput{}
	resource := &ResourceInfo{
		Type:   "users",
		ID:     "123",
		Action: "read",
	}

	input.SetResource(resource)

	assert.Equal(t, resource, input.Resource)
}

// =============================================================================
// DeriveActionFromMethod Tests
// =============================================================================

func TestDeriveActionFromMethod(t *testing.T) {
	tests := []struct {
		method   string
		expected string
	}{
		{"GET", "read"},
		{"POST", "create"},
		{"PUT", "update"},
		{"PATCH", "update"},
		{"DELETE", "delete"},
		{"HEAD", "read"},
		{"OPTIONS", "options"},
		{"CUSTOM", "unknown"},
		{"", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			result := DeriveActionFromMethod(tt.method)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkTokenInfo_HasRole(b *testing.B) {
	token := &TokenInfo{
		Roles: []string{"admin", "user", "editor", "viewer", "moderator"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		token.HasRole("moderator") // Last element
	}
}

func BenchmarkTokenInfo_HasAnyRole(b *testing.B) {
	token := &TokenInfo{
		Roles: []string{"admin", "user", "editor"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		token.HasAnyRole("viewer", "moderator", "editor")
	}
}

func BenchmarkTokenInfo_HasAllRoles(b *testing.B) {
	token := &TokenInfo{
		Roles: []string{"admin", "user", "editor"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		token.HasAllRoles("admin", "user")
	}
}

func BenchmarkDeny(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Deny("access denied", "insufficient permissions")
	}
}

func BenchmarkAllow(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Allow("granted")
	}
}

func BenchmarkDecision_WithMetadata(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Allow().WithMetadata("rule", "test").WithMetadata("priority", 100)
	}
}

func BenchmarkDeriveActionFromMethod(b *testing.B) {
	methods := []string{"GET", "POST", "PUT", "DELETE"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DeriveActionFromMethod(methods[i%len(methods)])
	}
}

func BenchmarkPolicyInput_SetExtension(b *testing.B) {
	input := &PolicyInput{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		input.SetExtension("key", "value")
	}
}
