package agent

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/your-org/authz-service/internal/domain"
)

// =============================================================================
// Enhancer Tests
// =============================================================================

func TestNewEnhancer(t *testing.T) {
	cfg := EnhancerConfig{Enabled: true}
	enhancer := NewEnhancer(cfg)

	require.NotNil(t, enhancer)
	assert.True(t, enhancer.enabled)
}

func TestNewEnhancer_Disabled(t *testing.T) {
	cfg := EnhancerConfig{Enabled: false}
	enhancer := NewEnhancer(cfg)

	require.NotNil(t, enhancer)
	assert.False(t, enhancer.enabled)
}

func TestEnhancer_Enhance_Disabled(t *testing.T) {
	enhancer := NewEnhancer(EnhancerConfig{Enabled: false})
	input := &domain.PolicyInput{
		Token: &domain.TokenInfo{Subject: "user123"},
	}

	err := enhancer.Enhance(context.Background(), input)

	assert.NoError(t, err)
	// No extensions should be set when disabled
	_, ok := input.GetExtension("agent")
	assert.False(t, ok)
}

func TestEnhancer_Enhance_NoToken(t *testing.T) {
	enhancer := NewEnhancer(EnhancerConfig{Enabled: true})
	input := &domain.PolicyInput{
		Token: nil,
	}

	err := enhancer.Enhance(context.Background(), input)

	assert.NoError(t, err)
	// No extensions should be set without token
	_, ok := input.GetExtension("agent")
	assert.False(t, ok)
}

func TestEnhancer_Enhance_BasicToken(t *testing.T) {
	enhancer := NewEnhancer(EnhancerConfig{Enabled: true})
	input := &domain.PolicyInput{
		Token: &domain.TokenInfo{
			Subject:  "user123",
			ClientID: "web-app",
			Scopes:   []string{"openid", "profile"},
		},
	}

	err := enhancer.Enhance(context.Background(), input)

	assert.NoError(t, err)

	agentExt, ok := input.GetExtension("agent")
	require.True(t, ok)

	agent, ok := agentExt.(*AgentInfo)
	require.True(t, ok)
	assert.Equal(t, "user123", agent.ID)
	assert.Equal(t, AgentTypeHuman, agent.Type)
	assert.Contains(t, agent.Permissions, "openid")
	assert.Contains(t, agent.Permissions, "profile")
}

func TestEnhancer_Enhance_AgentTypeFromClaim(t *testing.T) {
	enhancer := NewEnhancer(EnhancerConfig{Enabled: true})
	input := &domain.PolicyInput{
		Token: &domain.TokenInfo{
			Subject: "agent-123",
			ExtraClaims: map[string]any{
				"agent_type": "llm_agent",
			},
		},
	}

	err := enhancer.Enhance(context.Background(), input)

	assert.NoError(t, err)

	agentExt, _ := input.GetExtension("agent")
	agent := agentExt.(*AgentInfo)
	assert.Equal(t, AgentTypeLLM, agent.Type)
}

func TestEnhancer_Enhance_AgentClientID(t *testing.T) {
	tests := []struct {
		name       string
		clientID   string
		expectType AgentType
	}{
		{"agent prefix", "agent-service-1", AgentTypeLLM},
		{"bot prefix", "bot-helper", AgentTypeLLM},
		{"llm prefix", "llm-assistant", AgentTypeLLM},
		{"ai prefix", "ai-agent", AgentTypeLLM},
		{"normal client", "web-app", AgentTypeHuman},
		{"uppercase agent", "AGENT-SERVICE", AgentTypeLLM},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enhancer := NewEnhancer(EnhancerConfig{Enabled: true})
			input := &domain.PolicyInput{
				Token: &domain.TokenInfo{
					Subject:  "user",
					ClientID: tt.clientID,
				},
			}

			err := enhancer.Enhance(context.Background(), input)
			assert.NoError(t, err)

			agentExt, _ := input.GetExtension("agent")
			agent := agentExt.(*AgentInfo)
			assert.Equal(t, tt.expectType, agent.Type)
		})
	}
}

func TestEnhancer_Enhance_AgentMetadata(t *testing.T) {
	enhancer := NewEnhancer(EnhancerConfig{Enabled: true})
	input := &domain.PolicyInput{
		Token: &domain.TokenInfo{
			Subject: "agent-123",
			ExtraClaims: map[string]any{
				"agent_name":     "Claude Assistant",
				"agent_model":    "claude-3-opus",
				"agent_provider": "anthropic",
				"session_id":     "session-456",
			},
		},
	}

	err := enhancer.Enhance(context.Background(), input)

	assert.NoError(t, err)

	agentExt, _ := input.GetExtension("agent")
	agent := agentExt.(*AgentInfo)
	assert.Equal(t, "Claude Assistant", agent.Name)
	assert.Equal(t, "claude-3-opus", agent.Model)
	assert.Equal(t, "anthropic", agent.Provider)
	assert.Equal(t, "session-456", agent.SessionID)
}

func TestEnhancer_Enhance_DelegationChain(t *testing.T) {
	enhancer := NewEnhancer(EnhancerConfig{Enabled: true})
	input := &domain.PolicyInput{
		Token: &domain.TokenInfo{
			Subject: "service-b",
			ExtraClaims: map[string]any{
				"act": map[string]any{
					"sub":       "service-a",
					"iss":       "https://auth.example.com",
					"client_id": "service-a-client",
					"act": map[string]any{
						"sub": "original-user",
					},
				},
			},
		},
	}

	err := enhancer.Enhance(context.Background(), input)

	assert.NoError(t, err)

	// Check agent type is Service (due to delegation chain)
	agentTypeExt, ok := input.GetExtension("agent_type")
	assert.True(t, ok)
	assert.Equal(t, "service", agentTypeExt)

	// Check delegation chain
	chainExt, ok := input.GetExtension("delegation_chain")
	require.True(t, ok)
	chain := chainExt.([]DelegationInfo)
	assert.Len(t, chain, 2)
	assert.Equal(t, "service-a", chain[0].Subject)
	assert.Equal(t, "https://auth.example.com", chain[0].Issuer)
	assert.Equal(t, "original-user", chain[1].Subject)

	// Check delegation depth
	depthExt, ok := input.GetExtension("delegation_depth")
	assert.True(t, ok)
	assert.Equal(t, 2, depthExt)
}

func TestEnhancer_Enhance_AgentConstraints(t *testing.T) {
	enhancer := NewEnhancer(EnhancerConfig{Enabled: true})
	input := &domain.PolicyInput{
		Token: &domain.TokenInfo{
			Subject: "agent-123",
			ExtraClaims: map[string]any{
				"agent_constraints": map[string]any{
					"max_actions_per_minute": float64(60),
					"require_human_approval": true,
					"max_tokens_per_request": float64(1000),
					"allowed_resources":      []any{"/api/v1/*", "/api/v2/read"},
					"denied_resources":       []any{"/admin/*"},
					"allowed_operations":     []any{"read", "list"},
				},
			},
		},
	}

	err := enhancer.Enhance(context.Background(), input)

	assert.NoError(t, err)

	agentExt, _ := input.GetExtension("agent")
	agent := agentExt.(*AgentInfo)

	require.NotNil(t, agent.Constraints)
	assert.Equal(t, 60, agent.Constraints.MaxActionsPerMinute)
	assert.True(t, agent.Constraints.RequireHumanApproval)
	assert.Equal(t, 1000, agent.Constraints.MaxTokensPerRequest)
	assert.Contains(t, agent.Constraints.AllowedResources, "/api/v1/*")
	assert.Contains(t, agent.Constraints.DeniedResources, "/admin/*")
	assert.Contains(t, agent.Constraints.AllowedOperations, "read")
}

func TestEnhancer_Enhance_Permissions(t *testing.T) {
	enhancer := NewEnhancer(EnhancerConfig{Enabled: true})
	input := &domain.PolicyInput{
		Token: &domain.TokenInfo{
			Subject: "user123",
			Scopes:  []string{"openid", "profile"},
			ExtraClaims: map[string]any{
				"permissions": []any{"users:read", "users:write"},
			},
		},
	}

	err := enhancer.Enhance(context.Background(), input)

	assert.NoError(t, err)

	agentExt, _ := input.GetExtension("agent")
	agent := agentExt.(*AgentInfo)

	// Should include both scopes and custom permissions
	assert.Contains(t, agent.Permissions, "openid")
	assert.Contains(t, agent.Permissions, "profile")
	assert.Contains(t, agent.Permissions, "users:read")
	assert.Contains(t, agent.Permissions, "users:write")
}

// =============================================================================
// ValidateAgentAccess Tests
// =============================================================================

func TestValidateAgentAccess_NilAgent(t *testing.T) {
	err := ValidateAgentAccess(nil, "/api/users", "read")
	assert.NoError(t, err)
}

func TestValidateAgentAccess_NilConstraints(t *testing.T) {
	agent := &AgentInfo{
		ID:          "agent-123",
		Constraints: nil,
	}

	err := ValidateAgentAccess(agent, "/api/users", "read")
	assert.NoError(t, err)
}

func TestValidateAgentAccess_DeniedResource(t *testing.T) {
	agent := &AgentInfo{
		ID: "agent-123",
		Constraints: &AgentConstraints{
			DeniedResources: []string{"/admin/*"},
		},
	}

	err := ValidateAgentAccess(agent, "/admin/users", "read")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "denied")
}

func TestValidateAgentAccess_AllowedResource(t *testing.T) {
	agent := &AgentInfo{
		ID: "agent-123",
		Constraints: &AgentConstraints{
			AllowedResources: []string{"/api/*"},
		},
	}

	// Allowed resource
	err := ValidateAgentAccess(agent, "/api/users", "read")
	assert.NoError(t, err)

	// Not in allowed list
	err = ValidateAgentAccess(agent, "/admin/users", "read")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not in allowed list")
}

func TestValidateAgentAccess_AllowedOperations(t *testing.T) {
	agent := &AgentInfo{
		ID: "agent-123",
		Constraints: &AgentConstraints{
			AllowedOperations: []string{"read", "list"},
		},
	}

	// Allowed operation
	err := ValidateAgentAccess(agent, "/api/users", "read")
	assert.NoError(t, err)

	// Not allowed operation
	err = ValidateAgentAccess(agent, "/api/users", "delete")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not allowed")
}

func TestValidateAgentAccess_WildcardOperation(t *testing.T) {
	agent := &AgentInfo{
		ID: "agent-123",
		Constraints: &AgentConstraints{
			AllowedOperations: []string{"*"},
		},
	}

	err := ValidateAgentAccess(agent, "/api/users", "delete")
	assert.NoError(t, err)
}

func TestValidateAgentAccess_DeniedTakesPrecedence(t *testing.T) {
	agent := &AgentInfo{
		ID: "agent-123",
		Constraints: &AgentConstraints{
			AllowedResources: []string{"/api/*"},
			DeniedResources:  []string{"/api/admin/*"},
		},
	}

	// Denied even though parent is allowed
	err := ValidateAgentAccess(agent, "/api/admin/users", "read")
	assert.Error(t, err)
}

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestIsAgentClientID(t *testing.T) {
	tests := []struct {
		clientID string
		expected bool
	}{
		{"agent-service", true},
		{"Agent-Service", true},
		{"AGENT-SERVICE", true},
		{"bot-helper", true},
		{"llm-assistant", true},
		{"ai-agent", true},
		{"web-app", false},
		{"my-service", false},
		{"user-agent", false}, // Contains "agent" but not prefix
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.clientID, func(t *testing.T) {
			result := isAgentClientID(tt.clientID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchResource(t *testing.T) {
	tests := []struct {
		pattern  string
		resource string
		expected bool
	}{
		{"*", "/any/resource", true},
		{"/api/*", "/api/users", true},
		{"/api/*", "/api/users/123", true},
		{"/api/*", "/admin/users", false},
		{"/api/users", "/api/users", true},
		{"/api/users", "/api/users/123", false},
		{"/admin/*", "/admin/dashboard", true},
		{"/admin/*", "/api/admin", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.resource, func(t *testing.T) {
			result := matchResource(tt.pattern, tt.resource)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseConstraints(t *testing.T) {
	m := map[string]any{
		"max_actions_per_minute": float64(100),
		"require_human_approval": true,
		"max_tokens_per_request": float64(2000),
		"allowed_resources":      []any{"/api/*"},
		"denied_resources":       []any{"/admin/*"},
		"allowed_operations":     []any{"read", "write"},
	}

	c := parseConstraints(m)

	assert.Equal(t, 100, c.MaxActionsPerMinute)
	assert.True(t, c.RequireHumanApproval)
	assert.Equal(t, 2000, c.MaxTokensPerRequest)
	assert.Contains(t, c.AllowedResources, "/api/*")
	assert.Contains(t, c.DeniedResources, "/admin/*")
	assert.Contains(t, c.AllowedOperations, "read")
	assert.Contains(t, c.AllowedOperations, "write")
}

func TestParseConstraints_Empty(t *testing.T) {
	c := parseConstraints(map[string]any{})

	assert.Equal(t, 0, c.MaxActionsPerMinute)
	assert.False(t, c.RequireHumanApproval)
	assert.Empty(t, c.AllowedResources)
	assert.Empty(t, c.DeniedResources)
}

func TestExtractPermissions(t *testing.T) {
	token := &domain.TokenInfo{
		Scopes: []string{"openid", "profile"},
		ExtraClaims: map[string]any{
			"permissions": []any{"admin:read", "admin:write"},
		},
	}

	perms := extractPermissions(token)

	assert.Contains(t, perms, "openid")
	assert.Contains(t, perms, "profile")
	assert.Contains(t, perms, "admin:read")
	assert.Contains(t, perms, "admin:write")
}

func TestExtractPermissions_NoExtraClaims(t *testing.T) {
	token := &domain.TokenInfo{
		Scopes: []string{"openid"},
	}

	perms := extractPermissions(token)

	assert.Len(t, perms, 1)
	assert.Contains(t, perms, "openid")
}

// =============================================================================
// AgentType Constants Tests
// =============================================================================

func TestAgentTypeConstants(t *testing.T) {
	assert.Equal(t, AgentType("unknown"), AgentTypeUnknown)
	assert.Equal(t, AgentType("human"), AgentTypeHuman)
	assert.Equal(t, AgentType("llm_agent"), AgentTypeLLM)
	assert.Equal(t, AgentType("service"), AgentTypeService)
	assert.Equal(t, AgentType("bot"), AgentTypeBot)
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkEnhancer_Enhance(b *testing.B) {
	enhancer := NewEnhancer(EnhancerConfig{Enabled: true})
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		input := &domain.PolicyInput{
			Token: &domain.TokenInfo{
				Subject:  "user123",
				ClientID: "web-app",
				Scopes:   []string{"openid", "profile"},
			},
		}
		enhancer.Enhance(ctx, input)
	}
}

func BenchmarkEnhancer_Enhance_WithDelegation(b *testing.B) {
	enhancer := NewEnhancer(EnhancerConfig{Enabled: true})
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		input := &domain.PolicyInput{
			Token: &domain.TokenInfo{
				Subject: "service",
				ExtraClaims: map[string]any{
					"act": map[string]any{
						"sub": "service-a",
						"act": map[string]any{
							"sub": "user",
						},
					},
				},
			},
		}
		enhancer.Enhance(ctx, input)
	}
}

func BenchmarkValidateAgentAccess(b *testing.B) {
	agent := &AgentInfo{
		ID: "agent-123",
		Constraints: &AgentConstraints{
			AllowedResources:  []string{"/api/*", "/data/*"},
			DeniedResources:   []string{"/admin/*"},
			AllowedOperations: []string{"read", "list", "create"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ValidateAgentAccess(agent, "/api/users/123", "read")
	}
}

func BenchmarkIsAgentClientID(b *testing.B) {
	clientIDs := []string{"agent-service", "web-app", "bot-helper", "my-service"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isAgentClientID(clientIDs[i%len(clientIDs)])
	}
}
