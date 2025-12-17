package integration

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/your-org/authz-service/internal/domain"
	"github.com/your-org/authz-service/internal/service/agent"
)

func TestAgentEnhancer_Enhance_Disabled(t *testing.T) {
	enhancer := agent.NewEnhancer(agent.EnhancerConfig{
		Enabled: false,
	})

	ctx := NewTestContext(t)
	input := &domain.PolicyInput{
		Token: &domain.TokenInfo{
			Valid:   true,
			Subject: "user-123",
		},
	}

	err := enhancer.Enhance(ctx, input)
	require.NoError(t, err)

	// Should not add any extensions when disabled
	assert.Nil(t, input.Extensions)
}

func TestAgentEnhancer_Enhance_NoToken(t *testing.T) {
	enhancer := agent.NewEnhancer(agent.EnhancerConfig{
		Enabled: true,
	})

	ctx := NewTestContext(t)
	input := &domain.PolicyInput{
		Token: nil, // No token
	}

	err := enhancer.Enhance(ctx, input)
	require.NoError(t, err)

	// Should not add any extensions when no token
	assert.Nil(t, input.Extensions)
}

func TestAgentEnhancer_Enhance_HumanUser(t *testing.T) {
	enhancer := agent.NewEnhancer(agent.EnhancerConfig{
		Enabled: true,
	})

	ctx := NewTestContext(t)
	input := &domain.PolicyInput{
		Token: &domain.TokenInfo{
			Valid:       true,
			Subject:     "user-123",
			ClientID:    "web-app",
			Roles:       []string{"user"},
			ExtraClaims: map[string]any{},
		},
	}

	err := enhancer.Enhance(ctx, input)
	require.NoError(t, err)

	// Should identify as human
	agentType, ok := input.GetExtension("agent_type")
	require.True(t, ok)
	assert.Equal(t, "human", agentType)
}

func TestAgentEnhancer_Enhance_LLMAgent(t *testing.T) {
	enhancer := agent.NewEnhancer(agent.EnhancerConfig{
		Enabled: true,
	})

	ctx := NewTestContext(t)
	input := &domain.PolicyInput{
		Token: &domain.TokenInfo{
			Valid:    true,
			Subject:  "agent-claude",
			ClientID: "agent-client-123",
			ExtraClaims: map[string]any{
				"agent_type":     "llm_agent",
				"agent_name":     "Claude Assistant",
				"agent_model":    "claude-3-opus",
				"agent_provider": "anthropic",
				"session_id":     "session-abc-123",
			},
		},
	}

	err := enhancer.Enhance(ctx, input)
	require.NoError(t, err)

	// Should identify as LLM agent
	agentType, ok := input.GetExtension("agent_type")
	require.True(t, ok)
	assert.Equal(t, "llm_agent", agentType)

	// Should have agent info
	agentInfo, ok := input.GetExtension("agent")
	require.True(t, ok)

	info, ok := agentInfo.(*agent.AgentInfo)
	require.True(t, ok)
	assert.Equal(t, "agent-client-123", info.ID)
	assert.Equal(t, agent.AgentTypeLLM, info.Type)
	assert.Equal(t, "Claude Assistant", info.Name)
	assert.Equal(t, "claude-3-opus", info.Model)
	assert.Equal(t, "anthropic", info.Provider)
	assert.Equal(t, "session-abc-123", info.SessionID)
}

func TestAgentEnhancer_Enhance_WithDelegation(t *testing.T) {
	enhancer := agent.NewEnhancer(agent.EnhancerConfig{
		Enabled: true,
	})

	ctx := NewTestContext(t)
	input := &domain.PolicyInput{
		Token: &domain.TokenInfo{
			Valid:    true,
			Subject:  "user-123",
			ClientID: "agent-client",
			ExtraClaims: map[string]any{
				"act": map[string]any{
					"sub":       "agent-001",
					"client_id": "agent-client",
					"type":      "llm_agent",
					"act": map[string]any{
						"sub":       "service-orchestrator",
						"client_id": "orchestrator-client",
						"type":      "service",
					},
				},
			},
		},
	}

	err := enhancer.Enhance(ctx, input)
	require.NoError(t, err)

	// Should have delegation chain
	chain, ok := input.GetExtension("delegation_chain")
	require.True(t, ok)

	delegations, ok := chain.([]agent.DelegationInfo)
	require.True(t, ok)
	assert.Len(t, delegations, 2)

	// First delegation
	assert.Equal(t, "agent-001", delegations[0].Subject)
	assert.Equal(t, "agent-client", delegations[0].ClientID)
	assert.Equal(t, "llm_agent", delegations[0].Type)

	// Second delegation (nested)
	assert.Equal(t, "service-orchestrator", delegations[1].Subject)
	assert.Equal(t, "orchestrator-client", delegations[1].ClientID)
	assert.Equal(t, "service", delegations[1].Type)

	// Should have delegation depth
	depth, ok := input.GetExtension("delegation_depth")
	require.True(t, ok)
	assert.Equal(t, 2, depth)
}

func TestAgentEnhancer_Enhance_AgentPrefixClientID(t *testing.T) {
	enhancer := agent.NewEnhancer(agent.EnhancerConfig{
		Enabled: true,
	})

	testCases := []struct {
		name       string
		clientID   string
		expectType agent.AgentType
	}{
		{"agent- prefix", "agent-claude", agent.AgentTypeLLM},
		{"bot- prefix", "bot-assistant", agent.AgentTypeLLM},
		{"llm- prefix", "llm-model-123", agent.AgentTypeLLM},
		{"ai- prefix", "ai-helper", agent.AgentTypeLLM},
		{"normal client", "web-app", agent.AgentTypeHuman},
		{"service client", "backend-service", agent.AgentTypeHuman},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := NewTestContext(t)
			input := &domain.PolicyInput{
				Token: &domain.TokenInfo{
					Valid:       true,
					Subject:     "user-123",
					ClientID:    tc.clientID,
					ExtraClaims: map[string]any{},
				},
			}

			err := enhancer.Enhance(ctx, input)
			require.NoError(t, err)

			agentInfo, ok := input.GetExtension("agent")
			require.True(t, ok)

			info, ok := agentInfo.(*agent.AgentInfo)
			require.True(t, ok)
			assert.Equal(t, tc.expectType, info.Type)
		})
	}
}

func TestAgentEnhancer_Enhance_WithConstraints(t *testing.T) {
	enhancer := agent.NewEnhancer(agent.EnhancerConfig{
		Enabled: true,
	})

	ctx := NewTestContext(t)
	input := &domain.PolicyInput{
		Token: &domain.TokenInfo{
			Valid:    true,
			Subject:  "agent-001",
			ClientID: "agent-client",
			ExtraClaims: map[string]any{
				"agent_type": "llm_agent",
				"agent_constraints": map[string]any{
					"max_actions_per_minute":  float64(60),
					"require_human_approval":  true,
					"max_tokens_per_request":  float64(4096),
					"allowed_resources":       []any{"/api/read/*", "/api/data/*"},
					"denied_resources":        []any{"/api/admin/*", "/api/secrets/*"},
					"allowed_operations":      []any{"read", "list"},
				},
			},
		},
	}

	err := enhancer.Enhance(ctx, input)
	require.NoError(t, err)

	agentInfo, ok := input.GetExtension("agent")
	require.True(t, ok)

	info, ok := agentInfo.(*agent.AgentInfo)
	require.True(t, ok)
	require.NotNil(t, info.Constraints)

	c := info.Constraints
	assert.Equal(t, 60, c.MaxActionsPerMinute)
	assert.True(t, c.RequireHumanApproval)
	assert.Equal(t, 4096, c.MaxTokensPerRequest)
	assert.Contains(t, c.AllowedResources, "/api/read/*")
	assert.Contains(t, c.DeniedResources, "/api/admin/*")
	assert.Contains(t, c.AllowedOperations, "read")
}

func TestValidateAgentAccess_NoConstraints(t *testing.T) {
	err := agent.ValidateAgentAccess(nil, "/api/data", "read")
	assert.NoError(t, err)

	err = agent.ValidateAgentAccess(&agent.AgentInfo{}, "/api/data", "read")
	assert.NoError(t, err)

	err = agent.ValidateAgentAccess(&agent.AgentInfo{Constraints: nil}, "/api/data", "read")
	assert.NoError(t, err)
}

func TestValidateAgentAccess_DeniedResources(t *testing.T) {
	agentInfo := &agent.AgentInfo{
		Constraints: &agent.AgentConstraints{
			DeniedResources: []string{"/api/admin/*", "/api/secrets"},
		},
	}

	testCases := []struct {
		name        string
		resource    string
		expectError bool
	}{
		{"denied wildcard match", "/api/admin/users", true},
		{"denied exact match", "/api/secrets", true},
		{"allowed resource", "/api/data", false},
		{"allowed public", "/api/public/info", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := agent.ValidateAgentAccess(agentInfo, tc.resource, "read")
			if tc.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "denied")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateAgentAccess_AllowedResources(t *testing.T) {
	agentInfo := &agent.AgentInfo{
		Constraints: &agent.AgentConstraints{
			AllowedResources: []string{"/api/read/*", "/api/public"},
		},
	}

	testCases := []struct {
		name        string
		resource    string
		expectError bool
	}{
		{"allowed wildcard match", "/api/read/data", false},
		{"allowed exact match", "/api/public", false},
		{"not in allowed list", "/api/write/data", true},
		{"admin not allowed", "/api/admin", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := agent.ValidateAgentAccess(agentInfo, tc.resource, "read")
			if tc.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "not in allowed list")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateAgentAccess_AllowedOperations(t *testing.T) {
	agentInfo := &agent.AgentInfo{
		Constraints: &agent.AgentConstraints{
			AllowedOperations: []string{"read", "list", "get"},
		},
	}

	testCases := []struct {
		name        string
		operation   string
		expectError bool
	}{
		{"read allowed", "read", false},
		{"list allowed", "list", false},
		{"get allowed", "get", false},
		{"write not allowed", "write", true},
		{"delete not allowed", "delete", true},
		{"admin not allowed", "admin", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := agent.ValidateAgentAccess(agentInfo, "/api/data", tc.operation)
			if tc.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "not allowed")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateAgentAccess_WildcardOperation(t *testing.T) {
	agentInfo := &agent.AgentInfo{
		Constraints: &agent.AgentConstraints{
			AllowedOperations: []string{"*"},
		},
	}

	// Wildcard should allow any operation
	err := agent.ValidateAgentAccess(agentInfo, "/api/data", "read")
	assert.NoError(t, err)

	err = agent.ValidateAgentAccess(agentInfo, "/api/data", "write")
	assert.NoError(t, err)

	err = agent.ValidateAgentAccess(agentInfo, "/api/data", "delete")
	assert.NoError(t, err)
}

func TestValidateAgentAccess_CombinedConstraints(t *testing.T) {
	agentInfo := &agent.AgentInfo{
		Constraints: &agent.AgentConstraints{
			AllowedResources:  []string{"/api/data/*"},
			DeniedResources:   []string{"/api/data/secret"},
			AllowedOperations: []string{"read", "list"},
		},
	}

	testCases := []struct {
		name        string
		resource    string
		operation   string
		expectError bool
		errorMsg    string
	}{
		{"allowed resource and operation", "/api/data/items", "read", false, ""},
		{"allowed resource denied operation", "/api/data/items", "write", true, "not allowed"},
		{"denied resource", "/api/data/secret", "read", true, "denied"},
		{"resource not in allowed list", "/api/users", "read", true, "not in allowed"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := agent.ValidateAgentAccess(agentInfo, tc.resource, tc.operation)
			if tc.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Integration test: Agent enhancer in policy evaluation pipeline
func TestAgentEnhancer_PolicyIntegration(t *testing.T) {
	enhancer := agent.NewEnhancer(agent.EnhancerConfig{
		Enabled: true,
	})

	ctx := context.Background()

	// Simulate policy evaluation pipeline
	input := &domain.PolicyInput{
		Request: domain.RequestInfo{
			Path:   "/api/data/items",
			Method: "GET",
		},
		Token: &domain.TokenInfo{
			Valid:    true,
			Subject:  "agent-assistant",
			ClientID: "agent-claude",
			Roles:    []string{"agent"},
			Scopes:   []string{"read", "api"},
			ExtraClaims: map[string]any{
				"agent_type":     "llm_agent",
				"agent_model":    "claude-3-opus",
				"agent_provider": "anthropic",
				"agent_constraints": map[string]any{
					"allowed_resources": []any{"/api/data/*"},
					"allowed_operations": []any{"read", "list"},
				},
			},
		},
	}

	// Step 1: Enhance input with agent info
	err := enhancer.Enhance(ctx, input)
	require.NoError(t, err)

	// Step 2: Verify agent info is available for policy evaluation
	agentInfo, ok := input.GetExtension("agent")
	require.True(t, ok)

	info, ok := agentInfo.(*agent.AgentInfo)
	require.True(t, ok)

	// Step 3: Validate agent access constraints
	err = agent.ValidateAgentAccess(info, input.Request.Path, "read")
	assert.NoError(t, err)

	// Step 4: Policy could use this info for additional checks
	assert.Equal(t, agent.AgentTypeLLM, info.Type)
	assert.Equal(t, "claude-3-opus", info.Model)
	assert.Contains(t, info.Permissions, "read")
}
