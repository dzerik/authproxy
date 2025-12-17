// Package agent provides extension points for LLM agent authorization.
// This package implements the "prepare platform" approach for future agent support.
//
// Current capabilities:
// - Extract and validate agent identity from tokens
// - Parse delegation chains (act claims per RFC 8693)
// - Enrich policy input with agent context
// - Validate agent permissions and constraints
//
// Future extensions (when full agent support is needed):
// - Agent registry integration
// - Intent verification
// - Behavioral constraints enforcement
// - Session/conversation context
package agent

import (
	"context"
	"fmt"
	"strings"

	"github.com/your-org/authz-service/internal/domain"
	"github.com/your-org/authz-service/pkg/logger"
)

// AgentType represents the type of agent.
type AgentType string

const (
	AgentTypeUnknown AgentType = "unknown"
	AgentTypeHuman   AgentType = "human"
	AgentTypeLLM     AgentType = "llm_agent"
	AgentTypeService AgentType = "service"
	AgentTypeBot     AgentType = "bot"
)

// AgentInfo contains information about an agent making a request.
type AgentInfo struct {
	// ID is the unique agent identifier
	ID string `json:"id"`

	// Type indicates the agent type (human, llm_agent, service, bot)
	Type AgentType `json:"type"`

	// Name is the human-readable agent name
	Name string `json:"name,omitempty"`

	// Model is the LLM model identifier (for LLM agents)
	Model string `json:"model,omitempty"`

	// Provider is the agent provider (e.g., "openai", "anthropic")
	Provider string `json:"provider,omitempty"`

	// DelegatedBy contains the chain of principals who delegated authority
	DelegatedBy []DelegationInfo `json:"delegated_by,omitempty"`

	// Permissions are the agent's allowed actions
	Permissions []string `json:"permissions,omitempty"`

	// Constraints are restrictions on agent behavior
	Constraints *AgentConstraints `json:"constraints,omitempty"`

	// SessionID links to a conversation/session context
	SessionID string `json:"session_id,omitempty"`

	// Metadata contains additional agent-specific data
	Metadata map[string]any `json:"metadata,omitempty"`
}

// DelegationInfo represents a single delegation in the chain.
type DelegationInfo struct {
	Subject  string `json:"sub"`
	Issuer   string `json:"iss,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	Type     string `json:"type,omitempty"`
}

// AgentConstraints defines behavioral constraints for agents.
type AgentConstraints struct {
	// MaxActionsPerMinute limits the action rate
	MaxActionsPerMinute int `json:"max_actions_per_minute,omitempty"`

	// AllowedResources lists resources the agent can access
	AllowedResources []string `json:"allowed_resources,omitempty"`

	// DeniedResources lists resources the agent cannot access
	DeniedResources []string `json:"denied_resources,omitempty"`

	// RequireHumanApproval indicates actions requiring human confirmation
	RequireHumanApproval bool `json:"require_human_approval,omitempty"`

	// MaxTokensPerRequest limits token usage
	MaxTokensPerRequest int `json:"max_tokens_per_request,omitempty"`

	// AllowedOperations lists allowed operation types
	AllowedOperations []string `json:"allowed_operations,omitempty"`
}

// Enhancer enriches authorization input with agent information.
// Implements the policy.AuthorizationEnhancer interface.
type Enhancer struct {
	// Config holds enhancer configuration
	enabled bool
}

// EnhancerConfig holds agent enhancer configuration.
type EnhancerConfig struct {
	Enabled bool
}

// NewEnhancer creates a new agent enhancer.
func NewEnhancer(cfg EnhancerConfig) *Enhancer {
	return &Enhancer{
		enabled: cfg.Enabled,
	}
}

// Enhance enriches the policy input with agent information.
func (e *Enhancer) Enhance(ctx context.Context, input *domain.PolicyInput) error {
	if !e.enabled {
		return nil
	}

	if input.Token == nil {
		return nil
	}

	// Extract agent info from token claims
	agentInfo := e.extractAgentInfo(input.Token)
	if agentInfo == nil {
		return nil
	}

	// Add agent info to extensions
	input.SetExtension("agent", agentInfo)
	input.SetExtension("agent_type", string(agentInfo.Type))

	// Add delegation chain if present
	if len(agentInfo.DelegatedBy) > 0 {
		input.SetExtension("delegation_chain", agentInfo.DelegatedBy)
		input.SetExtension("delegation_depth", len(agentInfo.DelegatedBy))
	}

	logger.Debug("agent info extracted",
		logger.String("agent_id", agentInfo.ID),
		logger.String("agent_type", string(agentInfo.Type)),
		logger.Int("delegation_depth", len(agentInfo.DelegatedBy)),
	)

	return nil
}

// extractAgentInfo extracts agent information from token claims.
func (e *Enhancer) extractAgentInfo(token *domain.TokenInfo) *AgentInfo {
	info := &AgentInfo{
		ID:       token.Subject,
		Type:     AgentTypeHuman, // Default to human
		Metadata: make(map[string]any),
	}

	// Check for agent type indicator in claims
	if agentType, ok := token.GetExtraClaim("agent_type"); ok {
		if typeStr, ok := agentType.(string); ok {
			info.Type = AgentType(typeStr)
		}
	}

	// Check for azp (authorized party) which might indicate an agent
	if token.ClientID != "" {
		// If client_id looks like an agent identifier
		if isAgentClientID(token.ClientID) {
			info.Type = AgentTypeLLM
			info.ID = token.ClientID
		}
	}

	// Extract agent name
	if name, ok := token.GetExtraClaim("agent_name"); ok {
		if nameStr, ok := name.(string); ok {
			info.Name = nameStr
		}
	}

	// Extract model info for LLM agents
	if model, ok := token.GetExtraClaim("agent_model"); ok {
		if modelStr, ok := model.(string); ok {
			info.Model = modelStr
		}
	}

	// Extract provider
	if provider, ok := token.GetExtraClaim("agent_provider"); ok {
		if providerStr, ok := provider.(string); ok {
			info.Provider = providerStr
		}
	}

	// Extract session ID
	if sessionID, ok := token.GetExtraClaim("session_id"); ok {
		if sessionStr, ok := sessionID.(string); ok {
			info.SessionID = sessionStr
		}
	}

	// Parse delegation chain from "act" claim (RFC 8693)
	info.DelegatedBy = e.parseDelegationChain(token)

	// If there's a delegation chain, this is likely an agent acting on behalf
	if len(info.DelegatedBy) > 0 && info.Type == AgentTypeHuman {
		info.Type = AgentTypeService // At minimum, it's acting as a service
	}

	// Extract permissions from scope or custom claim
	info.Permissions = extractPermissions(token)

	// Extract constraints if present
	if constraints, ok := token.GetExtraClaim("agent_constraints"); ok {
		if constraintsMap, ok := constraints.(map[string]any); ok {
			info.Constraints = parseConstraints(constraintsMap)
		}
	}

	return info
}

// parseDelegationChain extracts delegation chain from act claims.
func (e *Enhancer) parseDelegationChain(token *domain.TokenInfo) []DelegationInfo {
	var chain []DelegationInfo

	actClaim, ok := token.GetExtraClaim("act")
	if !ok {
		return chain
	}

	// Parse nested act claims per RFC 8693
	current := actClaim
	for current != nil {
		actMap, ok := current.(map[string]any)
		if !ok {
			break
		}

		info := DelegationInfo{}
		if sub, ok := actMap["sub"].(string); ok {
			info.Subject = sub
		}
		if iss, ok := actMap["iss"].(string); ok {
			info.Issuer = iss
		}
		if clientID, ok := actMap["client_id"].(string); ok {
			info.ClientID = clientID
		}
		if actType, ok := actMap["type"].(string); ok {
			info.Type = actType
		}

		if info.Subject != "" {
			chain = append(chain, info)
		}

		// Move to nested act claim
		current, _ = actMap["act"]
	}

	return chain
}

// Helper functions

func isAgentClientID(clientID string) bool {
	agentPrefixes := []string{"agent-", "bot-", "llm-", "ai-"}
	for _, prefix := range agentPrefixes {
		if strings.HasPrefix(strings.ToLower(clientID), prefix) {
			return true
		}
	}
	return false
}

func extractPermissions(token *domain.TokenInfo) []string {
	var permissions []string

	// From scopes
	permissions = append(permissions, token.Scopes...)

	// From custom claim
	if perms, ok := token.GetExtraClaim("permissions"); ok {
		if permList, ok := perms.([]any); ok {
			for _, p := range permList {
				if pStr, ok := p.(string); ok {
					permissions = append(permissions, pStr)
				}
			}
		}
	}

	return permissions
}

func parseConstraints(m map[string]any) *AgentConstraints {
	c := &AgentConstraints{}

	if v, ok := m["max_actions_per_minute"].(float64); ok {
		c.MaxActionsPerMinute = int(v)
	}
	if v, ok := m["require_human_approval"].(bool); ok {
		c.RequireHumanApproval = v
	}
	if v, ok := m["max_tokens_per_request"].(float64); ok {
		c.MaxTokensPerRequest = int(v)
	}

	if resources, ok := m["allowed_resources"].([]any); ok {
		for _, r := range resources {
			if rStr, ok := r.(string); ok {
				c.AllowedResources = append(c.AllowedResources, rStr)
			}
		}
	}

	if resources, ok := m["denied_resources"].([]any); ok {
		for _, r := range resources {
			if rStr, ok := r.(string); ok {
				c.DeniedResources = append(c.DeniedResources, rStr)
			}
		}
	}

	if ops, ok := m["allowed_operations"].([]any); ok {
		for _, o := range ops {
			if oStr, ok := o.(string); ok {
				c.AllowedOperations = append(c.AllowedOperations, oStr)
			}
		}
	}

	return c
}

// ValidateAgentAccess checks if an agent can access a specific resource.
// This is a helper for policy evaluation.
func ValidateAgentAccess(agent *AgentInfo, resource, operation string) error {
	if agent == nil || agent.Constraints == nil {
		return nil // No constraints
	}

	c := agent.Constraints

	// Check denied resources
	for _, denied := range c.DeniedResources {
		if matchResource(denied, resource) {
			return fmt.Errorf("resource %s is denied for agent", resource)
		}
	}

	// Check allowed resources if specified
	if len(c.AllowedResources) > 0 {
		allowed := false
		for _, allowedRes := range c.AllowedResources {
			if matchResource(allowedRes, resource) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("resource %s is not in allowed list", resource)
		}
	}

	// Check allowed operations if specified
	if len(c.AllowedOperations) > 0 {
		allowed := false
		for _, op := range c.AllowedOperations {
			if op == operation || op == "*" {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("operation %s is not allowed for agent", operation)
		}
	}

	return nil
}

func matchResource(pattern, resource string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(resource, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == resource
}
