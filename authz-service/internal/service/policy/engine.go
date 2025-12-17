package policy

import (
	"context"

	"github.com/your-org/authz-service/internal/domain"
)

// Engine defines the interface for policy evaluation engines.
type Engine interface {
	// Name returns the engine name.
	Name() string

	// Evaluate evaluates a policy and returns an authorization decision.
	Evaluate(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error)

	// Start initializes the engine.
	Start(ctx context.Context) error

	// Stop shuts down the engine.
	Stop() error

	// Healthy returns true if the engine is healthy.
	Healthy(ctx context.Context) bool
}

// AuthorizationEnhancer allows extending authorization input before evaluation.
// This is an extension point for future LLM agent support.
type AuthorizationEnhancer interface {
	// Enhance modifies the policy input before evaluation.
	// This can be used to add agent-specific context, verify delegations, etc.
	Enhance(ctx context.Context, input *domain.PolicyInput) error
}

// DecisionEnhancer allows extending authorization decisions after evaluation.
type DecisionEnhancer interface {
	// Enhance modifies the decision after evaluation.
	// This can be used to add constraints, logging, etc.
	Enhance(ctx context.Context, input *domain.PolicyInput, decision *domain.Decision) error
}
