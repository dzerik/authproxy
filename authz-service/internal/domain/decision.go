package domain

import "time"

// Decision represents an authorization decision.
type Decision struct {
	// Allowed indicates whether the request is authorized
	Allowed bool `json:"allowed"`

	// Reasons provides explanation for the decision
	Reasons []string `json:"reasons,omitempty"`

	// PolicyVersion is the version of the policy that made the decision
	PolicyVersion string `json:"policy_version,omitempty"`

	// EvaluatedAt is when the decision was made
	EvaluatedAt time.Time `json:"evaluated_at"`

	// Cached indicates if this decision came from cache
	Cached bool `json:"cached"`

	// HeadersToAdd contains headers to add to the request (for allow decisions)
	HeadersToAdd map[string]string `json:"headers_to_add,omitempty"`

	// HeadersToRemove contains headers to remove from the request
	HeadersToRemove []string `json:"headers_to_remove,omitempty"`

	// Metadata contains additional decision metadata (extension point)
	Metadata map[string]any `json:"metadata,omitempty"`
}

// DecisionMetadata contains metadata about how the decision was made.
type DecisionMetadata struct {
	// DecisionID is a unique identifier for this decision
	DecisionID string `json:"decision_id"`

	// PolicyVersion is the version of the policy that made the decision
	PolicyVersion string `json:"policy_version,omitempty"`

	// Cached indicates if this decision came from cache
	Cached bool `json:"cached"`

	// EvaluationTime is how long the policy evaluation took
	EvaluationTime time.Duration `json:"evaluation_time_ns"`

	// Engine is the policy engine that made the decision
	Engine string `json:"engine,omitempty"`
}

// Deny creates a deny decision with the given reasons.
func Deny(reasons ...string) *Decision {
	return &Decision{
		Allowed:     false,
		Reasons:     reasons,
		EvaluatedAt: time.Now(),
	}
}

// Allow creates an allow decision with optional reason.
func Allow(reasons ...string) *Decision {
	return &Decision{
		Allowed:     true,
		Reasons:     reasons,
		EvaluatedAt: time.Now(),
	}
}

// AllowWithHeaders creates an allow decision with headers to add.
func AllowWithHeaders(headers map[string]string) *Decision {
	return &Decision{
		Allowed:      true,
		HeadersToAdd: headers,
		EvaluatedAt:  time.Now(),
	}
}

// WithMetadata adds a metadata key-value pair to the decision.
func (d *Decision) WithMetadata(key string, value any) *Decision {
	if d.Metadata == nil {
		d.Metadata = make(map[string]any)
	}
	d.Metadata[key] = value
	return d
}

// WithReason adds a reason to the decision.
func (d *Decision) WithReason(reason string) *Decision {
	d.Reasons = append(d.Reasons, reason)
	return d
}
