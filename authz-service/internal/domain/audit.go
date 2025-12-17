package domain

import "time"

// AuditEventType represents the type of audit event.
type AuditEventType string

const (
	AuditEventAuthzDecision   AuditEventType = "AUTHZ_DECISION"
	AuditEventTokenValidation AuditEventType = "TOKEN_VALIDATION"
	AuditEventTokenExchange   AuditEventType = "TOKEN_EXCHANGE"
	AuditEventCacheHit        AuditEventType = "CACHE_HIT"
	AuditEventCacheMiss       AuditEventType = "CACHE_MISS"
	AuditEventPolicyError     AuditEventType = "POLICY_ERROR"
)

// AuditEvent represents a security audit event.
type AuditEvent struct {
	// Timestamp is when the event occurred
	Timestamp time.Time `json:"timestamp"`

	// EventID is a unique identifier for this event
	EventID string `json:"event_id"`

	// EventType is the type of event
	EventType AuditEventType `json:"event_type"`

	// Subject contains information about who performed the action
	Subject AuditSubject `json:"subject"`

	// Resource contains information about the target resource
	Resource AuditResource `json:"resource"`

	// Action is what was attempted
	Action string `json:"action"`

	// Decision contains the authorization decision
	Decision AuditDecision `json:"decision"`

	// Request contains request metadata
	Request AuditRequest `json:"request,omitempty"`

	// Context is an extension point for additional context (agent info, delegation chains, etc.)
	Context map[string]any `json:"context,omitempty"`

	// Metadata contains additional metadata
	Metadata map[string]any `json:"metadata,omitempty"`
}

// AuditSubject contains information about the subject (user/service).
type AuditSubject struct {
	// ID is the subject identifier (user ID, service ID)
	ID string `json:"id"`

	// Type is the subject type (user, service, agent)
	Type string `json:"type"`

	// Roles are the subject's roles
	Roles []string `json:"roles,omitempty"`

	// Issuer is the token issuer
	Issuer string `json:"issuer,omitempty"`
}

// AuditResource contains information about the target resource.
type AuditResource struct {
	// Type is the resource type (api, service, data)
	Type string `json:"type"`

	// Path is the resource path
	Path string `json:"path"`

	// Service is the target service name
	Service string `json:"service,omitempty"`
}

// AuditDecision contains information about the authorization decision.
type AuditDecision struct {
	// Allowed indicates if access was granted
	Allowed bool `json:"allowed"`

	// Reasons explains why the decision was made
	Reasons []string `json:"reasons,omitempty"`

	// PolicyVersion is the policy version used
	PolicyVersion string `json:"policy_version,omitempty"`

	// Cached indicates if the decision came from cache
	Cached bool `json:"cached"`

	// DurationMs is how long the decision took
	DurationMs float64 `json:"duration_ms"`
}

// AuditRequest contains request metadata for audit.
type AuditRequest struct {
	// ID is the request ID
	ID string `json:"id"`

	// TraceID is the distributed trace ID
	TraceID string `json:"trace_id,omitempty"`

	// SourceIP is the client IP address
	SourceIP string `json:"source_ip,omitempty"`

	// UserAgent is the client user agent
	UserAgent string `json:"user_agent,omitempty"`
}

// NewAuditEvent creates a new audit event with defaults.
func NewAuditEvent(eventType AuditEventType) *AuditEvent {
	return &AuditEvent{
		Timestamp: time.Now().UTC(),
		EventType: eventType,
		Context:   make(map[string]any),
		Metadata:  make(map[string]any),
	}
}

// SetContext sets a context value.
func (e *AuditEvent) SetContext(key string, value any) *AuditEvent {
	if e.Context == nil {
		e.Context = make(map[string]any)
	}
	e.Context[key] = value
	return e
}

// SetMetadata sets a metadata value.
func (e *AuditEvent) SetMetadata(key string, value any) *AuditEvent {
	if e.Metadata == nil {
		e.Metadata = make(map[string]any)
	}
	e.Metadata[key] = value
	return e
}
