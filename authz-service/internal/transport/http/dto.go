package http

import (
	"time"

	"github.com/your-org/authz-service/internal/domain"
)

// AuthzRequest represents an authorization request.
type AuthzRequest struct {
	// Request contains HTTP request information
	Request RequestDTO `json:"request"`

	// Subject optionally contains subject information (for internal use)
	Subject *SubjectDTO `json:"subject,omitempty"`

	// Context contains additional context
	Context map[string]any `json:"context,omitempty"`
}

// RequestDTO represents HTTP request information.
type RequestDTO struct {
	Method   string            `json:"method"`
	Path     string            `json:"path"`
	Host     string            `json:"host,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Query    map[string]string `json:"query,omitempty"`
	Protocol string            `json:"protocol,omitempty"`
}

// SubjectDTO represents subject information.
type SubjectDTO struct {
	ID        string   `json:"id,omitempty"`
	Type      string   `json:"type,omitempty"`
	Roles     []string `json:"roles,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
	Audiences []string `json:"audiences,omitempty"`
}

// AuthzResponse represents an authorization response.
type AuthzResponse struct {
	Allowed       bool              `json:"allowed"`
	Reasons       []string          `json:"reasons,omitempty"`
	PolicyVersion string            `json:"policy_version,omitempty"`
	Cached        bool              `json:"cached"`
	EvaluatedAt   time.Time         `json:"evaluated_at"`
	Metadata      map[string]any    `json:"metadata,omitempty"`
}

// TokenInfoResponse represents token validation response.
type TokenInfoResponse struct {
	Valid       bool              `json:"valid"`
	Subject     string            `json:"sub,omitempty"`
	Issuer      string            `json:"iss,omitempty"`
	Audience    []string          `json:"aud,omitempty"`
	ExpiresAt   *time.Time        `json:"exp,omitempty"`
	IssuedAt    *time.Time        `json:"iat,omitempty"`
	Roles       []string          `json:"roles,omitempty"`
	Scopes      []string          `json:"scopes,omitempty"`
	ClientID    string            `json:"client_id,omitempty"`
	ExtraClaims map[string]any    `json:"extra_claims,omitempty"`
	Error       string            `json:"error,omitempty"`
	ErrorCode   string            `json:"error_code,omitempty"`
}

// ErrorResponse represents an error response.
type ErrorResponse struct {
	Error     string         `json:"error"`
	Code      string         `json:"code"`
	Details   map[string]any `json:"details,omitempty"`
	RequestID string         `json:"request_id,omitempty"`
}

// HealthResponse represents a health check response.
type HealthResponse struct {
	Status    string                 `json:"status"`
	Checks    map[string]CheckResult `json:"checks,omitempty"`
	Version   string                 `json:"version,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// TokenExchangeRequest represents a token exchange request.
type TokenExchangeRequest struct {
	SubjectToken       string `json:"subject_token"`
	SubjectTokenType   string `json:"subject_token_type,omitempty"`
	ActorToken         string `json:"actor_token,omitempty"`
	ActorTokenType     string `json:"actor_token_type,omitempty"`
	RequestedTokenType string `json:"requested_token_type,omitempty"`
	Audience           string `json:"audience,omitempty"`
	Scope              string `json:"scope,omitempty"`
	Resource           string `json:"resource,omitempty"`
}

// TokenExchangeResponse represents a token exchange response.
type TokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in,omitempty"`
	Scope           string `json:"scope,omitempty"`
	RefreshToken    string `json:"refresh_token,omitempty"`
}

// CheckResult represents a single health check result.
type CheckResult struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// BatchAuthzRequest represents a batch authorization request.
type BatchAuthzRequest struct {
	// Token is an optional shared token for all requests
	Token string `json:"token,omitempty"`

	// Requests is the list of authorization requests
	Requests []AuthzRequest `json:"requests"`
}

// BatchAuthzResponse represents a batch authorization response.
type BatchAuthzResponse struct {
	// Responses is the list of authorization responses
	Responses []AuthzResponse `json:"responses"`
}

// CacheInvalidateRequest represents a cache invalidation request.
type CacheInvalidateRequest struct {
	// Pattern is the cache key pattern to invalidate (supports wildcards)
	Pattern string `json:"pattern,omitempty"`

	// Keys is a list of specific keys to invalidate
	Keys []string `json:"keys,omitempty"`

	// Type is the cache type to invalidate (authorization, jwt, jwks)
	Type string `json:"type,omitempty"`
}

// CacheInvalidateResponse represents a cache invalidation response.
type CacheInvalidateResponse struct {
	Success       bool   `json:"success"`
	Message       string `json:"message,omitempty"`
	InvalidatedCount int `json:"invalidated_count,omitempty"`
}

// ToPolicyInput converts the request DTO to a PolicyInput domain object.
func (r *AuthzRequest) ToPolicyInput() *domain.PolicyInput {
	input := &domain.PolicyInput{
		Request: domain.RequestInfo{
			Method:   r.Request.Method,
			Path:     r.Request.Path,
			Host:     r.Request.Host,
			Headers:  r.Request.Headers,
			Query:    r.Request.Query,
			Protocol: r.Request.Protocol,
		},
		Context: domain.ContextInfo{
			Custom: r.Context,
		},
	}

	return input
}

// FromDecision creates a response from a domain Decision.
func FromDecision(d *domain.Decision) *AuthzResponse {
	return &AuthzResponse{
		Allowed:       d.Allowed,
		Reasons:       d.Reasons,
		PolicyVersion: d.PolicyVersion,
		Cached:        d.Cached,
		EvaluatedAt:   d.EvaluatedAt,
		Metadata:      d.Metadata,
	}
}

// FromTokenInfo creates a response from a domain TokenInfo.
func FromTokenInfo(t *domain.TokenInfo) *TokenInfoResponse {
	resp := &TokenInfoResponse{
		Valid:       t.Valid,
		Subject:     t.Subject,
		Issuer:      t.Issuer,
		Audience:    t.Audience,
		Roles:       t.Roles,
		Scopes:      t.Scopes,
		ClientID:    t.ClientID,
		ExtraClaims: t.ExtraClaims,
	}

	if !t.ExpiresAt.IsZero() {
		resp.ExpiresAt = &t.ExpiresAt
	}
	if !t.IssuedAt.IsZero() {
		resp.IssuedAt = &t.IssuedAt
	}

	return resp
}
