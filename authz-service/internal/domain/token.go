package domain

import "time"

// TokenInfo contains parsed and validated JWT token information.
type TokenInfo struct {
	// Raw is the original token string
	Raw string `json:"-"`

	// Valid indicates if the token passed validation
	Valid bool `json:"valid"`

	// Standard claims
	Subject   string    `json:"sub"`
	Issuer    string    `json:"iss"`
	Audience  []string  `json:"aud"`
	ExpiresAt time.Time `json:"exp"`
	IssuedAt  time.Time `json:"iat"`
	NotBefore time.Time `json:"nbf,omitempty"`
	JTI       string    `json:"jti,omitempty"`

	// OAuth/OIDC claims
	ClientID string `json:"client_id,omitempty"`

	// Authorization claims
	Roles  []string `json:"roles,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
	Groups []string `json:"groups,omitempty"`

	// ExtraClaims holds additional claims not explicitly mapped.
	// Extension point for future agent support (act, delegation_chain, etc.)
	ExtraClaims map[string]any `json:"extra_claims,omitempty"`
}

// HasRole checks if the token contains the specified role.
func (t *TokenInfo) HasRole(role string) bool {
	for _, r := range t.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasScope checks if the token contains the specified scope.
func (t *TokenInfo) HasScope(scope string) bool {
	for _, s := range t.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasAnyRole checks if the token contains any of the specified roles.
func (t *TokenInfo) HasAnyRole(roles ...string) bool {
	for _, role := range roles {
		if t.HasRole(role) {
			return true
		}
	}
	return false
}

// HasAllRoles checks if the token contains all of the specified roles.
func (t *TokenInfo) HasAllRoles(roles ...string) bool {
	for _, role := range roles {
		if !t.HasRole(role) {
			return false
		}
	}
	return true
}

// IsExpired checks if the token has expired.
func (t *TokenInfo) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// TTL returns the remaining time until token expiration.
func (t *TokenInfo) TTL() time.Duration {
	return time.Until(t.ExpiresAt)
}

// GetExtraClaim retrieves an extra claim by key.
func (t *TokenInfo) GetExtraClaim(key string) (any, bool) {
	if t.ExtraClaims == nil {
		return nil, false
	}
	v, ok := t.ExtraClaims[key]
	return v, ok
}
