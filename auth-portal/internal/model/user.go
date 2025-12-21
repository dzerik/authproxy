package model

import (
	"strings"
	"time"
)

// User represents an authenticated user
type User struct {
	ID            string            `json:"id"`
	Email         string            `json:"email"`
	Name          string            `json:"name"`
	PreferredName string            `json:"preferred_name"`
	GivenName     string            `json:"given_name"`
	FamilyName    string            `json:"family_name"`
	Picture       string            `json:"picture"`
	Locale        string            `json:"locale"`
	Roles         []string          `json:"roles"`
	Groups        []string          `json:"groups"`
	Claims        map[string]any    `json:"claims"`
	TenantID      string            `json:"tenant_id,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
}

// HasRole checks if user has a specific role
func (u *User) HasRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasAnyRole checks if user has any of the specified roles
func (u *User) HasAnyRole(roles ...string) bool {
	for _, role := range roles {
		if u.HasRole(role) {
			return true
		}
	}
	return false
}

// HasAllRoles checks if user has all of the specified roles
func (u *User) HasAllRoles(roles ...string) bool {
	for _, role := range roles {
		if !u.HasRole(role) {
			return false
		}
	}
	return true
}

// HasGroup checks if user belongs to a specific group
func (u *User) HasGroup(group string) bool {
	for _, g := range u.Groups {
		if g == group {
			return true
		}
	}
	return false
}

// HasAnyGroup checks if user belongs to any of the specified groups
func (u *User) HasAnyGroup(groups ...string) bool {
	for _, group := range groups {
		if u.HasGroup(group) {
			return true
		}
	}
	return false
}

// RolesString returns roles as comma-separated string
func (u *User) RolesString() string {
	return strings.Join(u.Roles, ",")
}

// GroupsString returns groups as comma-separated string
func (u *User) GroupsString() string {
	return strings.Join(u.Groups, ",")
}

// DisplayName returns the best available display name
func (u *User) DisplayName() string {
	if u.PreferredName != "" {
		return u.PreferredName
	}
	if u.Name != "" {
		return u.Name
	}
	if u.GivenName != "" && u.FamilyName != "" {
		return u.GivenName + " " + u.FamilyName
	}
	if u.GivenName != "" {
		return u.GivenName
	}
	return u.Email
}

// GetClaim returns a claim value by key
func (u *User) GetClaim(key string) (any, bool) {
	v, ok := u.Claims[key]
	return v, ok
}

// GetClaimString returns a claim as string
func (u *User) GetClaimString(key string) string {
	v, ok := u.Claims[key]
	if !ok {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
