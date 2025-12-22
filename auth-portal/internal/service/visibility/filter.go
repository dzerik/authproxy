// Package visibility provides role/group-based visibility filtering for portal services.
package visibility

import (
	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/model"
)

// Filter filters services based on user's roles and groups.
// Services without visibility config are visible to all authenticated users.
type Filter struct{}

// NewFilter creates a new visibility filter.
func NewFilter() *Filter {
	return &Filter{}
}

// FilterServices returns only the services that the user is allowed to see.
func (f *Filter) FilterServices(services []config.ServiceConfig, user *model.User) []config.ServiceConfig {
	if user == nil {
		return nil
	}

	var visible []config.ServiceConfig
	for _, svc := range services {
		if f.IsVisible(svc, user) {
			visible = append(visible, svc)
		}
	}
	return visible
}

// IsVisible checks if a service should be visible to the user.
// A service is visible if:
// - It has no visibility config (visible to all authenticated users)
// - Mode is "any" (default): user has ANY of the required roles OR is in ANY of the required groups
// - Mode is "all": user has ALL required roles AND is in ALL required groups
func (f *Filter) IsVisible(svc config.ServiceConfig, user *model.User) bool {
	if svc.Visibility == nil {
		return true // No restrictions
	}

	v := svc.Visibility

	// If no roles and no groups specified, visible to all
	if len(v.Roles) == 0 && len(v.Groups) == 0 {
		return true
	}

	mode := v.Mode
	if mode == "" {
		mode = "any" // Default mode
	}

	if mode == "all" {
		return f.hasAllRoles(user.Roles, v.Roles) && f.hasAllGroups(user.Groups, v.Groups)
	}

	// mode: any (OR logic)
	hasRole := len(v.Roles) == 0 || f.hasAnyRole(user.Roles, v.Roles)
	hasGroup := len(v.Groups) == 0 || f.hasAnyGroup(user.Groups, v.Groups)

	// If both are specified, user needs at least one from either
	if len(v.Roles) > 0 && len(v.Groups) > 0 {
		return f.hasAnyRole(user.Roles, v.Roles) || f.hasAnyGroup(user.Groups, v.Groups)
	}

	return hasRole && hasGroup
}

// hasAnyRole checks if userRoles contains at least one of the required roles.
func (f *Filter) hasAnyRole(userRoles, requiredRoles []string) bool {
	if len(requiredRoles) == 0 {
		return true
	}
	roleSet := make(map[string]struct{}, len(userRoles))
	for _, r := range userRoles {
		roleSet[r] = struct{}{}
	}
	for _, r := range requiredRoles {
		if _, ok := roleSet[r]; ok {
			return true
		}
	}
	return false
}

// hasAllRoles checks if userRoles contains all of the required roles.
func (f *Filter) hasAllRoles(userRoles, requiredRoles []string) bool {
	if len(requiredRoles) == 0 {
		return true
	}
	roleSet := make(map[string]struct{}, len(userRoles))
	for _, r := range userRoles {
		roleSet[r] = struct{}{}
	}
	for _, r := range requiredRoles {
		if _, ok := roleSet[r]; !ok {
			return false
		}
	}
	return true
}

// hasAnyGroup checks if userGroups contains at least one of the required groups.
func (f *Filter) hasAnyGroup(userGroups, requiredGroups []string) bool {
	if len(requiredGroups) == 0 {
		return true
	}
	groupSet := make(map[string]struct{}, len(userGroups))
	for _, g := range userGroups {
		groupSet[g] = struct{}{}
	}
	for _, g := range requiredGroups {
		if _, ok := groupSet[g]; ok {
			return true
		}
	}
	return false
}

// hasAllGroups checks if userGroups contains all of the required groups.
func (f *Filter) hasAllGroups(userGroups, requiredGroups []string) bool {
	if len(requiredGroups) == 0 {
		return true
	}
	groupSet := make(map[string]struct{}, len(userGroups))
	for _, g := range userGroups {
		groupSet[g] = struct{}{}
	}
	for _, g := range requiredGroups {
		if _, ok := groupSet[g]; !ok {
			return false
		}
	}
	return true
}
