package visibility

import (
	"testing"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/model"
)

func TestFilter_IsVisible(t *testing.T) {
	f := NewFilter()

	tests := []struct {
		name     string
		service  config.ServiceConfig
		user     *model.User
		expected bool
	}{
		{
			name: "no visibility config - visible to all",
			service: config.ServiceConfig{
				Name:       "public-service",
				Visibility: nil,
			},
			user: &model.User{
				Roles:  []string{"user"},
				Groups: []string{"/users"},
			},
			expected: true,
		},
		{
			name: "empty visibility config - visible to all",
			service: config.ServiceConfig{
				Name:       "public-service",
				Visibility: &config.VisibilityConfig{},
			},
			user: &model.User{
				Roles:  []string{"user"},
				Groups: []string{"/users"},
			},
			expected: true,
		},
		{
			name: "mode any - user has required role",
			service: config.ServiceConfig{
				Name: "admin-service",
				Visibility: &config.VisibilityConfig{
					Roles: []string{"admin"},
					Mode:  "any",
				},
			},
			user: &model.User{
				Roles:  []string{"user", "admin"},
				Groups: []string{"/users"},
			},
			expected: true,
		},
		{
			name: "mode any - user does not have required role",
			service: config.ServiceConfig{
				Name: "admin-service",
				Visibility: &config.VisibilityConfig{
					Roles: []string{"admin"},
					Mode:  "any",
				},
			},
			user: &model.User{
				Roles:  []string{"user"},
				Groups: []string{"/users"},
			},
			expected: false,
		},
		{
			name: "mode any - user has required group",
			service: config.ServiceConfig{
				Name: "admin-service",
				Visibility: &config.VisibilityConfig{
					Groups: []string{"/administrators"},
					Mode:   "any",
				},
			},
			user: &model.User{
				Roles:  []string{"user"},
				Groups: []string{"/users", "/administrators"},
			},
			expected: true,
		},
		{
			name: "mode any - user has role OR group (role match)",
			service: config.ServiceConfig{
				Name: "admin-service",
				Visibility: &config.VisibilityConfig{
					Roles:  []string{"admin"},
					Groups: []string{"/administrators"},
					Mode:   "any",
				},
			},
			user: &model.User{
				Roles:  []string{"admin"},
				Groups: []string{"/users"},
			},
			expected: true,
		},
		{
			name: "mode any - user has role OR group (group match)",
			service: config.ServiceConfig{
				Name: "admin-service",
				Visibility: &config.VisibilityConfig{
					Roles:  []string{"admin"},
					Groups: []string{"/administrators"},
					Mode:   "any",
				},
			},
			user: &model.User{
				Roles:  []string{"user"},
				Groups: []string{"/administrators"},
			},
			expected: true,
		},
		{
			name: "mode any - user has neither role nor group",
			service: config.ServiceConfig{
				Name: "admin-service",
				Visibility: &config.VisibilityConfig{
					Roles:  []string{"admin"},
					Groups: []string{"/administrators"},
					Mode:   "any",
				},
			},
			user: &model.User{
				Roles:  []string{"user"},
				Groups: []string{"/users"},
			},
			expected: false,
		},
		{
			name: "mode all - user has all required roles and groups",
			service: config.ServiceConfig{
				Name: "super-admin-service",
				Visibility: &config.VisibilityConfig{
					Roles:  []string{"admin", "super-user"},
					Groups: []string{"/administrators"},
					Mode:   "all",
				},
			},
			user: &model.User{
				Roles:  []string{"admin", "super-user", "user"},
				Groups: []string{"/administrators", "/users"},
			},
			expected: true,
		},
		{
			name: "mode all - user missing one role",
			service: config.ServiceConfig{
				Name: "super-admin-service",
				Visibility: &config.VisibilityConfig{
					Roles:  []string{"admin", "super-user"},
					Groups: []string{"/administrators"},
					Mode:   "all",
				},
			},
			user: &model.User{
				Roles:  []string{"admin"},
				Groups: []string{"/administrators"},
			},
			expected: false,
		},
		{
			name: "mode all - user missing group",
			service: config.ServiceConfig{
				Name: "super-admin-service",
				Visibility: &config.VisibilityConfig{
					Roles:  []string{"admin"},
					Groups: []string{"/administrators"},
					Mode:   "all",
				},
			},
			user: &model.User{
				Roles:  []string{"admin"},
				Groups: []string{"/users"},
			},
			expected: false,
		},
		{
			name: "default mode (empty) behaves as any",
			service: config.ServiceConfig{
				Name: "admin-service",
				Visibility: &config.VisibilityConfig{
					Roles: []string{"admin"},
					Mode:  "", // empty = default = any
				},
			},
			user: &model.User{
				Roles:  []string{"admin"},
				Groups: []string{"/users"},
			},
			expected: true,
		},
		{
			name: "only groups specified - user in group",
			service: config.ServiceConfig{
				Name: "group-service",
				Visibility: &config.VisibilityConfig{
					Groups: []string{"/developers"},
					Mode:   "any",
				},
			},
			user: &model.User{
				Roles:  []string{"user"},
				Groups: []string{"/developers"},
			},
			expected: true,
		},
		{
			name: "only groups specified - user not in group",
			service: config.ServiceConfig{
				Name: "group-service",
				Visibility: &config.VisibilityConfig{
					Groups: []string{"/developers"},
					Mode:   "any",
				},
			},
			user: &model.User{
				Roles:  []string{"user"},
				Groups: []string{"/users"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := f.IsVisible(tt.service, tt.user)
			if result != tt.expected {
				t.Errorf("IsVisible() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestFilter_FilterServices(t *testing.T) {
	f := NewFilter()

	services := []config.ServiceConfig{
		{
			Name:       "public",
			Visibility: nil, // visible to all
		},
		{
			Name: "admin-only",
			Visibility: &config.VisibilityConfig{
				Roles: []string{"admin"},
				Mode:  "any",
			},
		},
		{
			Name: "user-only",
			Visibility: &config.VisibilityConfig{
				Roles: []string{"user"},
				Mode:  "any",
			},
		},
		{
			Name: "developers",
			Visibility: &config.VisibilityConfig{
				Groups: []string{"/developers"},
				Mode:   "any",
			},
		},
	}

	tests := []struct {
		name          string
		user          *model.User
		expectedNames []string
	}{
		{
			name: "admin user sees public, admin-only, and user services",
			user: &model.User{
				Roles:  []string{"admin", "user"},
				Groups: []string{"/admins"},
			},
			expectedNames: []string{"public", "admin-only", "user-only"},
		},
		{
			name: "regular user sees public and user-only",
			user: &model.User{
				Roles:  []string{"user"},
				Groups: []string{"/users"},
			},
			expectedNames: []string{"public", "user-only"},
		},
		{
			name: "developer sees public and developers",
			user: &model.User{
				Roles:  []string{"viewer"},
				Groups: []string{"/developers"},
			},
			expectedNames: []string{"public", "developers"},
		},
		{
			name: "nil user sees nothing",
			user: nil,
			expectedNames: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := f.FilterServices(services, tt.user)

			if len(result) != len(tt.expectedNames) {
				t.Errorf("FilterServices() returned %d services, expected %d", len(result), len(tt.expectedNames))
				return
			}

			for i, svc := range result {
				if svc.Name != tt.expectedNames[i] {
					t.Errorf("FilterServices()[%d].Name = %s, expected %s", i, svc.Name, tt.expectedNames[i])
				}
			}
		})
	}
}

func TestFilter_HasAnyRole(t *testing.T) {
	f := NewFilter()

	tests := []struct {
		name          string
		userRoles     []string
		requiredRoles []string
		expected      bool
	}{
		{
			name:          "user has one of required roles",
			userRoles:     []string{"user", "admin"},
			requiredRoles: []string{"admin", "super-admin"},
			expected:      true,
		},
		{
			name:          "user has no required roles",
			userRoles:     []string{"user"},
			requiredRoles: []string{"admin", "super-admin"},
			expected:      false,
		},
		{
			name:          "empty required roles returns true",
			userRoles:     []string{"user"},
			requiredRoles: []string{},
			expected:      true,
		},
		{
			name:          "empty user roles returns false",
			userRoles:     []string{},
			requiredRoles: []string{"admin"},
			expected:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := f.hasAnyRole(tt.userRoles, tt.requiredRoles)
			if result != tt.expected {
				t.Errorf("hasAnyRole() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestFilter_HasAllRoles(t *testing.T) {
	f := NewFilter()

	tests := []struct {
		name          string
		userRoles     []string
		requiredRoles []string
		expected      bool
	}{
		{
			name:          "user has all required roles",
			userRoles:     []string{"user", "admin", "super-admin"},
			requiredRoles: []string{"admin", "super-admin"},
			expected:      true,
		},
		{
			name:          "user missing one required role",
			userRoles:     []string{"user", "admin"},
			requiredRoles: []string{"admin", "super-admin"},
			expected:      false,
		},
		{
			name:          "empty required roles returns true",
			userRoles:     []string{"user"},
			requiredRoles: []string{},
			expected:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := f.hasAllRoles(tt.userRoles, tt.requiredRoles)
			if result != tt.expected {
				t.Errorf("hasAllRoles() = %v, expected %v", result, tt.expected)
			}
		})
	}
}
