package model

import (
	"testing"
	"time"
)

func TestUser_HasRole(t *testing.T) {
	user := &User{
		Roles: []string{"admin", "user", "developer"},
	}

	tests := []struct {
		role     string
		expected bool
	}{
		{"admin", true},
		{"user", true},
		{"developer", true},
		{"guest", false},
		{"", false},
		{"Admin", false}, // case sensitive
	}

	for _, tt := range tests {
		t.Run(tt.role, func(t *testing.T) {
			result := user.HasRole(tt.role)
			if result != tt.expected {
				t.Errorf("HasRole(%q) = %v, want %v", tt.role, result, tt.expected)
			}
		})
	}
}

func TestUser_HasRole_EmptyRoles(t *testing.T) {
	user := &User{}
	if user.HasRole("admin") {
		t.Error("HasRole should return false for empty roles")
	}
}

func TestUser_HasAnyRole(t *testing.T) {
	user := &User{
		Roles: []string{"admin", "user"},
	}

	tests := []struct {
		name     string
		roles    []string
		expected bool
	}{
		{"has admin", []string{"admin", "guest"}, true},
		{"has user", []string{"guest", "user"}, true},
		{"has none", []string{"guest", "visitor"}, false},
		{"empty roles", []string{}, false},
		{"single match", []string{"admin"}, true},
		{"single no match", []string{"guest"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := user.HasAnyRole(tt.roles...)
			if result != tt.expected {
				t.Errorf("HasAnyRole(%v) = %v, want %v", tt.roles, result, tt.expected)
			}
		})
	}
}

func TestUser_HasAllRoles(t *testing.T) {
	user := &User{
		Roles: []string{"admin", "user", "developer"},
	}

	tests := []struct {
		name     string
		roles    []string
		expected bool
	}{
		{"has all", []string{"admin", "user"}, true},
		{"has all three", []string{"admin", "user", "developer"}, true},
		{"missing one", []string{"admin", "guest"}, false},
		{"empty roles", []string{}, true},
		{"single match", []string{"admin"}, true},
		{"single no match", []string{"guest"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := user.HasAllRoles(tt.roles...)
			if result != tt.expected {
				t.Errorf("HasAllRoles(%v) = %v, want %v", tt.roles, result, tt.expected)
			}
		})
	}
}

func TestUser_HasGroup(t *testing.T) {
	user := &User{
		Groups: []string{"engineering", "platform"},
	}

	tests := []struct {
		group    string
		expected bool
	}{
		{"engineering", true},
		{"platform", true},
		{"marketing", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.group, func(t *testing.T) {
			result := user.HasGroup(tt.group)
			if result != tt.expected {
				t.Errorf("HasGroup(%q) = %v, want %v", tt.group, result, tt.expected)
			}
		})
	}
}

func TestUser_HasAnyGroup(t *testing.T) {
	user := &User{
		Groups: []string{"engineering", "platform"},
	}

	tests := []struct {
		name     string
		groups   []string
		expected bool
	}{
		{"has engineering", []string{"engineering", "sales"}, true},
		{"has none", []string{"sales", "marketing"}, false},
		{"empty groups", []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := user.HasAnyGroup(tt.groups...)
			if result != tt.expected {
				t.Errorf("HasAnyGroup(%v) = %v, want %v", tt.groups, result, tt.expected)
			}
		})
	}
}

func TestUser_RolesString(t *testing.T) {
	tests := []struct {
		name     string
		roles    []string
		expected string
	}{
		{"multiple roles", []string{"admin", "user"}, "admin,user"},
		{"single role", []string{"admin"}, "admin"},
		{"no roles", []string{}, ""},
		{"nil roles", nil, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &User{Roles: tt.roles}
			result := user.RolesString()
			if result != tt.expected {
				t.Errorf("RolesString() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestUser_GroupsString(t *testing.T) {
	tests := []struct {
		name     string
		groups   []string
		expected string
	}{
		{"multiple groups", []string{"eng", "platform"}, "eng,platform"},
		{"single group", []string{"eng"}, "eng"},
		{"no groups", []string{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &User{Groups: tt.groups}
			result := user.GroupsString()
			if result != tt.expected {
				t.Errorf("GroupsString() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestUser_DisplayName(t *testing.T) {
	tests := []struct {
		name     string
		user     *User
		expected string
	}{
		{
			name:     "preferred name",
			user:     &User{PreferredName: "Johnny", Name: "John Doe", GivenName: "John", FamilyName: "Doe", Email: "john@example.com"},
			expected: "Johnny",
		},
		{
			name:     "name",
			user:     &User{Name: "John Doe", GivenName: "John", FamilyName: "Doe", Email: "john@example.com"},
			expected: "John Doe",
		},
		{
			name:     "given and family name",
			user:     &User{GivenName: "John", FamilyName: "Doe", Email: "john@example.com"},
			expected: "John Doe",
		},
		{
			name:     "given name only",
			user:     &User{GivenName: "John", Email: "john@example.com"},
			expected: "John",
		},
		{
			name:     "email only",
			user:     &User{Email: "john@example.com"},
			expected: "john@example.com",
		},
		{
			name:     "empty",
			user:     &User{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.user.DisplayName()
			if result != tt.expected {
				t.Errorf("DisplayName() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestUser_GetClaim(t *testing.T) {
	user := &User{
		Claims: map[string]any{
			"custom_claim": "value",
			"number_claim": 42,
			"bool_claim":   true,
		},
	}

	t.Run("existing claim", func(t *testing.T) {
		value, ok := user.GetClaim("custom_claim")
		if !ok {
			t.Error("GetClaim should return true for existing claim")
		}
		if value != "value" {
			t.Errorf("GetClaim value = %v, want 'value'", value)
		}
	})

	t.Run("non-existing claim", func(t *testing.T) {
		_, ok := user.GetClaim("nonexistent")
		if ok {
			t.Error("GetClaim should return false for non-existing claim")
		}
	})

	t.Run("number claim", func(t *testing.T) {
		value, ok := user.GetClaim("number_claim")
		if !ok {
			t.Error("GetClaim should return true for number claim")
		}
		if value != 42 {
			t.Errorf("GetClaim value = %v, want 42", value)
		}
	})
}

func TestUser_GetClaimString(t *testing.T) {
	user := &User{
		Claims: map[string]any{
			"string_claim": "value",
			"number_claim": 42,
		},
	}

	tests := []struct {
		name     string
		key      string
		expected string
	}{
		{"string claim", "string_claim", "value"},
		{"number claim", "number_claim", ""},
		{"non-existing", "nonexistent", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := user.GetClaimString(tt.key)
			if result != tt.expected {
				t.Errorf("GetClaimString(%q) = %q, want %q", tt.key, result, tt.expected)
			}
		})
	}
}

func TestUser_GetClaimString_NilClaims(t *testing.T) {
	user := &User{}
	result := user.GetClaimString("any")
	if result != "" {
		t.Errorf("GetClaimString with nil claims = %q, want empty", result)
	}
}

func TestUser_Struct(t *testing.T) {
	now := time.Now()
	user := &User{
		ID:            "user-123",
		Email:         "test@example.com",
		Name:          "Test User",
		PreferredName: "Tester",
		GivenName:     "Test",
		FamilyName:    "User",
		Picture:       "https://example.com/pic.jpg",
		Locale:        "en-US",
		Roles:         []string{"admin"},
		Groups:        []string{"engineering"},
		TenantID:      "tenant-1",
		CreatedAt:     now,
		Claims:        map[string]any{"key": "value"},
	}

	if user.ID != "user-123" {
		t.Errorf("ID = %s, want user-123", user.ID)
	}
	if user.Email != "test@example.com" {
		t.Errorf("Email = %s, want test@example.com", user.Email)
	}
	if user.Picture != "https://example.com/pic.jpg" {
		t.Errorf("Picture = %s", user.Picture)
	}
	if user.Locale != "en-US" {
		t.Errorf("Locale = %s, want en-US", user.Locale)
	}
	if user.TenantID != "tenant-1" {
		t.Errorf("TenantID = %s, want tenant-1", user.TenantID)
	}
}
