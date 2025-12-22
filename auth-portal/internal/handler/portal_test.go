package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPortalHandler(t *testing.T) {
	cfg := &config.Config{}

	h := NewPortalHandler(nil, cfg, nil)
	require.NotNil(t, h)
	assert.Equal(t, cfg, h.config)
}

func TestPortalHandler_getServicesForUser(t *testing.T) {
	cfg := &config.Config{
		Services: []config.ServiceConfig{
			{
				Name:        "grafana",
				DisplayName: "Grafana",
				Description: "Metrics dashboard",
				Location:    "/grafana/",
				Icon:        "chart-line",
			},
			{
				Name:        "kibana",
				DisplayName: "Kibana",
				Description: "Log viewer",
				Upstream:    "http://kibana:5601",
				Icon:        "search",
			},
			{
				Name:        "prometheus",
				DisplayName: "Prometheus",
				Description: "Metrics database",
				Location:    "/prom/",
				Upstream:    "http://prometheus:9090",
				Icon:        "database",
			},
		},
	}

	h := NewPortalHandler(nil, cfg, nil)
	user := &model.User{ID: "user-1", Email: "user@example.com"}

	services := h.getServicesForUser(user)

	assert.Len(t, services, 3)

	// Check first service
	assert.Equal(t, "grafana", services[0].Name)
	assert.Equal(t, "Grafana", services[0].DisplayName)
	assert.Equal(t, "Metrics dashboard", services[0].Description)
	assert.Equal(t, "/grafana/", services[0].URL)
	assert.Equal(t, "chart-line", services[0].Icon)

	// Check second service (has upstream but no location)
	assert.Equal(t, "http://kibana:5601", services[1].URL)

	// Check third service (has both location and upstream, should use location)
	assert.Equal(t, "/prom/", services[2].URL)
}

func TestPortalHandler_getServicesForUser_Empty(t *testing.T) {
	cfg := &config.Config{
		Services: []config.ServiceConfig{},
	}

	h := NewPortalHandler(nil, cfg, nil)
	user := &model.User{ID: "user-1"}

	services := h.getServicesForUser(user)

	assert.Empty(t, services)
}

func TestPortalHandler_renderJSONError(t *testing.T) {
	h := NewPortalHandler(nil, &config.Config{}, nil)

	rr := httptest.NewRecorder()
	h.renderJSONError(rr, "Test error", http.StatusBadRequest)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
}

func TestPortalPageData_Struct(t *testing.T) {
	user := &model.User{ID: "user-1", Email: "test@example.com"}
	services := []ServiceView{
		{Name: "service1", DisplayName: "Service 1"},
		{Name: "service2", DisplayName: "Service 2"},
	}

	data := PortalPageData{
		Title:    "Portal",
		User:     user,
		Services: services,
		Error:    "",
	}

	assert.Equal(t, "Portal", data.Title)
	assert.Equal(t, "user-1", data.User.ID)
	assert.Len(t, data.Services, 2)
}

func TestServiceView_Struct(t *testing.T) {
	sv := ServiceView{
		Name:        "grafana",
		DisplayName: "Grafana Dashboard",
		Description: "Metrics visualization",
		URL:         "/grafana/",
		Icon:        "chart-line",
	}

	assert.Equal(t, "grafana", sv.Name)
	assert.Equal(t, "Grafana Dashboard", sv.DisplayName)
	assert.Equal(t, "Metrics visualization", sv.Description)
	assert.Equal(t, "/grafana/", sv.URL)
	assert.Equal(t, "chart-line", sv.Icon)
}

func TestPortalHandler_isUserAdmin(t *testing.T) {
	cfg := &config.Config{}
	h := NewPortalHandler(nil, cfg, nil, WithAdminRoles([]string{"admin", "superuser"}))

	tests := []struct {
		name     string
		roles    []string
		expected bool
	}{
		{"user has admin role", []string{"user", "admin"}, true},
		{"user has superuser role", []string{"superuser"}, true},
		{"user has no admin roles", []string{"user", "viewer"}, false},
		{"user has empty roles", []string{}, false},
		{"user has multiple roles including admin", []string{"viewer", "editor", "admin"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &model.User{ID: "user-1", Roles: tt.roles}
			result := h.isUserAdmin(user)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPortalHandler_isUserAdmin_defaultRoles(t *testing.T) {
	cfg := &config.Config{}
	// Default admin roles: admin, administrator, portal-admin
	h := NewPortalHandler(nil, cfg, nil)

	t.Run("user with admin role", func(t *testing.T) {
		user := &model.User{ID: "user-1", Roles: []string{"admin"}}
		assert.True(t, h.isUserAdmin(user))
	})

	t.Run("user with administrator role", func(t *testing.T) {
		user := &model.User{ID: "user-1", Roles: []string{"administrator"}}
		assert.True(t, h.isUserAdmin(user))
	})

	t.Run("user with portal-admin role", func(t *testing.T) {
		user := &model.User{ID: "user-1", Roles: []string{"portal-admin"}}
		assert.True(t, h.isUserAdmin(user))
	})

	t.Run("user without admin role", func(t *testing.T) {
		user := &model.User{ID: "user-1", Roles: []string{"user"}}
		assert.False(t, h.isUserAdmin(user))
	})

	t.Run("nil user", func(t *testing.T) {
		assert.False(t, h.isUserAdmin(nil))
	})
}

func TestPortalHandler_WithSecurityWarnings(t *testing.T) {
	cfg := &config.Config{}

	t.Run("sets security warnings", func(t *testing.T) {
		// We can't directly access securityWarnings, but we can verify the option doesn't panic
		h := NewPortalHandler(nil, cfg, nil, WithSecurityWarnings(nil))
		require.NotNil(t, h)
	})
}

func TestPortalHandler_WithAdminRoles(t *testing.T) {
	cfg := &config.Config{}
	customRoles := []string{"root", "superadmin"}

	h := NewPortalHandler(nil, cfg, nil, WithAdminRoles(customRoles))
	require.NotNil(t, h)

	// Verify custom roles work
	user := &model.User{ID: "user-1", Roles: []string{"root"}}
	assert.True(t, h.isUserAdmin(user))

	// Verify default roles don't work anymore
	user2 := &model.User{ID: "user-2", Roles: []string{"admin"}}
	assert.False(t, h.isUserAdmin(user2))
}

func TestPortalHandler_renderError_noTemplates(t *testing.T) {
	h := NewPortalHandler(nil, &config.Config{}, nil)

	w := httptest.NewRecorder()
	h.renderError(w, "Test error", http.StatusBadRequest)

	// Without templates, renderError should fall back to JSON
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Body.String(), "Test error")
}

func BenchmarkGetServicesForUser(b *testing.B) {
	cfg := &config.Config{
		Services: []config.ServiceConfig{
			{Name: "service1", Location: "/s1/"},
			{Name: "service2", Location: "/s2/"},
			{Name: "service3", Location: "/s3/"},
			{Name: "service4", Location: "/s4/"},
			{Name: "service5", Location: "/s5/"},
		},
	}

	h := NewPortalHandler(nil, cfg, nil)
	user := &model.User{ID: "user-1"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.getServicesForUser(user)
	}
}
