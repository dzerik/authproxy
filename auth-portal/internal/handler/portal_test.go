package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/model"
)

func TestNewPortalHandler(t *testing.T) {
	cfg := &config.Config{}

	h := NewPortalHandler(nil, cfg, nil)
	if h == nil {
		t.Fatal("NewPortalHandler returned nil")
	}
	if h.config != cfg {
		t.Error("config not set correctly")
	}
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

	if len(services) != 3 {
		t.Errorf("services length = %d, want 3", len(services))
	}

	// Check first service
	if services[0].Name != "grafana" {
		t.Errorf("services[0].Name = %s, want grafana", services[0].Name)
	}
	if services[0].DisplayName != "Grafana" {
		t.Errorf("services[0].DisplayName = %s, want Grafana", services[0].DisplayName)
	}
	if services[0].Description != "Metrics dashboard" {
		t.Errorf("services[0].Description = %s", services[0].Description)
	}
	if services[0].URL != "/grafana/" {
		t.Errorf("services[0].URL = %s, want /grafana/", services[0].URL)
	}
	if services[0].Icon != "chart-line" {
		t.Errorf("services[0].Icon = %s, want chart-line", services[0].Icon)
	}

	// Check second service (has upstream but no location)
	if services[1].URL != "http://kibana:5601" {
		t.Errorf("services[1].URL = %s, want http://kibana:5601 (from upstream)", services[1].URL)
	}

	// Check third service (has both location and upstream, should use location)
	if services[2].URL != "/prom/" {
		t.Errorf("services[2].URL = %s, want /prom/", services[2].URL)
	}
}

func TestPortalHandler_getServicesForUser_Empty(t *testing.T) {
	cfg := &config.Config{
		Services: []config.ServiceConfig{},
	}

	h := NewPortalHandler(nil, cfg, nil)
	user := &model.User{ID: "user-1"}

	services := h.getServicesForUser(user)

	if len(services) != 0 {
		t.Errorf("services length = %d, want 0", len(services))
	}
}

func TestPortalHandler_renderJSONError(t *testing.T) {
	h := NewPortalHandler(nil, &config.Config{}, nil)

	rr := httptest.NewRecorder()
	h.renderJSONError(rr, "Test error", http.StatusBadRequest)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}

	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %s, want application/json", ct)
	}
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

	if data.Title != "Portal" {
		t.Errorf("Title = %s, want Portal", data.Title)
	}
	if data.User.ID != "user-1" {
		t.Errorf("User.ID = %s, want user-1", data.User.ID)
	}
	if len(data.Services) != 2 {
		t.Errorf("Services length = %d, want 2", len(data.Services))
	}
}

func TestServiceView_Struct(t *testing.T) {
	sv := ServiceView{
		Name:        "grafana",
		DisplayName: "Grafana Dashboard",
		Description: "Metrics visualization",
		URL:         "/grafana/",
		Icon:        "chart-line",
	}

	if sv.Name != "grafana" {
		t.Errorf("Name = %s, want grafana", sv.Name)
	}
	if sv.DisplayName != "Grafana Dashboard" {
		t.Errorf("DisplayName = %s, want Grafana Dashboard", sv.DisplayName)
	}
	if sv.Description != "Metrics visualization" {
		t.Errorf("Description = %s, want Metrics visualization", sv.Description)
	}
	if sv.URL != "/grafana/" {
		t.Errorf("URL = %s, want /grafana/", sv.URL)
	}
	if sv.Icon != "chart-line" {
		t.Errorf("Icon = %s, want chart-line", sv.Icon)
	}
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
