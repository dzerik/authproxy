package model

import (
	"testing"
)

func TestService_Struct(t *testing.T) {
	service := Service{
		Name:         "grafana",
		DisplayName:  "Grafana Monitoring",
		Description:  "Metrics visualization",
		Icon:         "chart-line",
		Location:     "/grafana/",
		Upstream:     "http://grafana:3000",
		AuthRequired: true,
		Rewrite:      "^/grafana/(.*) /$1 break",
		Headers: ServiceHeaders{
			Add:    map[string]string{"X-User": "test"},
			Remove: []string{"Authorization"},
		},
		NginxExtra: "proxy_set_header Upgrade $http_upgrade;",
	}

	if service.Name != "grafana" {
		t.Errorf("Name = %s, want grafana", service.Name)
	}
	if service.DisplayName != "Grafana Monitoring" {
		t.Errorf("DisplayName = %s", service.DisplayName)
	}
	if service.Description != "Metrics visualization" {
		t.Errorf("Description = %s", service.Description)
	}
	if service.Icon != "chart-line" {
		t.Errorf("Icon = %s", service.Icon)
	}
	if service.Location != "/grafana/" {
		t.Errorf("Location = %s", service.Location)
	}
	if service.Upstream != "http://grafana:3000" {
		t.Errorf("Upstream = %s", service.Upstream)
	}
	if !service.AuthRequired {
		t.Error("AuthRequired should be true")
	}
	if service.Rewrite != "^/grafana/(.*) /$1 break" {
		t.Errorf("Rewrite = %s", service.Rewrite)
	}
	if service.Headers.Add["X-User"] != "test" {
		t.Errorf("Headers.Add[X-User] = %s", service.Headers.Add["X-User"])
	}
	if len(service.Headers.Remove) != 1 || service.Headers.Remove[0] != "Authorization" {
		t.Errorf("Headers.Remove = %v", service.Headers.Remove)
	}
	if service.NginxExtra == "" {
		t.Error("NginxExtra should not be empty")
	}
}

func TestServiceHeaders_Struct(t *testing.T) {
	headers := ServiceHeaders{
		Add: map[string]string{
			"X-Header-1": "value1",
			"X-Header-2": "value2",
		},
		Remove: []string{"Cookie", "Authorization"},
	}

	if len(headers.Add) != 2 {
		t.Errorf("Add has %d entries, want 2", len(headers.Add))
	}
	if headers.Add["X-Header-1"] != "value1" {
		t.Errorf("Add[X-Header-1] = %s, want value1", headers.Add["X-Header-1"])
	}
	if len(headers.Remove) != 2 {
		t.Errorf("Remove has %d entries, want 2", len(headers.Remove))
	}
}

func TestNewServiceList(t *testing.T) {
	services := []Service{
		{Name: "service-1"},
		{Name: "service-2"},
		{Name: "service-3"},
	}

	list := NewServiceList(services)

	if list == nil {
		t.Fatal("NewServiceList returned nil")
	}
	if len(list.Services) != 3 {
		t.Errorf("Services length = %d, want 3", len(list.Services))
	}
	if list.Total != 3 {
		t.Errorf("Total = %d, want 3", list.Total)
	}
}

func TestNewServiceList_Empty(t *testing.T) {
	list := NewServiceList([]Service{})

	if list == nil {
		t.Fatal("NewServiceList returned nil")
	}
	if len(list.Services) != 0 {
		t.Errorf("Services length = %d, want 0", len(list.Services))
	}
	if list.Total != 0 {
		t.Errorf("Total = %d, want 0", list.Total)
	}
}

func TestNewServiceList_Nil(t *testing.T) {
	list := NewServiceList(nil)

	if list == nil {
		t.Fatal("NewServiceList returned nil")
	}
	if list.Total != 0 {
		t.Errorf("Total = %d, want 0", list.Total)
	}
}

func TestServiceList_FilterByAuth(t *testing.T) {
	services := []Service{
		{Name: "public-1", AuthRequired: false},
		{Name: "private-1", AuthRequired: true},
		{Name: "public-2", AuthRequired: false},
		{Name: "private-2", AuthRequired: true},
		{Name: "private-3", AuthRequired: true},
	}

	list := NewServiceList(services)

	t.Run("filter auth required", func(t *testing.T) {
		filtered := list.FilterByAuth(true)
		if filtered.Total != 3 {
			t.Errorf("Total = %d, want 3", filtered.Total)
		}
		for _, svc := range filtered.Services {
			if !svc.AuthRequired {
				t.Errorf("Service %s should have AuthRequired=true", svc.Name)
			}
		}
	})

	t.Run("filter no auth required", func(t *testing.T) {
		filtered := list.FilterByAuth(false)
		if filtered.Total != 2 {
			t.Errorf("Total = %d, want 2", filtered.Total)
		}
		for _, svc := range filtered.Services {
			if svc.AuthRequired {
				t.Errorf("Service %s should have AuthRequired=false", svc.Name)
			}
		}
	})
}

func TestServiceList_FilterByAuth_Empty(t *testing.T) {
	list := NewServiceList([]Service{})

	filtered := list.FilterByAuth(true)
	if filtered.Total != 0 {
		t.Errorf("Total = %d, want 0", filtered.Total)
	}
}

func TestServiceList_FindByName(t *testing.T) {
	services := []Service{
		{Name: "grafana", DisplayName: "Grafana"},
		{Name: "kibana", DisplayName: "Kibana"},
		{Name: "prometheus", DisplayName: "Prometheus"},
	}

	list := NewServiceList(services)

	tests := []struct {
		name     string
		findName string
		found    bool
	}{
		{"find grafana", "grafana", true},
		{"find kibana", "kibana", true},
		{"find prometheus", "prometheus", true},
		{"find nonexistent", "nonexistent", false},
		{"find empty", "", false},
		{"case sensitive", "Grafana", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := list.FindByName(tt.findName)
			if tt.found && result == nil {
				t.Errorf("FindByName(%q) should find service", tt.findName)
			}
			if !tt.found && result != nil {
				t.Errorf("FindByName(%q) should not find service", tt.findName)
			}
			if tt.found && result != nil && result.Name != tt.findName {
				t.Errorf("FindByName(%q) found wrong service: %s", tt.findName, result.Name)
			}
		})
	}
}

func TestServiceList_FindByName_Empty(t *testing.T) {
	list := NewServiceList([]Service{})

	result := list.FindByName("anything")
	if result != nil {
		t.Error("FindByName on empty list should return nil")
	}
}

func TestServiceList_FindByLocation(t *testing.T) {
	services := []Service{
		{Name: "grafana", Location: "/grafana/"},
		{Name: "kibana", Location: "/kibana/"},
		{Name: "prometheus", Location: "/prom/"},
	}

	list := NewServiceList(services)

	tests := []struct {
		name         string
		findLocation string
		found        bool
		expectedName string
	}{
		{"find grafana", "/grafana/", true, "grafana"},
		{"find kibana", "/kibana/", true, "kibana"},
		{"find prometheus", "/prom/", true, "prometheus"},
		{"find nonexistent", "/nonexistent/", false, ""},
		{"find empty", "", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := list.FindByLocation(tt.findLocation)
			if tt.found && result == nil {
				t.Errorf("FindByLocation(%q) should find service", tt.findLocation)
			}
			if !tt.found && result != nil {
				t.Errorf("FindByLocation(%q) should not find service", tt.findLocation)
			}
			if tt.found && result != nil && result.Name != tt.expectedName {
				t.Errorf("FindByLocation(%q) found wrong service: %s, want %s", tt.findLocation, result.Name, tt.expectedName)
			}
		})
	}
}

func TestServiceList_FindByLocation_Empty(t *testing.T) {
	list := NewServiceList([]Service{})

	result := list.FindByLocation("/any/")
	if result != nil {
		t.Error("FindByLocation on empty list should return nil")
	}
}

func TestServiceList_Struct(t *testing.T) {
	list := &ServiceList{
		Services: []Service{{Name: "test"}},
		Total:    1,
	}

	if list.Total != 1 {
		t.Errorf("Total = %d, want 1", list.Total)
	}
	if len(list.Services) != 1 {
		t.Errorf("Services length = %d, want 1", len(list.Services))
	}
}

func BenchmarkServiceList_FindByName(b *testing.B) {
	services := make([]Service, 100)
	for i := 0; i < 100; i++ {
		services[i] = Service{Name: "service-" + string(rune('0'+i%10))}
	}
	services[50].Name = "target-service"
	list := NewServiceList(services)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = list.FindByName("target-service")
	}
}

func BenchmarkServiceList_FilterByAuth(b *testing.B) {
	services := make([]Service, 100)
	for i := 0; i < 100; i++ {
		services[i] = Service{
			Name:         "service-" + string(rune('0'+i%10)),
			AuthRequired: i%2 == 0,
		}
	}
	list := NewServiceList(services)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = list.FilterByAuth(true)
	}
}
