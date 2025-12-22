package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	assert.Equal(t, "grafana", service.Name)
	assert.Equal(t, "Grafana Monitoring", service.DisplayName)
	assert.Equal(t, "Metrics visualization", service.Description)
	assert.Equal(t, "chart-line", service.Icon)
	assert.Equal(t, "/grafana/", service.Location)
	assert.Equal(t, "http://grafana:3000", service.Upstream)
	assert.True(t, service.AuthRequired)
	assert.Equal(t, "^/grafana/(.*) /$1 break", service.Rewrite)
	assert.Equal(t, "test", service.Headers.Add["X-User"])
	require.Len(t, service.Headers.Remove, 1)
	assert.Equal(t, "Authorization", service.Headers.Remove[0])
	assert.NotEmpty(t, service.NginxExtra)
}

func TestServiceHeaders_Struct(t *testing.T) {
	headers := ServiceHeaders{
		Add: map[string]string{
			"X-Header-1": "value1",
			"X-Header-2": "value2",
		},
		Remove: []string{"Cookie", "Authorization"},
	}

	assert.Len(t, headers.Add, 2)
	assert.Equal(t, "value1", headers.Add["X-Header-1"])
	assert.Len(t, headers.Remove, 2)
}

func TestNewServiceList(t *testing.T) {
	services := []Service{
		{Name: "service-1"},
		{Name: "service-2"},
		{Name: "service-3"},
	}

	list := NewServiceList(services)

	require.NotNil(t, list)
	assert.Len(t, list.Services, 3)
	assert.Equal(t, 3, list.Total)
}

func TestNewServiceList_Empty(t *testing.T) {
	list := NewServiceList([]Service{})

	require.NotNil(t, list)
	assert.Len(t, list.Services, 0)
	assert.Equal(t, 0, list.Total)
}

func TestNewServiceList_Nil(t *testing.T) {
	list := NewServiceList(nil)

	require.NotNil(t, list)
	assert.Equal(t, 0, list.Total)
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
		assert.Equal(t, 3, filtered.Total)
		for _, svc := range filtered.Services {
			assert.True(t, svc.AuthRequired, "Service %s should have AuthRequired=true", svc.Name)
		}
	})

	t.Run("filter no auth required", func(t *testing.T) {
		filtered := list.FilterByAuth(false)
		assert.Equal(t, 2, filtered.Total)
		for _, svc := range filtered.Services {
			assert.False(t, svc.AuthRequired, "Service %s should have AuthRequired=false", svc.Name)
		}
	})
}

func TestServiceList_FilterByAuth_Empty(t *testing.T) {
	list := NewServiceList([]Service{})

	filtered := list.FilterByAuth(true)
	assert.Equal(t, 0, filtered.Total)
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
			if tt.found {
				require.NotNil(t, result, "FindByName(%q) should find service", tt.findName)
				assert.Equal(t, tt.findName, result.Name)
			} else {
				assert.Nil(t, result, "FindByName(%q) should not find service", tt.findName)
			}
		})
	}
}

func TestServiceList_FindByName_Empty(t *testing.T) {
	list := NewServiceList([]Service{})

	result := list.FindByName("anything")
	assert.Nil(t, result)
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
			if tt.found {
				require.NotNil(t, result, "FindByLocation(%q) should find service", tt.findLocation)
				assert.Equal(t, tt.expectedName, result.Name)
			} else {
				assert.Nil(t, result, "FindByLocation(%q) should not find service", tt.findLocation)
			}
		})
	}
}

func TestServiceList_FindByLocation_Empty(t *testing.T) {
	list := NewServiceList([]Service{})

	result := list.FindByLocation("/any/")
	assert.Nil(t, result)
}

func TestServiceList_Struct(t *testing.T) {
	list := &ServiceList{
		Services: []Service{{Name: "test"}},
		Total:    1,
	}

	assert.Equal(t, 1, list.Total)
	assert.Len(t, list.Services, 1)
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
