package policy

import (
	"testing"
)

func TestPathMatcher_TemplateMatch(t *testing.T) {
	m := NewPathMatcher()

	tests := []struct {
		name        string
		pattern     string
		path        string
		wantMatch   bool
		wantParams  map[string]string
	}{
		{
			name:      "simple template match",
			pattern:   "/api/v1/{resource}/{id}",
			path:      "/api/v1/users/123",
			wantMatch: true,
			wantParams: map[string]string{
				"resource": "users",
				"id":       "123",
			},
		},
		{
			name:      "template with resource_type and resource_id",
			pattern:   "/api/v1/{resource_type}/{resource_id}",
			path:      "/api/v1/orders/order-456",
			wantMatch: true,
			wantParams: map[string]string{
				"resource_type": "orders",
				"resource_id":   "order-456",
			},
		},
		{
			name:      "template with action",
			pattern:   "/api/v1/{resource}/{id}/{action}",
			path:      "/api/v1/users/123/activate",
			wantMatch: true,
			wantParams: map[string]string{
				"resource": "users",
				"id":       "123",
				"action":   "activate",
			},
		},
		{
			name:      "template with custom regex pattern",
			pattern:   "/api/v{version:\\d+}/{resource}/{id}",
			path:      "/api/v2/products/abc",
			wantMatch: true,
			wantParams: map[string]string{
				"version":  "2",
				"resource": "products",
				"id":       "abc",
			},
		},
		{
			name:      "template no match - wrong path",
			pattern:   "/api/v1/{resource}/{id}",
			path:      "/api/v2/users/123",
			wantMatch: false,
		},
		{
			name:      "template no match - missing segment",
			pattern:   "/api/v1/{resource}/{id}",
			path:      "/api/v1/users",
			wantMatch: false,
		},
		{
			name:      "template with UUID pattern",
			pattern:   "/api/v1/{resource}/{uuid:[0-9a-f-]+}",
			path:      "/api/v1/items/550e8400-e29b-41d4-a716-446655440000",
			wantMatch: true,
			wantParams: map[string]string{
				"resource": "items",
				"uuid":     "550e8400-e29b-41d4-a716-446655440000",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := m.Match(tt.pattern, tt.path)
			if result.Matched != tt.wantMatch {
				t.Errorf("Match() matched = %v, want %v", result.Matched, tt.wantMatch)
			}
			if tt.wantMatch && tt.wantParams != nil {
				for k, v := range tt.wantParams {
					if result.Params[k] != v {
						t.Errorf("Match() param[%s] = %v, want %v", k, result.Params[k], v)
					}
				}
			}
		})
	}
}

func TestPathMatcher_RegexMatch(t *testing.T) {
	m := NewPathMatcher()

	tests := []struct {
		name        string
		pattern     string
		path        string
		wantMatch   bool
		wantParams  map[string]string
	}{
		{
			name:      "regex with named groups",
			pattern:   "^/api/v(?P<version>\\d+)/(?P<resource>\\w+)/(?P<id>[^/]+)$",
			path:      "/api/v1/users/123",
			wantMatch: true,
			wantParams: map[string]string{
				"version":  "1",
				"resource": "users",
				"id":       "123",
			},
		},
		{
			name:      "regex no match",
			pattern:   "^/api/v(?P<version>\\d+)/users/(?P<id>\\d+)$",
			path:      "/api/v1/users/abc",
			wantMatch: false,
		},
		{
			name:      "regex with optional segment",
			pattern:   "^/api/(?P<resource>\\w+)(/(?P<id>[^/]+))?$",
			path:      "/api/users",
			wantMatch: true,
			wantParams: map[string]string{
				"resource": "users",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := m.Match(tt.pattern, tt.path)
			if result.Matched != tt.wantMatch {
				t.Errorf("Match() matched = %v, want %v", result.Matched, tt.wantMatch)
			}
			if tt.wantMatch && tt.wantParams != nil {
				for k, v := range tt.wantParams {
					if result.Params[k] != v {
						t.Errorf("Match() param[%s] = %v, want %v", k, result.Params[k], v)
					}
				}
			}
		})
	}
}

func TestPathMatcher_GlobFallback(t *testing.T) {
	m := NewPathMatcher()

	tests := []struct {
		name      string
		patterns  []string
		path      string
		wantMatch bool
	}{
		{
			name:      "glob wildcard",
			patterns:  []string{"/api/v1/*"},
			path:      "/api/v1/users",
			wantMatch: true,
		},
		{
			name:      "glob double wildcard",
			patterns:  []string{"/api/**"},
			path:      "/api/v1/users/123/profile",
			wantMatch: true,
		},
		{
			name:      "glob exact match",
			patterns:  []string{"/health", "/ready"},
			path:      "/health",
			wantMatch: true,
		},
		{
			name:      "glob no match",
			patterns:  []string{"/api/v1/*"},
			path:      "/api/v2/users",
			wantMatch: false,
		},
		{
			name:      "mixed patterns - template wins",
			patterns:  []string{"/api/v1/{resource}/{id}", "/api/*"},
			path:      "/api/v1/users/123",
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := m.MatchWithGlobFallback(tt.patterns, tt.path)
			if result.Matched != tt.wantMatch {
				t.Errorf("MatchWithGlobFallback() matched = %v, want %v", result.Matched, tt.wantMatch)
			}
		})
	}
}

func TestPathMatcher_CacheHit(t *testing.T) {
	m := NewPathMatcher()

	pattern := "/api/v1/{resource}/{id}"
	path := "/api/v1/users/123"

	// First match - cache miss
	result1 := m.Match(pattern, path)
	if !result1.Matched {
		t.Fatal("First match failed")
	}
	if m.CacheSize() != 1 {
		t.Errorf("Cache size after first match = %d, want 1", m.CacheSize())
	}

	// Second match - cache hit
	result2 := m.Match(pattern, path)
	if !result2.Matched {
		t.Fatal("Second match failed")
	}
	if m.CacheSize() != 1 {
		t.Errorf("Cache size after second match = %d, want 1", m.CacheSize())
	}

	// Different pattern - cache miss
	m.Match("/api/v2/{resource}", "/api/v2/orders")
	if m.CacheSize() != 2 {
		t.Errorf("Cache size after third pattern = %d, want 2", m.CacheSize())
	}
}

func TestPathMatcher_PrecompilePatterns(t *testing.T) {
	m := NewPathMatcher()

	// Start with empty cache
	if m.CacheSize() != 0 {
		t.Errorf("Initial cache size = %d, want 0", m.CacheSize())
	}

	patterns := []string{
		"/api/v1/{resource}/{id}",
		"/api/v2/users/*",
		"/health",
		"",  // empty string should be ignored
		"/admin/{action}",
	}

	// Pre-compile patterns
	compiled := m.PrecompilePatterns(patterns)

	// Should compile 4 patterns (empty string ignored)
	if compiled != 4 {
		t.Errorf("Precompiled count = %d, want 4", compiled)
	}

	// Cache should have 4 entries
	if m.CacheSize() != 4 {
		t.Errorf("Cache size after precompile = %d, want 4", m.CacheSize())
	}

	// Now matching should use cached patterns (no cache misses)
	result := m.Match("/api/v1/{resource}/{id}", "/api/v1/users/123")
	if !result.Matched {
		t.Error("Match failed for precompiled pattern")
	}
	if result.Params["resource"] != "users" {
		t.Errorf("Params[resource] = %q, want 'users'", result.Params["resource"])
	}
}

func TestCIDRMatcher_Match(t *testing.T) {
	m := NewCIDRMatcher()

	tests := []struct {
		name      string
		cidrs     []string
		ip        string
		wantMatch bool
	}{
		{
			name:      "exact IP match",
			cidrs:     []string{"192.168.1.1"},
			ip:        "192.168.1.1",
			wantMatch: true,
		},
		{
			name:      "CIDR /24 match",
			cidrs:     []string{"192.168.1.0/24"},
			ip:        "192.168.1.100",
			wantMatch: true,
		},
		{
			name:      "CIDR /24 no match",
			cidrs:     []string{"192.168.1.0/24"},
			ip:        "192.168.2.1",
			wantMatch: false,
		},
		{
			name:      "wildcard match",
			cidrs:     []string{"*"},
			ip:        "10.0.0.1",
			wantMatch: true,
		},
		{
			name:      "multiple CIDRs",
			cidrs:     []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			ip:        "172.20.1.1",
			wantMatch: true,
		},
		{
			name:      "IP with port",
			cidrs:     []string{"192.168.1.0/24"},
			ip:        "192.168.1.100:8080",
			wantMatch: true,
		},
		{
			name:      "empty CIDR list",
			cidrs:     []string{},
			ip:        "192.168.1.1",
			wantMatch: true, // No restriction
		},
		{
			name:      "IPv6 match",
			cidrs:     []string{"::1/128"},
			ip:        "::1",
			wantMatch: true,
		},
		{
			name:      "IPv6 CIDR match",
			cidrs:     []string{"2001:db8::/32"},
			ip:        "2001:db8::1",
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := m.Match(tt.cidrs, tt.ip)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestExtractResource(t *testing.T) {
	tests := []struct {
		name       string
		params     map[string]string
		wantType   string
		wantID     string
		wantAction string
	}{
		{
			name: "standard names",
			params: map[string]string{
				"resource_type": "users",
				"resource_id":   "123",
				"action":        "read",
			},
			wantType:   "users",
			wantID:     "123",
			wantAction: "read",
		},
		{
			name: "short names",
			params: map[string]string{
				"resource": "orders",
				"id":       "456",
			},
			wantType: "orders",
			wantID:   "456",
		},
		{
			name: "mixed names",
			params: map[string]string{
				"type": "products",
				"uuid": "abc-123",
			},
			wantType: "products",
			wantID:   "abc-123",
		},
		{
			name:   "empty params",
			params: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource := ExtractResource(tt.params)
			if len(tt.params) == 0 {
				if resource != nil {
					t.Error("Expected nil resource for empty params")
				}
				return
			}

			if resource.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", resource.Type, tt.wantType)
			}
			if resource.ID != tt.wantID {
				t.Errorf("ID = %v, want %v", resource.ID, tt.wantID)
			}
			if resource.Action != tt.wantAction {
				t.Errorf("Action = %v, want %v", resource.Action, tt.wantAction)
			}
		})
	}
}

func TestTemplateToRegex(t *testing.T) {
	tests := []struct {
		template string
		expected string
	}{
		{
			template: "/api/v1/{resource}/{id}",
			expected: "^/api/v1/(?P<resource>[^/]+)/(?P<id>[^/]+)$",
		},
		{
			template: "/api/v{version:\\d+}/{resource}",
			expected: "^/api/v(?P<version>\\d+)/(?P<resource>[^/]+)$",
		},
		{
			template: "/files/**",
			expected: "^/files/.*$",
		},
		{
			template: "/api/*",
			expected: "^/api/[^/]*$",
		},
		{
			template: "/api/v1/users.json",
			expected: "^/api/v1/users\\.json$",
		},
	}

	for _, tt := range tests {
		t.Run(tt.template, func(t *testing.T) {
			got := templateToRegex(tt.template)
			if got != tt.expected {
				t.Errorf("templateToRegex(%q) = %q, want %q", tt.template, got, tt.expected)
			}
		})
	}
}

func BenchmarkPathMatcher_Match(b *testing.B) {
	m := NewPathMatcher()
	pattern := "/api/v1/{resource_type}/{resource_id}"
	path := "/api/v1/users/123"

	// Warm up cache
	m.Match(pattern, path)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Match(pattern, path)
	}
}

func BenchmarkPathMatcher_MatchNoCache(b *testing.B) {
	pattern := "/api/v1/{resource_type}/{resource_id}"
	path := "/api/v1/users/123"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m := NewPathMatcher()
		m.Match(pattern, path)
	}
}

func BenchmarkCIDRMatcher_Match(b *testing.B) {
	m := NewCIDRMatcher()
	cidrs := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	ip := "172.20.1.1"

	// Warm up cache
	m.Match(cidrs, ip)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Match(cidrs, ip)
	}
}
