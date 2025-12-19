package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePortFromAddr(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		expected int
	}{
		{
			name:     "port only with colon",
			addr:     ":8080",
			expected: 8080,
		},
		{
			name:     "host and port",
			addr:     "0.0.0.0:9090",
			expected: 9090,
		},
		{
			name:     "localhost and port",
			addr:     "localhost:3000",
			expected: 3000,
		},
		{
			name:     "empty string",
			addr:     "",
			expected: 0,
		},
		{
			name:     "invalid format",
			addr:     "not-a-port",
			expected: 0,
		},
		{
			name:     "IPv6 address",
			addr:     "[::1]:8080",
			expected: 8080,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parsePortFromAddr(tt.addr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfigValidator_ValidatePortUniqueness(t *testing.T) {
	tests := []struct {
		name        string
		serviceCfg  *ServicesConfig
		envCfg      *EnvironmentConfig
		expectError bool
		errorField  string
	}{
		{
			name: "unique ports - no error",
			serviceCfg: &ServicesConfig{
				Proxy: ProxyListenersConfig{
					Listeners: []ProxyListenerConfig{
						{Name: "api", Port: 8080, Routes: []RouteConfig{{PathPrefix: "/api", Upstream: "api-svc"}}, Upstreams: map[string]UpstreamConfig{"api-svc": {URL: "http://api:8080"}}},
						{Name: "admin", Port: 8081, Routes: []RouteConfig{{PathPrefix: "/admin", Upstream: "admin-svc"}}, Upstreams: map[string]UpstreamConfig{"admin-svc": {URL: "http://admin:8080"}}},
					},
				},
			},
			envCfg:      nil,
			expectError: false,
		},
		{
			name: "duplicate proxy ports - error",
			serviceCfg: &ServicesConfig{
				Proxy: ProxyListenersConfig{
					Listeners: []ProxyListenerConfig{
						{Name: "api", Port: 8080, Routes: []RouteConfig{{PathPrefix: "/api", Upstream: "api-svc"}}, Upstreams: map[string]UpstreamConfig{"api-svc": {URL: "http://api:8080"}}},
						{Name: "admin", Port: 8080, Routes: []RouteConfig{{PathPrefix: "/admin", Upstream: "admin-svc"}}, Upstreams: map[string]UpstreamConfig{"admin-svc": {URL: "http://admin:8080"}}},
					},
				},
			},
			envCfg:      nil,
			expectError: true,
			errorField:  "listeners",
		},
		{
			name: "proxy and egress port conflict - error",
			serviceCfg: &ServicesConfig{
				Proxy: ProxyListenersConfig{
					Listeners: []ProxyListenerConfig{
						{Name: "api", Port: 8080, Routes: []RouteConfig{{PathPrefix: "/api", Upstream: "api-svc"}}, Upstreams: map[string]UpstreamConfig{"api-svc": {URL: "http://api:8080"}}},
					},
				},
				Egress: EgressListenersConfig{
					Listeners: []EgressListenerConfig{
						{Name: "external", Port: 8080, Targets: map[string]EgressTargetConfig{"svc": {URL: "https://example.com"}}},
					},
				},
			},
			envCfg:      nil,
			expectError: true,
			errorField:  "listeners",
		},
		{
			name: "conflict with management port - error",
			serviceCfg: &ServicesConfig{
				Proxy: ProxyListenersConfig{
					Listeners: []ProxyListenerConfig{
						{Name: "api", Port: 15000, Routes: []RouteConfig{{PathPrefix: "/api", Upstream: "api-svc"}}, Upstreams: map[string]UpstreamConfig{"api-svc": {URL: "http://api:8080"}}},
					},
				},
			},
			envCfg: &EnvironmentConfig{
				Management: ManagementServerConfig{
					Enabled:   true,
					AdminAddr: ":15000",
				},
			},
			expectError: true,
			errorField:  "listeners",
		},
		{
			name: "conflict with HTTP server port - error",
			serviceCfg: &ServicesConfig{
				Proxy: ProxyListenersConfig{
					Listeners: []ProxyListenerConfig{
						{Name: "api", Port: 8080, Routes: []RouteConfig{{PathPrefix: "/api", Upstream: "api-svc"}}, Upstreams: map[string]UpstreamConfig{"api-svc": {URL: "http://api:8080"}}},
					},
				},
			},
			envCfg: &EnvironmentConfig{
				Server: ServerConfig{
					HTTP: HTTPServerConfig{
						Enabled: true,
						Addr:    ":8080",
					},
				},
			},
			expectError: true,
			errorField:  "listeners",
		},
		{
			name: "management disabled - no conflict",
			serviceCfg: &ServicesConfig{
				Proxy: ProxyListenersConfig{
					Listeners: []ProxyListenerConfig{
						{Name: "api", Port: 15000, Routes: []RouteConfig{{PathPrefix: "/api", Upstream: "api-svc"}}, Upstreams: map[string]UpstreamConfig{"api-svc": {URL: "http://api:8080"}}},
					},
				},
			},
			envCfg: &EnvironmentConfig{
				Management: ManagementServerConfig{
					Enabled:   false,
					AdminAddr: ":15000",
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewConfigValidator()
			err := v.ValidateServices(tt.serviceCfg, tt.envCfg, nil)

			if tt.expectError {
				require.Error(t, err)
				validationErrs, ok := err.(ValidationErrors)
				require.True(t, ok, "expected ValidationErrors type")
				assert.NotEmpty(t, validationErrs)
				if tt.errorField != "" {
					found := false
					for _, e := range validationErrs {
						if e.Field == tt.errorField {
							found = true
							break
						}
					}
					assert.True(t, found, "expected error for field %s", tt.errorField)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfigValidator_ValidateRuleSetReferences(t *testing.T) {
	tests := []struct {
		name        string
		serviceCfg  *ServicesConfig
		rulesCfg    *RulesConfig
		expectError bool
		errorCount  int
	}{
		{
			name: "valid rule set references from rules.yaml",
			serviceCfg: &ServicesConfig{
				Proxy: ProxyListenersConfig{
					Listeners: []ProxyListenerConfig{
						{
							Name:     "api",
							Port:     8080,
							RuleSets: []string{"api-rules"},
							Routes:   []RouteConfig{{PathPrefix: "/api", Upstream: "api-svc"}},
							Upstreams: map[string]UpstreamConfig{"api-svc": {URL: "http://api:8080"}},
						},
						{
							Name:     "admin",
							Port:     8081,
							RuleSets: []string{"admin-rules"},
							Routes:   []RouteConfig{{PathPrefix: "/admin", Upstream: "admin-svc"}},
							Upstreams: map[string]UpstreamConfig{"admin-svc": {URL: "http://admin:8080"}},
						},
					},
				},
			},
			rulesCfg: &RulesConfig{
				RuleSets: map[string][]Rule{
					"api-rules":   {{Name: "allow-api", Priority: 100, Effect: "allow"}},
					"admin-rules": {{Name: "allow-admin", Priority: 100, Effect: "allow"}},
				},
			},
			expectError: false,
		},
		{
			name: "missing rule set reference in rules.yaml",
			serviceCfg: &ServicesConfig{
				Proxy: ProxyListenersConfig{
					Listeners: []ProxyListenerConfig{
						{
							Name:     "api",
							Port:     8080,
							RuleSets: []string{"api-rules", "missing-rules"},
							Routes:   []RouteConfig{{PathPrefix: "/api", Upstream: "api-svc"}},
							Upstreams: map[string]UpstreamConfig{"api-svc": {URL: "http://api:8080"}},
						},
					},
				},
			},
			rulesCfg: &RulesConfig{
				RuleSets: map[string][]Rule{
					"api-rules": {{Name: "allow-api", Priority: 100, Effect: "allow"}},
				},
			},
			expectError: true,
			errorCount:  1,
		},
		{
			name: "no rule sets defined in rules.yaml but referenced",
			serviceCfg: &ServicesConfig{
				Proxy: ProxyListenersConfig{
					Listeners: []ProxyListenerConfig{
						{
							Name:     "api",
							Port:     8080,
							RuleSets: []string{"some-rules"},
							Routes:   []RouteConfig{{PathPrefix: "/api", Upstream: "api-svc"}},
							Upstreams: map[string]UpstreamConfig{"api-svc": {URL: "http://api:8080"}},
						},
					},
				},
			},
			rulesCfg: &RulesConfig{
				RuleSets: nil,
			},
			expectError: true,
			errorCount:  1,
		},
		{
			name: "nil rules config but rule sets referenced - error",
			serviceCfg: &ServicesConfig{
				Proxy: ProxyListenersConfig{
					Listeners: []ProxyListenerConfig{
						{
							Name:     "api",
							Port:     8080,
							RuleSets: []string{"some-rules"},
							Routes:   []RouteConfig{{PathPrefix: "/api", Upstream: "api-svc"}},
							Upstreams: map[string]UpstreamConfig{"api-svc": {URL: "http://api:8080"}},
						},
					},
				},
			},
			rulesCfg:    nil,
			expectError: true,
			errorCount:  1,
		},
		{
			name: "empty rule sets reference - valid",
			serviceCfg: &ServicesConfig{
				Proxy: ProxyListenersConfig{
					Listeners: []ProxyListenerConfig{
						{
							Name:     "api",
							Port:     8080,
							RuleSets: nil, // no rule sets referenced
							Routes:   []RouteConfig{{PathPrefix: "/api", Upstream: "api-svc"}},
							Upstreams: map[string]UpstreamConfig{"api-svc": {URL: "http://api:8080"}},
						},
					},
				},
			},
			rulesCfg:    nil,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewConfigValidator()
			err := v.ValidateServices(tt.serviceCfg, nil, tt.rulesCfg)

			if tt.expectError {
				require.Error(t, err)
				validationErrs, ok := err.(ValidationErrors)
				require.True(t, ok, "expected ValidationErrors type")
				assert.Len(t, validationErrs, tt.errorCount)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfigValidator_ValidateRequiredFields(t *testing.T) {
	tests := []struct {
		name        string
		serviceCfg  *ServicesConfig
		expectError bool
		errorCount  int
	}{
		{
			name: "proxy listener with routes - valid",
			serviceCfg: &ServicesConfig{
				Proxy: ProxyListenersConfig{
					Listeners: []ProxyListenerConfig{
						{
							Name:   "api",
							Port:   8080,
							Routes: []RouteConfig{{PathPrefix: "/api", Upstream: "api-svc"}},
							Upstreams: map[string]UpstreamConfig{"api-svc": {URL: "http://api:8080"}},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "proxy listener without routes - error",
			serviceCfg: &ServicesConfig{
				Proxy: ProxyListenersConfig{
					Listeners: []ProxyListenerConfig{
						{
							Name: "api",
							Port: 8080,
							// No routes
						},
					},
				},
			},
			expectError: true,
			errorCount:  1,
		},
		{
			name: "route references missing upstream - error",
			serviceCfg: &ServicesConfig{
				Proxy: ProxyListenersConfig{
					Listeners: []ProxyListenerConfig{
						{
							Name:   "api",
							Port:   8080,
							Routes: []RouteConfig{{PathPrefix: "/api", Upstream: "missing-upstream"}},
							Upstreams: map[string]UpstreamConfig{"api-svc": {URL: "http://api:8080"}},
						},
					},
				},
			},
			expectError: true,
			errorCount:  1,
		},
		{
			name: "egress listener without targets or routes - error",
			serviceCfg: &ServicesConfig{
				Egress: EgressListenersConfig{
					Listeners: []EgressListenerConfig{
						{
							Name: "external",
							Port: 9090,
							// No targets, no routes
						},
					},
				},
			},
			expectError: true,
			errorCount:  1,
		},
		{
			name: "egress listener with targets - valid",
			serviceCfg: &ServicesConfig{
				Egress: EgressListenersConfig{
					Listeners: []EgressListenerConfig{
						{
							Name: "external",
							Port: 9090,
							Targets: map[string]EgressTargetConfig{
								"service": {URL: "https://example.com"},
							},
						},
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewConfigValidator()
			err := v.ValidateServices(tt.serviceCfg, nil, nil)

			if tt.expectError {
				require.Error(t, err)
				validationErrs, ok := err.(ValidationErrors)
				require.True(t, ok, "expected ValidationErrors type")
				assert.Len(t, validationErrs, tt.errorCount)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfigValidator_ValidateRules(t *testing.T) {
	tests := []struct {
		name        string
		rulesCfg    *RulesConfig
		expectError bool
		errorCount  int
	}{
		{
			name: "unique priorities in global rules - valid",
			rulesCfg: &RulesConfig{
				Rules: []Rule{
					{Name: "rule-1", Priority: 100},
					{Name: "rule-2", Priority: 90},
					{Name: "rule-3", Priority: 80},
				},
			},
			expectError: false,
		},
		{
			name: "duplicate priorities in global rules - error",
			rulesCfg: &RulesConfig{
				Rules: []Rule{
					{Name: "rule-1", Priority: 100},
					{Name: "rule-2", Priority: 100}, // duplicate priority
				},
			},
			expectError: true,
			errorCount:  1,
		},
		{
			name: "duplicate priorities in rule set - error",
			rulesCfg: &RulesConfig{
				RuleSets: map[string][]Rule{
					"api-rules": {
						{Name: "rule-1", Priority: 100},
						{Name: "rule-2", Priority: 100}, // duplicate within set
					},
				},
			},
			expectError: true,
			errorCount:  1,
		},
		{
			name: "empty rule set - error",
			rulesCfg: &RulesConfig{
				RuleSets: map[string][]Rule{
					"empty-rules": {}, // empty
				},
			},
			expectError: true,
			errorCount:  1,
		},
		{
			name: "valid rule sets with unique priorities",
			rulesCfg: &RulesConfig{
				RuleSets: map[string][]Rule{
					"api-rules": {
						{Name: "rule-1", Priority: 100},
						{Name: "rule-2", Priority: 90},
					},
					"admin-rules": {
						{Name: "rule-3", Priority: 100}, // same priority but different set - ok
						{Name: "rule-4", Priority: 90},
					},
				},
			},
			expectError: false,
		},
		{
			name: "nil config - valid",
			rulesCfg:    nil,
			expectError: false,
		},
		{
			name: "rules without names - uses priority in error",
			rulesCfg: &RulesConfig{
				Rules: []Rule{
					{Priority: 100},
					{Priority: 100}, // duplicate, no name
				},
			},
			expectError: true,
			errorCount:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewConfigValidator()
			err := v.ValidateRules(tt.rulesCfg)

			if tt.expectError {
				require.Error(t, err)
				validationErrs, ok := err.(ValidationErrors)
				require.True(t, ok, "expected ValidationErrors type")
				assert.Len(t, validationErrs, tt.errorCount)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetRulesForListener(t *testing.T) {
	tests := []struct {
		name          string
		listener      ProxyListenerConfig
		rulesConfig   *RulesConfig
		expectedCount int
		expectedNames []string
	}{
		{
			name: "merge rule sets and global rules",
			listener: ProxyListenerConfig{
				RuleSets: []string{"api-rules"},
			},
			rulesConfig: &RulesConfig{
				RuleSets: map[string][]Rule{
					"api-rules": {
						{Name: "api-allow", Priority: 100},
					},
				},
				Rules: []Rule{
					{Name: "global-deny", Priority: 1},
				},
			},
			expectedCount: 2,
			expectedNames: []string{"api-allow", "global-deny"},
		},
		{
			name: "multiple rule sets in order",
			listener: ProxyListenerConfig{
				RuleSets: []string{"first-rules", "second-rules"},
			},
			rulesConfig: &RulesConfig{
				RuleSets: map[string][]Rule{
					"first-rules":  {{Name: "first", Priority: 100}},
					"second-rules": {{Name: "second", Priority: 90}},
				},
				Rules: []Rule{
					{Name: "global", Priority: 1},
				},
			},
			expectedCount: 3,
			expectedNames: []string{"first", "second", "global"},
		},
		{
			name: "no rule sets - only global rules",
			listener: ProxyListenerConfig{
				RuleSets: nil,
			},
			rulesConfig: &RulesConfig{
				Rules: []Rule{
					{Name: "global-only", Priority: 1},
				},
			},
			expectedCount: 1,
			expectedNames: []string{"global-only"},
		},
		{
			name: "nil rules config - empty result",
			listener: ProxyListenerConfig{
				RuleSets: []string{"api-rules"},
			},
			rulesConfig:   nil,
			expectedCount: 0,
			expectedNames: nil,
		},
		{
			name: "missing rule set - skipped",
			listener: ProxyListenerConfig{
				RuleSets: []string{"existing-rules", "missing-rules"},
			},
			rulesConfig: &RulesConfig{
				RuleSets: map[string][]Rule{
					"existing-rules": {{Name: "exists", Priority: 100}},
				},
				Rules: []Rule{
					{Name: "global", Priority: 1},
				},
			},
			expectedCount: 2, // only existing-rules and global
			expectedNames: []string{"exists", "global"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetRulesForListener(tt.listener, tt.rulesConfig)

			assert.Len(t, result, tt.expectedCount)

			if tt.expectedNames != nil {
				for i, name := range tt.expectedNames {
					assert.Equal(t, name, result[i].Name)
				}
			}
		})
	}
}
