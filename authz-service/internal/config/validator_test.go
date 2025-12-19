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
						{Name: "api", Port: 8080, Routes: []RouteConfig{{PathPrefix: "/api"}}},
						{Name: "admin", Port: 8081, Routes: []RouteConfig{{PathPrefix: "/admin"}}},
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
						{Name: "api", Port: 8080, Routes: []RouteConfig{{PathPrefix: "/api"}}},
						{Name: "admin", Port: 8080, Routes: []RouteConfig{{PathPrefix: "/admin"}}}, // duplicate
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
						{Name: "api", Port: 8080, Routes: []RouteConfig{{PathPrefix: "/api"}}},
					},
				},
				Egress: EgressListenersConfig{
					Listeners: []EgressListenerConfig{
						{Name: "external", Port: 8080, Targets: map[string]EgressTargetConfig{"svc": {URL: "https://example.com"}}}, // conflict with proxy
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
						{Name: "api", Port: 15000, Routes: []RouteConfig{{PathPrefix: "/api"}}}, // conflict with management admin
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
						{Name: "api", Port: 8080, Routes: []RouteConfig{{PathPrefix: "/api"}}}, // conflict with HTTP server
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
						{Name: "api", Port: 15000, Routes: []RouteConfig{{PathPrefix: "/api"}}}, // same as management but disabled
					},
				},
			},
			envCfg: &EnvironmentConfig{
				Management: ManagementServerConfig{
					Enabled:   false, // disabled
					AdminAddr: ":15000",
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewConfigValidator()
			err := v.ValidateServices(tt.serviceCfg, tt.envCfg)

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
		expectError bool
		errorCount  int
	}{
		{
			name: "valid rule set references",
			serviceCfg: &ServicesConfig{
				RuleSets: map[string][]RouteConfig{
					"api-rules":   {{PathPrefix: "/api"}},
					"admin-rules": {{PathPrefix: "/admin"}},
				},
				Proxy: ProxyListenersConfig{
					Listeners: []ProxyListenerConfig{
						{
							Name:     "api",
							Port:     8080,
							RuleSets: []string{"api-rules"},
						},
						{
							Name:     "admin",
							Port:     8081,
							RuleSets: []string{"admin-rules"},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "missing rule set reference",
			serviceCfg: &ServicesConfig{
				RuleSets: map[string][]RouteConfig{
					"api-rules": {{PathPrefix: "/api"}},
				},
				Proxy: ProxyListenersConfig{
					Listeners: []ProxyListenerConfig{
						{
							Name:     "api",
							Port:     8080,
							RuleSets: []string{"api-rules", "missing-rules"}, // missing-rules doesn't exist
						},
					},
				},
			},
			expectError: true,
			errorCount:  1,
		},
		{
			name: "no rule sets defined but referenced",
			serviceCfg: &ServicesConfig{
				RuleSets: nil, // no rule sets defined
				Proxy: ProxyListenersConfig{
					Listeners: []ProxyListenerConfig{
						{
							Name:     "api",
							Port:     8080,
							RuleSets: []string{"some-rules"},
						},
					},
				},
			},
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
							Routes:   []RouteConfig{{PathPrefix: "/api"}},
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
			err := v.ValidateServices(tt.serviceCfg, nil)

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
							Routes: []RouteConfig{{PathPrefix: "/api"}},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "proxy listener with rule_sets - valid",
			serviceCfg: &ServicesConfig{
				RuleSets: map[string][]RouteConfig{
					"api-rules": {{PathPrefix: "/api"}},
				},
				Proxy: ProxyListenersConfig{
					Listeners: []ProxyListenerConfig{
						{
							Name:     "api",
							Port:     8080,
							RuleSets: []string{"api-rules"},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "proxy listener without routes or rule_sets - error",
			serviceCfg: &ServicesConfig{
				Proxy: ProxyListenersConfig{
					Listeners: []ProxyListenerConfig{
						{
							Name: "api",
							Port: 8080,
							// No routes, no rule_sets
						},
					},
				},
			},
			expectError: true,
			errorCount:  1,
		},
		{
			name: "empty rule_set - error",
			serviceCfg: &ServicesConfig{
				RuleSets: map[string][]RouteConfig{
					"empty-rules": {}, // Empty rule set
				},
				Proxy: ProxyListenersConfig{
					Listeners: []ProxyListenerConfig{
						{
							Name:     "api",
							Port:     8080,
							RuleSets: []string{"empty-rules"},
						},
					},
				},
			},
			expectError: true,
			errorCount:  1, // One error for empty rule set
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
			err := v.ValidateServices(tt.serviceCfg, nil)

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
			name: "unique priorities - valid",
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
			name: "duplicate priorities - error",
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
			name: "multiple duplicate priorities - multiple errors",
			rulesCfg: &RulesConfig{
				Rules: []Rule{
					{Name: "rule-1", Priority: 100},
					{Name: "rule-2", Priority: 100}, // duplicate
					{Name: "rule-3", Priority: 50},
					{Name: "rule-4", Priority: 50}, // another duplicate
				},
			},
			expectError: true,
			errorCount:  2,
		},
		{
			name: "empty rules - valid",
			rulesCfg: &RulesConfig{
				Rules: nil,
			},
			expectError: false,
		},
		{
			name:        "nil config - valid",
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

func TestMergeRoutesForListener(t *testing.T) {
	tests := []struct {
		name           string
		listener       ProxyListenerConfig
		ruleSets       map[string][]RouteConfig
		expectedCount  int
		expectedFirst  string // PathPrefix of first route (from rule sets)
		expectedLast   string // PathPrefix of last route (from inline routes)
	}{
		{
			name: "merge rule sets and inline routes",
			listener: ProxyListenerConfig{
				RuleSets: []string{"api-rules"},
				Routes: []RouteConfig{
					{PathPrefix: "/inline"},
				},
			},
			ruleSets: map[string][]RouteConfig{
				"api-rules": {
					{PathPrefix: "/api"},
				},
			},
			expectedCount: 2,
			expectedFirst: "/api",    // from rule set
			expectedLast:  "/inline", // from inline routes
		},
		{
			name: "multiple rule sets merged in order",
			listener: ProxyListenerConfig{
				RuleSets: []string{"first-set", "second-set"},
				Routes:   nil,
			},
			ruleSets: map[string][]RouteConfig{
				"first-set": {
					{PathPrefix: "/first"},
				},
				"second-set": {
					{PathPrefix: "/second"},
				},
			},
			expectedCount: 2,
			expectedFirst: "/first",  // first rule set
			expectedLast:  "/second", // second rule set
		},
		{
			name: "inline routes only - preserves order",
			listener: ProxyListenerConfig{
				RuleSets: nil,
				Routes: []RouteConfig{
					{PathPrefix: "/b"},
					{PathPrefix: "/a"},
				},
			},
			ruleSets:      nil,
			expectedCount: 2,
			expectedFirst: "/b", // first inline route
			expectedLast:  "/a", // second inline route (order preserved)
		},
		{
			name: "empty configuration",
			listener: ProxyListenerConfig{
				RuleSets: nil,
				Routes:   nil,
			},
			ruleSets:      nil,
			expectedCount: 0,
		},
		{
			name: "missing rule set reference - only inline routes",
			listener: ProxyListenerConfig{
				RuleSets: []string{"missing"},
				Routes: []RouteConfig{
					{PathPrefix: "/inline"},
				},
			},
			ruleSets:      map[string][]RouteConfig{},
			expectedCount: 1,
			expectedFirst: "/inline",
			expectedLast:  "/inline",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MergeRoutesForListener(tt.listener, tt.ruleSets)

			assert.Len(t, result, tt.expectedCount)

			if tt.expectedCount > 0 {
				assert.Equal(t, tt.expectedFirst, result[0].PathPrefix)
				assert.Equal(t, tt.expectedLast, result[len(result)-1].PathPrefix)
			}
		})
	}
}

func TestValidationError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ValidationError
		expected string
	}{
		{
			name: "simple error without details",
			err: ValidationError{
				Field:   "port",
				Message: "must be unique",
			},
			expected: "port: must be unique",
		},
		{
			name: "error with details",
			err: ValidationError{
				Field:   "listeners",
				Message: "port conflict",
				Details: []string{"proxy:api", "proxy:admin"},
			},
			expected: "listeners: port conflict\n    - proxy:api\n    - proxy:admin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestValidationErrors_Error(t *testing.T) {
	errs := ValidationErrors{
		{Field: "port", Message: "must be unique"},
		{Field: "rule_sets", Message: "not found"},
	}

	result := errs.Error()
	assert.Contains(t, result, "configuration validation failed:")
	assert.Contains(t, result, "port: must be unique")
	assert.Contains(t, result, "rule_sets: not found")
}
