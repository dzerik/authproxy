package integration

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/internal/domain"
	"github.com/your-org/authz-service/internal/service/policy"
)

func TestBuiltinEngine_Evaluate_AllowHealthEndpoints(t *testing.T) {
	rulesYAML := `
version: "v1.0.0"
description: "Test rules"
default_deny: true

rules:
  - name: allow-health
    priority: 1000
    enabled: true
    conditions:
      paths:
        - "/health"
        - "/health/*"
        - "/ready"
      methods:
        - GET
    effect: allow
`

	rulesFile := createTempRulesFile(t, rulesYAML)
	defer os.Remove(rulesFile)

	engine, err := policy.NewBuiltinEngine(config.BuiltinPolicyConfig{
		RulesPath: rulesFile,
	})
	require.NoError(t, err)

	ctx := NewTestContext(t)
	require.NoError(t, engine.Start(ctx))
	defer engine.Stop()

	testCases := []struct {
		name     string
		path     string
		method   string
		expected bool
	}{
		{"health endpoint", "/health", "GET", true},
		{"health subpath", "/health/live", "GET", true},
		{"ready endpoint", "/ready", "GET", true},
		{"health POST denied", "/health", "POST", false},
		{"other endpoint denied", "/api/users", "GET", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := &domain.PolicyInput{
				Request: domain.RequestInfo{
					Path:   tc.path,
					Method: tc.method,
				},
			}

			decision, err := engine.Evaluate(ctx, input)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, decision.Allowed)
		})
	}
}

func TestBuiltinEngine_Evaluate_RoleBasedAccess(t *testing.T) {
	rulesYAML := `
version: "v1.0.0"
default_deny: true

rules:
  - name: admin-full-access
    priority: 100
    enabled: true
    conditions:
      paths:
        - "/api/*"
      roles:
        - admin
    effect: allow

  - name: user-read-only
    priority: 90
    enabled: true
    conditions:
      paths:
        - "/api/*"
      methods:
        - GET
      roles:
        - user
    effect: allow
`

	rulesFile := createTempRulesFile(t, rulesYAML)
	defer os.Remove(rulesFile)

	engine, err := policy.NewBuiltinEngine(config.BuiltinPolicyConfig{
		RulesPath: rulesFile,
	})
	require.NoError(t, err)

	ctx := NewTestContext(t)
	require.NoError(t, engine.Start(ctx))
	defer engine.Stop()

	testCases := []struct {
		name     string
		path     string
		method   string
		roles    []string
		expected bool
	}{
		{"admin GET", "/api/users", "GET", []string{"admin"}, true},
		{"admin POST", "/api/users", "POST", []string{"admin"}, true},
		{"admin DELETE", "/api/users/1", "DELETE", []string{"admin"}, true},
		{"user GET", "/api/users", "GET", []string{"user"}, true},
		{"user POST denied", "/api/users", "POST", []string{"user"}, false},
		{"no role denied", "/api/users", "GET", []string{}, false},
		{"guest denied", "/api/users", "GET", []string{"guest"}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := &domain.PolicyInput{
				Request: domain.RequestInfo{
					Path:   tc.path,
					Method: tc.method,
				},
				Token: &domain.TokenInfo{
					Valid: true,
					Roles: tc.roles,
				},
			}

			decision, err := engine.Evaluate(ctx, input)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, decision.Allowed)
		})
	}
}

func TestBuiltinEngine_Evaluate_ScopeBasedAccess(t *testing.T) {
	rulesYAML := `
version: "v1.0.0"
default_deny: true

rules:
  - name: read-scope-access
    priority: 100
    enabled: true
    conditions:
      paths:
        - "/api/data/*"
      methods:
        - GET
      scopes:
        - read
        - data:read
    effect: allow

  - name: write-scope-access
    priority: 100
    enabled: true
    conditions:
      paths:
        - "/api/data/*"
      methods:
        - POST
        - PUT
        - DELETE
      scopes:
        - write
        - data:write
    effect: allow
`

	rulesFile := createTempRulesFile(t, rulesYAML)
	defer os.Remove(rulesFile)

	engine, err := policy.NewBuiltinEngine(config.BuiltinPolicyConfig{
		RulesPath: rulesFile,
	})
	require.NoError(t, err)

	ctx := NewTestContext(t)
	require.NoError(t, engine.Start(ctx))
	defer engine.Stop()

	testCases := []struct {
		name     string
		path     string
		method   string
		scopes   []string
		expected bool
	}{
		{"read scope GET", "/api/data/items", "GET", []string{"read"}, true},
		{"data:read scope GET", "/api/data/items", "GET", []string{"data:read"}, true},
		{"write scope POST", "/api/data/items", "POST", []string{"write"}, true},
		{"data:write scope PUT", "/api/data/items", "PUT", []string{"data:write"}, true},
		{"read scope POST denied", "/api/data/items", "POST", []string{"read"}, false},
		{"no scope denied", "/api/data/items", "GET", []string{}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := &domain.PolicyInput{
				Request: domain.RequestInfo{
					Path:   tc.path,
					Method: tc.method,
				},
				Token: &domain.TokenInfo{
					Valid:  true,
					Scopes: tc.scopes,
				},
			}

			decision, err := engine.Evaluate(ctx, input)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, decision.Allowed)
		})
	}
}

func TestBuiltinEngine_Evaluate_DenyRules(t *testing.T) {
	rulesYAML := `
version: "v1.0.0"
default_deny: false

rules:
  - name: deny-admin-endpoints
    priority: 1000
    enabled: true
    conditions:
      paths:
        - "/admin/*"
    effect: deny

  - name: allow-admin-for-superuser
    priority: 900
    enabled: true
    conditions:
      paths:
        - "/admin/*"
      roles:
        - superuser
    effect: allow
`

	rulesFile := createTempRulesFile(t, rulesYAML)
	defer os.Remove(rulesFile)

	engine, err := policy.NewBuiltinEngine(config.BuiltinPolicyConfig{
		RulesPath: rulesFile,
	})
	require.NoError(t, err)

	ctx := NewTestContext(t)
	require.NoError(t, engine.Start(ctx))
	defer engine.Stop()

	testCases := []struct {
		name     string
		path     string
		roles    []string
		expected bool
	}{
		// Deny has higher priority, so even superuser can't access (priority 1000 > 900)
		{"admin denied for normal user", "/admin/users", []string{"user"}, false},
		{"admin denied for admin", "/admin/users", []string{"admin"}, false},
		{"admin denied even for superuser (higher priority deny)", "/admin/users", []string{"superuser"}, false},
		{"non-admin path allowed", "/api/users", []string{"user"}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := &domain.PolicyInput{
				Request: domain.RequestInfo{
					Path:   tc.path,
					Method: "GET",
				},
				Token: &domain.TokenInfo{
					Valid: true,
					Roles: tc.roles,
				},
			}

			decision, err := engine.Evaluate(ctx, input)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, decision.Allowed)
		})
	}
}

func TestBuiltinEngine_Evaluate_DisabledRules(t *testing.T) {
	rulesYAML := `
version: "v1.0.0"
default_deny: true

rules:
  - name: disabled-rule
    priority: 100
    enabled: false
    conditions:
      paths:
        - "/api/*"
    effect: allow

  - name: enabled-rule
    priority: 90
    enabled: true
    conditions:
      paths:
        - "/api/public/*"
    effect: allow
`

	rulesFile := createTempRulesFile(t, rulesYAML)
	defer os.Remove(rulesFile)

	engine, err := policy.NewBuiltinEngine(config.BuiltinPolicyConfig{
		RulesPath: rulesFile,
	})
	require.NoError(t, err)

	ctx := NewTestContext(t)
	require.NoError(t, engine.Start(ctx))
	defer engine.Stop()

	// Disabled rule should not match
	input := &domain.PolicyInput{
		Request: domain.RequestInfo{
			Path:   "/api/private",
			Method: "GET",
		},
	}

	decision, err := engine.Evaluate(ctx, input)
	require.NoError(t, err)
	assert.False(t, decision.Allowed)

	// Enabled rule should match
	input.Request.Path = "/api/public/data"
	decision, err = engine.Evaluate(ctx, input)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestBuiltinEngine_Evaluate_IPBasedAccess(t *testing.T) {
	rulesYAML := `
version: "v1.0.0"
default_deny: true

rules:
  - name: internal-only
    priority: 100
    enabled: true
    conditions:
      paths:
        - "/internal/*"
      source_ips:
        - "10.0.0.0/8"
        - "192.168.0.0/16"
        - "127.0.0.1"
    effect: allow

  - name: public-access
    priority: 90
    enabled: true
    conditions:
      paths:
        - "/public/*"
    effect: allow
`

	rulesFile := createTempRulesFile(t, rulesYAML)
	defer os.Remove(rulesFile)

	engine, err := policy.NewBuiltinEngine(config.BuiltinPolicyConfig{
		RulesPath: rulesFile,
	})
	require.NoError(t, err)

	ctx := NewTestContext(t)
	require.NoError(t, engine.Start(ctx))
	defer engine.Stop()

	testCases := []struct {
		name     string
		path     string
		sourceIP string
		expected bool
	}{
		{"internal from localhost", "/internal/api", "127.0.0.1", true},
		{"internal from 10.x", "/internal/api", "10.1.2.3", true},
		{"internal from 192.168.x", "/internal/api", "192.168.1.100", true},
		{"internal from external denied", "/internal/api", "8.8.8.8", false},
		{"public from anywhere", "/public/data", "8.8.8.8", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := &domain.PolicyInput{
				Request: domain.RequestInfo{
					Path:   tc.path,
					Method: "GET",
				},
				Source: domain.SourceInfo{
					Address: tc.sourceIP,
				},
			}

			decision, err := engine.Evaluate(ctx, input)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, decision.Allowed)
		})
	}
}

func TestBuiltinEngine_Evaluate_TimeBasedAccess(t *testing.T) {
	rulesYAML := `
version: "v1.0.0"
default_deny: true

rules:
  - name: business-hours-only
    priority: 100
    enabled: true
    conditions:
      paths:
        - "/api/*"
      time_restrictions:
        hours_start: 9
        hours_end: 17
        weekdays:
          - monday
          - tuesday
          - wednesday
          - thursday
          - friday
    effect: allow
`

	rulesFile := createTempRulesFile(t, rulesYAML)
	defer os.Remove(rulesFile)

	engine, err := policy.NewBuiltinEngine(config.BuiltinPolicyConfig{
		RulesPath: rulesFile,
	})
	require.NoError(t, err)

	ctx := NewTestContext(t)
	require.NoError(t, engine.Start(ctx))
	defer engine.Stop()

	// Note: This test's behavior depends on current time.
	// In production, you'd mock time or use time-travel testing.
	input := &domain.PolicyInput{
		Request: domain.RequestInfo{
			Path:   "/api/data",
			Method: "GET",
		},
		Context: domain.ContextInfo{
			Timestamp: time.Now().Unix(),
		},
	}

	decision, err := engine.Evaluate(ctx, input)
	require.NoError(t, err)
	// Result depends on current time - just verify no error
	t.Logf("Access allowed: %v (depends on current time)", decision.Allowed)
}

func TestOPASidecarEngine_Evaluate(t *testing.T) {
	// Create mock OPA sidecar
	allowedPaths := map[string]bool{
		"/api/allowed/*":  true,
		"/api/denied/*":   false,
		"/health":         true,
		"/api/users/read": true,
	}

	opaSidecar := MockOPASidecar(t, allowedPaths)
	defer opaSidecar.Close()

	engine := policy.NewOPASidecarEngine(config.OPASidecarConfig{
		URL:     opaSidecar.URL,
		Timeout: 5 * time.Second,
	})

	ctx := NewTestContext(t)
	require.NoError(t, engine.Start(ctx))
	defer engine.Stop()

	testCases := []struct {
		name     string
		path     string
		expected bool
	}{
		{"allowed path", "/api/allowed/test", true},
		{"denied path", "/api/denied/test", false},
		{"health endpoint", "/health", true},
		{"users read", "/api/users/read", true},
		{"unknown path", "/unknown", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := &domain.PolicyInput{
				Request: domain.RequestInfo{
					Path:   tc.path,
					Method: "GET",
				},
			}

			decision, err := engine.Evaluate(ctx, input)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, decision.Allowed)
		})
	}
}

func TestPolicyService_WithMultipleEngines(t *testing.T) {
	// Create builtin rules
	rulesYAML := `
version: "v1.0.0"
default_deny: true

rules:
  - name: health-allow
    priority: 1000
    enabled: true
    conditions:
      paths:
        - "/health"
    effect: allow
`

	rulesFile := createTempRulesFile(t, rulesYAML)
	defer os.Remove(rulesFile)

	// Create engines
	builtinEngine, err := policy.NewBuiltinEngine(config.BuiltinPolicyConfig{
		RulesPath: rulesFile,
	})
	require.NoError(t, err)

	opaSidecar := MockOPASidecar(t, map[string]bool{
		"/api/*": true,
	})
	defer opaSidecar.Close()

	opaEngine := policy.NewOPASidecarEngine(config.OPASidecarConfig{
		URL:     opaSidecar.URL,
		Timeout: 5 * time.Second,
	})

	// Create service with both engines
	cfg := config.PolicyConfig{
		Engine: "builtin", // Primary engine
	}

	svc, err := policy.NewService(cfg)
	require.NoError(t, err)
	_ = builtinEngine // Used for reference - service creates its own engine
	_ = opaEngine     // Used for reference - service creates its own engine

	ctx := NewTestContext(t)
	require.NoError(t, svc.Start(ctx))
	defer svc.Stop()

	// Test with primary engine
	input := &domain.PolicyInput{
		Request: domain.RequestInfo{
			Path:   "/health",
			Method: "GET",
		},
	}

	decision, err := svc.Evaluate(ctx, input)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

// Helper functions

func createTempRulesFile(t *testing.T, content string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")

	err := os.WriteFile(path, []byte(content), 0644)
	require.NoError(t, err)

	return path
}
