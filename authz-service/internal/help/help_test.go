package help

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGenerator(t *testing.T) {
	appInfo := AppInfo{
		Name:        "test-app",
		Description: "Test application",
		Version:     "1.0.0",
		BuildTime:   "2024-01-01",
		GitCommit:   "abc123",
		DocsURL:     "https://example.com/docs",
	}

	gen := NewGenerator(appInfo, "TEST")

	require.NotNil(t, gen)
	assert.Equal(t, appInfo, gen.appInfo)
	assert.Equal(t, "TEST", gen.envVarPrefix)
}

func TestGenerator_SetEnvVars(t *testing.T) {
	gen := NewGenerator(AppInfo{Name: "test"}, "TEST")

	vars := []EnvVar{
		{Name: "TEST_VAR1", Description: "First var"},
		{Name: "TEST_VAR2", Description: "Second var"},
	}

	gen.SetEnvVars(vars)

	assert.Equal(t, vars, gen.envVars)
}

func TestGenerator_ExtractEnvVars(t *testing.T) {
	gen := NewGenerator(AppInfo{Name: "test"}, "TEST")

	type SampleConfig struct {
		Host string `mapstructure:"host" jsonschema:"description=Hostname"`
		Port int    `mapstructure:"port" jsonschema:"description=Port number"`
	}

	gen.ExtractEnvVars(SampleConfig{})

	require.Len(t, gen.envVars, 2)
	assert.Equal(t, "TEST_HOST", gen.envVars[0].Name)
	assert.Equal(t, "TEST_PORT", gen.envVars[1].Name)
}

func TestGenerator_PrintVersion(t *testing.T) {
	appInfo := AppInfo{
		Name:      "myapp",
		Version:   "2.0.0",
		BuildTime: "2024-06-15T10:00:00Z",
		GitCommit: "def456",
	}

	gen := NewGenerator(appInfo, "APP")

	result := gen.PrintVersion()

	assert.Contains(t, result, "myapp 2.0.0")
	assert.Contains(t, result, "Build time: 2024-06-15T10:00:00Z")
	assert.Contains(t, result, "Git commit: def456")
}

func TestGenerator_PrintUsage(t *testing.T) {
	appInfo := AppInfo{
		Name:        "myapp",
		Description: "My awesome application",
	}

	gen := NewGenerator(appInfo, "APP")

	result := gen.PrintUsage()

	assert.Contains(t, result, "Usage: myapp [OPTIONS]")
	assert.Contains(t, result, "My awesome application")
	assert.Contains(t, result, "Options:")
	assert.Contains(t, result, "--help")
}

func TestGenerator_PrintEnvVars(t *testing.T) {
	appInfo := AppInfo{
		Name: "authz-service",
	}

	gen := NewGenerator(appInfo, "AUTHZ")
	gen.SetEnvVars([]EnvVar{
		{Name: "AUTHZ_SERVER_HOST", ConfigPath: "server.host", Description: "Server host"},
		{Name: "AUTHZ_SERVER_PORT", ConfigPath: "server.port", Description: "Server port"},
	})

	result := gen.PrintEnvVars()

	assert.Contains(t, result, "AUTHZ-SERVICE - Environment Variables")
	assert.Contains(t, result, "Prefix: AUTHZ")
	assert.Contains(t, result, "Total variables: 2")
	assert.Contains(t, result, "AUTHZ_SERVER_HOST")
	assert.Contains(t, result, "AUTHZ_SERVER_PORT")
	assert.Contains(t, result, "[Server]")
}

func TestGenerator_PrintEnvVars_Empty(t *testing.T) {
	gen := NewGenerator(AppInfo{Name: "test"}, "TEST")

	result := gen.PrintEnvVars()

	assert.Contains(t, result, "Total variables: 0")
}

func TestGenerator_PrintExtendedHelp(t *testing.T) {
	appInfo := AppInfo{
		Name:        "authz-service",
		Description: "Authorization service",
		Version:     "1.0.0",
		BuildTime:   "2024-01-01",
		GitCommit:   "abc123",
		DocsURL:     "https://docs.example.com",
	}

	gen := NewGenerator(appInfo, "AUTHZ")
	gen.SetEnvVars([]EnvVar{
		{Name: "AUTHZ_VAR", Description: "Test var"},
	})

	result := gen.PrintExtendedHelp()

	// Header
	assert.Contains(t, result, "AUTHZ-SERVICE")

	// Description section
	assert.Contains(t, result, "DESCRIPTION")
	assert.Contains(t, result, "Authorization service")

	// Usage section
	assert.Contains(t, result, "USAGE")
	assert.Contains(t, result, "authz-service [OPTIONS]")

	// Options section
	assert.Contains(t, result, "OPTIONS")
	assert.Contains(t, result, "--config")
	assert.Contains(t, result, "--version")
	assert.Contains(t, result, "--help")
	assert.Contains(t, result, "--help-env")
	assert.Contains(t, result, "--schema")
	assert.Contains(t, result, "--validate")
	assert.Contains(t, result, "--dry-run")

	// Configuration methods
	assert.Contains(t, result, "CONFIGURATION METHODS")
	assert.Contains(t, result, "COMMAND LINE FLAGS")
	assert.Contains(t, result, "ENVIRONMENT VARIABLES")
	assert.Contains(t, result, "CONFIGURATION FILE")

	// Operation modes
	assert.Contains(t, result, "OPERATION MODES")
	assert.Contains(t, result, "DECISION API MODE")
	assert.Contains(t, result, "REVERSE PROXY MODE")
	assert.Contains(t, result, "EGRESS PROXY MODE")

	// Policy engines
	assert.Contains(t, result, "POLICY ENGINES")
	assert.Contains(t, result, "BUILTIN")
	assert.Contains(t, result, "OPA EMBEDDED")
	assert.Contains(t, result, "OPA SIDECAR")

	// JSON Schema generation
	assert.Contains(t, result, "JSON SCHEMA GENERATION")

	// Examples
	assert.Contains(t, result, "EXAMPLES")

	// Files and signals
	assert.Contains(t, result, "FILES")
	assert.Contains(t, result, "SIGNALS")
	assert.Contains(t, result, "HEALTH ENDPOINTS")

	// Version
	assert.Contains(t, result, "VERSION")
	assert.Contains(t, result, "1.0.0")

	// Documentation
	assert.Contains(t, result, "DOCUMENTATION")
	assert.Contains(t, result, "https://docs.example.com")
}

func TestGenerator_PrintExtendedHelp_EnvVarsCount(t *testing.T) {
	gen := NewGenerator(AppInfo{Name: "test"}, "TEST")

	vars := make([]EnvVar, 50)
	for i := 0; i < 50; i++ {
		vars[i] = EnvVar{Name: "TEST_VAR", Description: "Var"}
	}
	gen.SetEnvVars(vars)

	result := gen.PrintExtendedHelp()

	// Should show count and reference to --help-env
	assert.Contains(t, result, "Use --help-env to see all 50 environment variables")
}

func TestGenerator_header(t *testing.T) {
	appInfo := AppInfo{
		Name:        "test-app",
		Description: "A test application",
	}

	gen := NewGenerator(appInfo, "TEST")

	result := gen.header()

	assert.Contains(t, result, "TEST-APP")
	assert.Contains(t, result, "A test application")
	assert.Contains(t, result, "+")
	assert.Contains(t, result, "|")
}

func TestGenerator_header_LongDescription(t *testing.T) {
	appInfo := AppInfo{
		Name:        "test",
		Description: strings.Repeat("Very long description ", 10),
	}

	gen := NewGenerator(appInfo, "TEST")

	result := gen.header()

	// Should truncate with "..."
	assert.Contains(t, result, "...")
}

func TestGenerator_separator(t *testing.T) {
	gen := NewGenerator(AppInfo{Name: "test"}, "TEST")

	result := gen.separator()

	assert.Equal(t, 80, len(strings.TrimSuffix(result, "\n\n")))
	assert.True(t, strings.HasPrefix(result, "---"))
}

func TestGenerator_optionsSection(t *testing.T) {
	gen := NewGenerator(AppInfo{Name: "test"}, "TEST")

	result := gen.optionsSection()

	options := []string{
		"--config",
		"--version",
		"--help",
		"--help-env",
		"--schema",
		"--schema-output",
		"--validate",
		"--dry-run",
	}

	for _, opt := range options {
		assert.Contains(t, result, opt, "should contain option %s", opt)
	}
}

func TestGenerator_configMethodsSection(t *testing.T) {
	gen := NewGenerator(AppInfo{Name: "myapp"}, "MYAPP")

	result := gen.configMethodsSection()

	assert.Contains(t, result, "myapp --config")
	assert.Contains(t, result, "MYAPP_")
	assert.Contains(t, result, "COMMAND LINE FLAGS")
	assert.Contains(t, result, "ENVIRONMENT VARIABLES")
	assert.Contains(t, result, "CONFIGURATION FILE")
}

func TestGenerator_operationModesSection(t *testing.T) {
	gen := NewGenerator(AppInfo{Name: "test"}, "TEST")

	result := gen.operationModesSection()

	assert.Contains(t, result, "DECISION API MODE")
	assert.Contains(t, result, "REVERSE PROXY MODE")
	assert.Contains(t, result, "EGRESS PROXY MODE")
	assert.Contains(t, result, "/v1/authorize")
	assert.Contains(t, result, "proxy.enabled=true")
}

func TestGenerator_policyEnginesSection(t *testing.T) {
	gen := NewGenerator(AppInfo{Name: "test"}, "TEST")

	result := gen.policyEnginesSection()

	assert.Contains(t, result, "BUILTIN")
	assert.Contains(t, result, "OPA EMBEDDED")
	assert.Contains(t, result, "OPA SIDECAR")
	assert.Contains(t, result, "policy.engine=builtin")
	assert.Contains(t, result, "policy.engine=opa_embedded")
	assert.Contains(t, result, "policy.engine=opa_sidecar")
}

func TestGenerator_schemaGenerationSection(t *testing.T) {
	gen := NewGenerator(AppInfo{Name: "myapp"}, "MYAPP")

	result := gen.schemaGenerationSection()

	assert.Contains(t, result, "myapp --schema config")
	assert.Contains(t, result, "myapp --schema rules")
	assert.Contains(t, result, "--schema-output")
	assert.Contains(t, result, "yaml-language-server")
}

func TestGenerator_examplesSection(t *testing.T) {
	gen := NewGenerator(AppInfo{Name: "authz"}, "AUTHZ")

	result := gen.examplesSection()

	assert.Contains(t, result, "authz --config")
	assert.Contains(t, result, "--validate")
	assert.Contains(t, result, "--dry-run")
	assert.Contains(t, result, "AUTHZ_SERVER_HTTP_ADDR")
	assert.Contains(t, result, "AUTHZ_LOGGING_LEVEL")
	assert.Contains(t, result, "docker run")
}

func TestGenerator_filesSection(t *testing.T) {
	gen := NewGenerator(AppInfo{Name: "test"}, "TEST")

	result := gen.filesSection()

	assert.Contains(t, result, "/etc/authz/config.yaml")
	assert.Contains(t, result, "/etc/authz/rules.yaml")
	assert.Contains(t, result, "/etc/authz/policies/")
	assert.Contains(t, result, "/etc/authz/data/")
}

func TestGenerator_secretsSection(t *testing.T) {
	gen := NewGenerator(AppInfo{Name: "authz"}, "AUTHZ")

	result := gen.secretsSection()

	// Check warning
	assert.Contains(t, result, "NEVER store secrets in configuration files")

	// Check sensitive env vars
	assert.Contains(t, result, "AUTHZ_JWT_ISSUERS_0_CLIENT_SECRET")
	assert.Contains(t, result, "AUTHZ_CACHE_L2_REDIS_PASSWORD")
	assert.Contains(t, result, "AUTHZ_RESILIENCE_RATE_LIMIT_REDIS_PASSWORD")
	assert.Contains(t, result, "AUTHZ_EGRESS_TOKEN_STORE_REDIS_PASSWORD")

	// Check best practices
	assert.Contains(t, result, "Kubernetes secrets")
	assert.Contains(t, result, "Docker secrets")
	assert.Contains(t, result, "HashiCorp Vault")
	assert.Contains(t, result, "Rotate secrets")
}

func TestGenerator_PrintExtendedHelp_ContainsSecretsSection(t *testing.T) {
	gen := NewGenerator(AppInfo{
		Name:        "authz",
		Description: "Test app",
		Version:     "1.0.0",
		BuildTime:   "2024-01-01",
		GitCommit:   "abc123",
		DocsURL:     "https://docs.example.com",
	}, "AUTHZ")

	result := gen.PrintExtendedHelp()

	assert.Contains(t, result, "SECRETS MANAGEMENT")
	assert.Contains(t, result, "NEVER store secrets")
}

func BenchmarkGenerator_PrintVersion(b *testing.B) {
	gen := NewGenerator(AppInfo{
		Name:      "test",
		Version:   "1.0.0",
		BuildTime: "2024-01-01",
		GitCommit: "abc123",
	}, "TEST")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gen.PrintVersion()
	}
}

func BenchmarkGenerator_PrintExtendedHelp(b *testing.B) {
	gen := NewGenerator(AppInfo{
		Name:        "test",
		Description: "Test app",
		Version:     "1.0.0",
		DocsURL:     "https://example.com",
	}, "TEST")

	vars := make([]EnvVar, 100)
	for i := 0; i < 100; i++ {
		vars[i] = EnvVar{Name: "TEST_VAR", Description: "Var"}
	}
	gen.SetEnvVars(vars)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gen.PrintExtendedHelp()
	}
}

func BenchmarkGenerator_PrintEnvVars(b *testing.B) {
	gen := NewGenerator(AppInfo{Name: "test"}, "TEST")

	vars := make([]EnvVar, 200)
	for i := 0; i < 200; i++ {
		section := "section" + string(rune('a'+i%5))
		vars[i] = EnvVar{
			Name:        "TEST_VAR_" + string(rune('A'+i%26)),
			ConfigPath:  section + ".var",
			Description: "Description for variable",
			Default:     "default",
		}
	}
	gen.SetEnvVars(vars)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gen.PrintEnvVars()
	}
}
