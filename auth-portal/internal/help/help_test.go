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
		DocsURL:     "https://docs.example.com",
	}

	g := NewGenerator(appInfo, "TEST_PREFIX")

	require.NotNil(t, g)
	assert.Equal(t, appInfo.Name, g.appInfo.Name)
	assert.Equal(t, "TEST_PREFIX", g.envVarPrefix)
}

func TestGenerator_PrintVersion(t *testing.T) {
	appInfo := AppInfo{
		Name:      "auth-portal",
		Version:   "1.2.3",
		BuildTime: "2024-06-15T10:30:00Z",
	}

	g := NewGenerator(appInfo, "AUTH_PORTAL")
	output := g.PrintVersion()

	tests := []string{
		"auth-portal",
		"1.2.3",
		"Build time:",
		"2024-06-15T10:30:00Z",
	}

	for _, expected := range tests {
		assert.Contains(t, output, expected)
	}
}

func TestGenerator_PrintUsage(t *testing.T) {
	appInfo := AppInfo{
		Name:        "auth-portal",
		Description: "Authentication portal for web services",
	}

	g := NewGenerator(appInfo, "AUTH_PORTAL")
	output := g.PrintUsage()

	tests := []string{
		"Usage:",
		"auth-portal",
		"[OPTIONS]",
		"Authentication portal for web services",
		"--help",
	}

	for _, expected := range tests {
		assert.Contains(t, output, expected)
	}
}

func TestGenerator_PrintExtendedHelp(t *testing.T) {
	appInfo := AppInfo{
		Name:        "auth-portal",
		Description: "Authentication portal for web services",
		Version:     "1.0.0",
		BuildTime:   "2024-01-01",
		DocsURL:     "https://docs.example.com",
	}

	g := NewGenerator(appInfo, "AUTH_PORTAL")
	output := g.PrintExtendedHelp()

	// Check all major sections are present
	sections := []string{
		"DESCRIPTION",
		"USAGE",
		"OPTIONS",
		"CONFIGURATION",
		"ENVIRONMENT VARIABLES",
		"OPERATION MODES",
		"NGINX INTEGRATION",
		"EXAMPLES",
		"HEALTH ENDPOINTS",
		"VERSION",
		"DOCUMENTATION",
	}

	for _, section := range sections {
		assert.Contains(t, output, section)
	}
}

func TestGenerator_PrintExtendedHelp_NoDocsURL(t *testing.T) {
	appInfo := AppInfo{
		Name:        "auth-portal",
		Description: "Authentication portal",
		Version:     "1.0.0",
		BuildTime:   "2024-01-01",
		DocsURL:     "", // Empty docs URL
	}

	g := NewGenerator(appInfo, "AUTH_PORTAL")
	output := g.PrintExtendedHelp()

	// DOCUMENTATION section should not be present
	assert.NotContains(t, output, "DOCUMENTATION\n    https")
}

func TestGenerator_PrintExtendedHelp_Options(t *testing.T) {
	appInfo := AppInfo{
		Name:        "auth-portal",
		Description: "Test",
		Version:     "1.0.0",
		BuildTime:   "now",
	}

	g := NewGenerator(appInfo, "AUTH_PORTAL")
	output := g.PrintExtendedHelp()

	options := []string{
		"--config",
		"--generate-nginx",
		"--output",
		"--dev",
		"--version",
		"--help",
		"--schema",
		"--schema-output",
	}

	for _, opt := range options {
		assert.Contains(t, output, opt)
	}
}

func TestGenerator_PrintExtendedHelp_EnvVars(t *testing.T) {
	appInfo := AppInfo{
		Name:        "auth-portal",
		Description: "Test",
		Version:     "1.0.0",
		BuildTime:   "now",
	}

	g := NewGenerator(appInfo, "AUTH_PORTAL")
	output := g.PrintExtendedHelp()

	envVars := []string{
		"KC_ISSUER_URL",
		"KC_CLIENT_ID",
		"KC_CLIENT_SECRET",
		"KC_REDIRECT_URL",
		"ENCRYPTION_KEY",
		"JWT_SIGNING_KEY",
		"SESSION_SECRET",
		"REDIS_PASSWORD",
		"HTTP_PORT",
		"HTTPS_PORT",
		"LOG_LEVEL",
		"DEV_MODE",
	}

	for _, env := range envVars {
		assert.Contains(t, output, env)
	}
}

func TestGenerator_PrintExtendedHelp_OperationModes(t *testing.T) {
	appInfo := AppInfo{
		Name:        "auth-portal",
		Description: "Test",
		Version:     "1.0.0",
		BuildTime:   "now",
	}

	g := NewGenerator(appInfo, "AUTH_PORTAL")
	output := g.PrintExtendedHelp()

	modes := []string{
		"PORTAL MODE",
		"SINGLE-SERVICE MODE",
		"FORWARD AUTH MODE",
	}

	for _, mode := range modes {
		assert.Contains(t, output, mode)
	}

	// Check endpoints
	endpoints := []string{
		"/auth",
		"/auth/redirect",
		"/auth/verify",
		"/auth/introspect",
	}

	for _, endpoint := range endpoints {
		assert.Contains(t, output, endpoint)
	}
}

func TestGenerator_PrintExtendedHelp_HealthEndpoints(t *testing.T) {
	appInfo := AppInfo{
		Name:        "auth-portal",
		Description: "Test",
		Version:     "1.0.0",
		BuildTime:   "now",
	}

	g := NewGenerator(appInfo, "AUTH_PORTAL")
	output := g.PrintExtendedHelp()

	healthEndpoints := []string{
		"/health",
		"/ready",
		"/metrics",
	}

	for _, endpoint := range healthEndpoints {
		assert.Contains(t, output, endpoint)
	}
}

func TestGenerator_Header(t *testing.T) {
	appInfo := AppInfo{
		Name:        "auth-portal",
		Description: "Authentication portal for web services",
	}

	g := NewGenerator(appInfo, "AUTH_PORTAL")
	output := g.header()

	// Should contain box borders
	assert.Contains(t, output, "+")
	assert.Contains(t, output, "-")
	assert.Contains(t, output, "|")

	// Should contain app name in uppercase
	assert.Contains(t, output, "AUTH-PORTAL")

	// Should contain description
	assert.Contains(t, output, "Authentication portal")
}

func TestGenerator_Header_LongDescription(t *testing.T) {
	appInfo := AppInfo{
		Name:        "app",
		Description: strings.Repeat("A very long description that exceeds the width of the box", 3),
	}

	g := NewGenerator(appInfo, "PREFIX")
	output := g.header()

	// Long description should be truncated with "..."
	assert.Contains(t, output, "...")
}

func TestGenerator_Separator(t *testing.T) {
	appInfo := AppInfo{Name: "app", Description: "desc"}
	g := NewGenerator(appInfo, "PREFIX")

	sep := g.separator()

	assert.GreaterOrEqual(t, len(sep), 80)
	assert.True(t, strings.HasPrefix(sep, strings.Repeat("-", 80)))
}

func TestGenerator_OptionsSection(t *testing.T) {
	appInfo := AppInfo{Name: "app", Description: "desc"}
	g := NewGenerator(appInfo, "PREFIX")

	output := g.optionsSection()

	// Check option formatting
	options := []struct {
		flag  string
		descr string
	}{
		{"--config", "Path to configuration"},
		{"--generate-nginx", "Generate nginx config"},
		{"--output", "Output path"},
		{"--dev", "development mode"},
		{"--version", "version information"},
		{"--help", "help message"},
		{"--schema", "JSON Schema"},
	}

	for _, opt := range options {
		assert.Contains(t, output, opt.flag)
	}
}

func TestGenerator_ConfigSection(t *testing.T) {
	appInfo := AppInfo{Name: "app", Description: "desc"}
	g := NewGenerator(appInfo, "AUTH_PORTAL")

	output := g.configSection()

	// Check config sections are documented
	configSections := []string{
		"server:",
		"mode:",
		"auth:",
		"session:",
		"services:",
		"nginx:",
		"observability:",
		"resilience:",
		"log:",
		"dev_mode:",
	}

	for _, section := range configSections {
		assert.Contains(t, output, section)
	}

	// Check env var prefix is used
	assert.Contains(t, output, "AUTH_PORTAL_")

	// Check secrets management
	secrets := []string{
		"KC_CLIENT_SECRET",
		"ENCRYPTION_KEY",
		"JWT_SIGNING_KEY",
		"SESSION_SECRET",
		"REDIS_PASSWORD",
	}

	for _, secret := range secrets {
		assert.Contains(t, output, secret)
	}
}

func TestGenerator_EnvVarsSection(t *testing.T) {
	appInfo := AppInfo{Name: "app", Description: "desc"}
	g := NewGenerator(appInfo, "MY_APP")

	output := g.envVarsSection()

	// Check prefix is used
	assert.Contains(t, output, "MY_APP_")

	// Check notes
	notes := []string{
		"UPPER_SNAKE_CASE",
		"underscore",
		"Boolean",
		"Duration",
	}

	for _, note := range notes {
		assert.Contains(t, output, note)
	}
}

func TestGenerator_OperationModesSection(t *testing.T) {
	appInfo := AppInfo{Name: "app", Description: "desc"}
	g := NewGenerator(appInfo, "PREFIX")

	output := g.operationModesSection()

	// Check all modes are documented
	modes := []string{
		"PORTAL MODE",
		"mode=portal",
		"SINGLE-SERVICE MODE",
		"mode=single-service",
		"FORWARD AUTH MODE",
	}

	for _, mode := range modes {
		assert.Contains(t, output, mode)
	}
}

func TestGenerator_NginxSection(t *testing.T) {
	appInfo := AppInfo{Name: "my-app", Description: "desc"}
	g := NewGenerator(appInfo, "PREFIX")

	output := g.nginxSection()

	// Check app name is used in examples
	assert.Contains(t, output, "my-app")

	// Check nginx generation is documented
	nginxTopics := []string{
		"GENERATION",
		"--generate-nginx",
		"--output",
		"CONTAINER INTEGRATION",
		"Docker",
		"Kubernetes",
		"GENERATED CONFIG INCLUDES",
		"Upstream",
		"Forward auth",
		"Header injection",
	}

	for _, topic := range nginxTopics {
		assert.Contains(t, output, topic)
	}
}

func TestGenerator_ExamplesSection(t *testing.T) {
	appInfo := AppInfo{Name: "auth-portal", Description: "desc"}
	g := NewGenerator(appInfo, "PREFIX")

	output := g.examplesSection()

	// Check app name is used
	assert.GreaterOrEqual(t, strings.Count(output, "auth-portal"), 5)

	// Check example commands
	examples := []string{
		"--config",
		"--dev",
		"--generate-nginx",
		"--schema",
		"docker run",
		"KC_CLIENT_SECRET",
		"LOG_LEVEL",
	}

	for _, example := range examples {
		assert.Contains(t, output, example)
	}
}

func TestAppInfo(t *testing.T) {
	info := AppInfo{
		Name:        "test-app",
		Description: "A test application",
		Version:     "2.0.0",
		BuildTime:   "2024-12-01",
		DocsURL:     "https://example.com/docs",
	}

	assert.Equal(t, "test-app", info.Name)
	assert.Equal(t, "A test application", info.Description)
	assert.Equal(t, "2.0.0", info.Version)
	assert.Equal(t, "2024-12-01", info.BuildTime)
	assert.Equal(t, "https://example.com/docs", info.DocsURL)
}

func BenchmarkPrintExtendedHelp(b *testing.B) {
	appInfo := AppInfo{
		Name:        "auth-portal",
		Description: "Authentication portal for web services",
		Version:     "1.0.0",
		BuildTime:   "2024-01-01",
		DocsURL:     "https://docs.example.com",
	}

	g := NewGenerator(appInfo, "AUTH_PORTAL")

	for i := 0; i < b.N; i++ {
		_ = g.PrintExtendedHelp()
	}
}

func BenchmarkHeader(b *testing.B) {
	appInfo := AppInfo{
		Name:        "auth-portal",
		Description: "Authentication portal for web services",
	}

	g := NewGenerator(appInfo, "AUTH_PORTAL")

	for i := 0; i < b.N; i++ {
		_ = g.header()
	}
}
