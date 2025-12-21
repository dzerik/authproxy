package help

import (
	"strings"
	"testing"
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

	if g == nil {
		t.Fatal("NewGenerator returned nil")
	}

	if g.appInfo.Name != appInfo.Name {
		t.Errorf("appInfo.Name = %s, want %s", g.appInfo.Name, appInfo.Name)
	}

	if g.envVarPrefix != "TEST_PREFIX" {
		t.Errorf("envVarPrefix = %s, want TEST_PREFIX", g.envVarPrefix)
	}
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
		if !strings.Contains(output, expected) {
			t.Errorf("PrintVersion should contain %q, got: %s", expected, output)
		}
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
		if !strings.Contains(output, expected) {
			t.Errorf("PrintUsage should contain %q, got: %s", expected, output)
		}
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
		if !strings.Contains(output, section) {
			t.Errorf("PrintExtendedHelp should contain section %q", section)
		}
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
	if strings.Contains(output, "DOCUMENTATION\n    https") {
		t.Error("PrintExtendedHelp should not include DOCUMENTATION section when DocsURL is empty")
	}
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
		if !strings.Contains(output, opt) {
			t.Errorf("PrintExtendedHelp should contain option %q", opt)
		}
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
		if !strings.Contains(output, env) {
			t.Errorf("PrintExtendedHelp should contain env var %q", env)
		}
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
		if !strings.Contains(output, mode) {
			t.Errorf("PrintExtendedHelp should contain mode %q", mode)
		}
	}

	// Check endpoints
	endpoints := []string{
		"/auth",
		"/auth/redirect",
		"/auth/verify",
		"/auth/introspect",
	}

	for _, endpoint := range endpoints {
		if !strings.Contains(output, endpoint) {
			t.Errorf("PrintExtendedHelp should contain endpoint %q", endpoint)
		}
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
		if !strings.Contains(output, endpoint) {
			t.Errorf("PrintExtendedHelp should contain health endpoint %q", endpoint)
		}
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
	if !strings.Contains(output, "+") {
		t.Error("header should contain box corners (+)")
	}
	if !strings.Contains(output, "-") {
		t.Error("header should contain horizontal borders (-)")
	}
	if !strings.Contains(output, "|") {
		t.Error("header should contain vertical borders (|)")
	}

	// Should contain app name in uppercase
	if !strings.Contains(output, "AUTH-PORTAL") {
		t.Error("header should contain app name in uppercase")
	}

	// Should contain description
	if !strings.Contains(output, "Authentication portal") {
		t.Error("header should contain description")
	}
}

func TestGenerator_Header_LongDescription(t *testing.T) {
	appInfo := AppInfo{
		Name:        "app",
		Description: strings.Repeat("A very long description that exceeds the width of the box", 3),
	}

	g := NewGenerator(appInfo, "PREFIX")
	output := g.header()

	// Long description should be truncated with "..."
	if !strings.Contains(output, "...") {
		t.Error("header should truncate long descriptions with ...")
	}
}

func TestGenerator_Separator(t *testing.T) {
	appInfo := AppInfo{Name: "app", Description: "desc"}
	g := NewGenerator(appInfo, "PREFIX")

	sep := g.separator()

	if len(sep) < 80 {
		t.Error("separator should be at least 80 characters")
	}

	if !strings.HasPrefix(sep, strings.Repeat("-", 80)) {
		t.Error("separator should start with 80 dashes")
	}
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
		if !strings.Contains(output, opt.flag) {
			t.Errorf("optionsSection should contain flag %q", opt.flag)
		}
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
		if !strings.Contains(output, section) {
			t.Errorf("configSection should contain %q", section)
		}
	}

	// Check env var prefix is used
	if !strings.Contains(output, "AUTH_PORTAL_") {
		t.Error("configSection should contain env var prefix examples")
	}

	// Check secrets management
	secrets := []string{
		"KC_CLIENT_SECRET",
		"ENCRYPTION_KEY",
		"JWT_SIGNING_KEY",
		"SESSION_SECRET",
		"REDIS_PASSWORD",
	}

	for _, secret := range secrets {
		if !strings.Contains(output, secret) {
			t.Errorf("configSection should document secret %q", secret)
		}
	}
}

func TestGenerator_EnvVarsSection(t *testing.T) {
	appInfo := AppInfo{Name: "app", Description: "desc"}
	g := NewGenerator(appInfo, "MY_APP")

	output := g.envVarsSection()

	// Check prefix is used
	if !strings.Contains(output, "MY_APP_") {
		t.Error("envVarsSection should use the configured prefix")
	}

	// Check notes
	notes := []string{
		"UPPER_SNAKE_CASE",
		"underscore",
		"Boolean",
		"Duration",
	}

	for _, note := range notes {
		if !strings.Contains(output, note) {
			t.Errorf("envVarsSection should contain note about %q", note)
		}
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
		if !strings.Contains(output, mode) {
			t.Errorf("operationModesSection should contain %q", mode)
		}
	}
}

func TestGenerator_NginxSection(t *testing.T) {
	appInfo := AppInfo{Name: "my-app", Description: "desc"}
	g := NewGenerator(appInfo, "PREFIX")

	output := g.nginxSection()

	// Check app name is used in examples
	if !strings.Contains(output, "my-app") {
		t.Error("nginxSection should use app name in examples")
	}

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
		if !strings.Contains(output, topic) {
			t.Errorf("nginxSection should contain %q", topic)
		}
	}
}

func TestGenerator_ExamplesSection(t *testing.T) {
	appInfo := AppInfo{Name: "auth-portal", Description: "desc"}
	g := NewGenerator(appInfo, "PREFIX")

	output := g.examplesSection()

	// Check app name is used
	if strings.Count(output, "auth-portal") < 5 {
		t.Error("examplesSection should use app name in multiple examples")
	}

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
		if !strings.Contains(output, example) {
			t.Errorf("examplesSection should contain %q", example)
		}
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

	if info.Name != "test-app" {
		t.Errorf("Name = %s, want test-app", info.Name)
	}
	if info.Description != "A test application" {
		t.Errorf("Description = %s, want A test application", info.Description)
	}
	if info.Version != "2.0.0" {
		t.Errorf("Version = %s, want 2.0.0", info.Version)
	}
	if info.BuildTime != "2024-12-01" {
		t.Errorf("BuildTime = %s, want 2024-12-01", info.BuildTime)
	}
	if info.DocsURL != "https://example.com/docs" {
		t.Errorf("DocsURL = %s, want https://example.com/docs", info.DocsURL)
	}
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
