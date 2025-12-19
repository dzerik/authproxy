package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create test config files
func createTestConfigFiles(t *testing.T, tmpDir string, envContent, svcContent string) string {
	t.Helper()

	envPath := filepath.Join(tmpDir, "environment.yaml")
	svcPath := filepath.Join(tmpDir, "services.yaml")
	rulesPath := filepath.Join(tmpDir, "rules.yaml")

	if envContent == "" {
		envContent = `
config_source:
  type: file
  file:
    services_path: ` + svcPath + `
    rules_path: ` + rulesPath + `
`
	}

	if svcContent == "" {
		svcContent = "{}"
	}

	rulesContent := `
rules:
  - name: default
    effect: allow
`

	err := os.WriteFile(envPath, []byte(envContent), 0644)
	require.NoError(t, err)
	err = os.WriteFile(svcPath, []byte(svcContent), 0644)
	require.NoError(t, err)
	err = os.WriteFile(rulesPath, []byte(rulesContent), 0644)
	require.NoError(t, err)

	return envPath
}

func TestLoadAll_DefaultValues(t *testing.T) {
	tmpDir := t.TempDir()
	envPath := createTestConfigFiles(t, tmpDir, "", "")

	loader, err := LoadAll(context.Background(), envPath)
	require.NoError(t, err)
	require.NotNil(t, loader)

	cfg := loader.ToConfig()
	require.NotNil(t, cfg)

	// Server defaults
	assert.True(t, cfg.Server.HTTP.Enabled)
	assert.Equal(t, ":8080", cfg.Server.HTTP.Addr)
	assert.Equal(t, 10*time.Second, cfg.Server.HTTP.ReadTimeout)
	assert.Equal(t, 30*time.Second, cfg.Server.HTTP.WriteTimeout)  // Default is 30s
	assert.Equal(t, 120*time.Second, cfg.Server.HTTP.IdleTimeout)
	assert.Equal(t, 30*time.Second, cfg.Server.HTTP.ShutdownTimeout)
	assert.Equal(t, 1<<20, cfg.Server.HTTP.MaxHeaderBytes) // 1MB

	assert.False(t, cfg.Server.GRPC.Enabled)
	assert.Equal(t, ":9090", cfg.Server.GRPC.Addr)

	// Proxy defaults
	assert.False(t, cfg.Proxy.Enabled)

	// Policy defaults
	assert.Equal(t, "builtin", cfg.Policy.Engine)
	assert.Equal(t, "/etc/authz/rules.yaml", cfg.Policy.Builtin.RulesPath)

	// Cache defaults
	assert.True(t, cfg.Cache.L1.Enabled)
	assert.Equal(t, 10000, cfg.Cache.L1.MaxSize)
	assert.Equal(t, 10*time.Second, cfg.Cache.L1.TTL)
	assert.False(t, cfg.Cache.L2.Enabled)

	// Audit defaults
	assert.True(t, cfg.Audit.Enabled)
	assert.Contains(t, cfg.Audit.Events, "AUTHZ_DECISION")

	// Logging defaults
	assert.Equal(t, "info", cfg.Logging.Level)
	assert.Equal(t, "json", cfg.Logging.Format)

	// Resilience defaults
	assert.True(t, cfg.Resilience.RateLimit.Enabled)
	assert.Equal(t, "100-S", cfg.Resilience.RateLimit.Rate)
	assert.True(t, cfg.Resilience.CircuitBreaker.Enabled)

	// Sensitive data defaults
	assert.True(t, cfg.SensitiveData.Enabled)
	assert.Equal(t, "***MASKED***", cfg.SensitiveData.MaskValue)
	assert.True(t, cfg.SensitiveData.MaskJWT)
}

func TestLoadAll_CustomValues(t *testing.T) {
	tmpDir := t.TempDir()
	svcPath := filepath.Join(tmpDir, "services.yaml")
	rulesPath := filepath.Join(tmpDir, "rules.yaml")

	envContent := `
server:
  http:
    addr: ":9000"
    read_timeout: 30s
  grpc:
    enabled: true
    addr: ":9091"
logging:
  level: debug
config_source:
  type: file
  file:
    services_path: ` + svcPath + `
    rules_path: ` + rulesPath + `
`
	svcContent := `
policy:
  engine: opa
  opa:
    url: http://opa:8181
cache:
  l1:
    max_size: 5000
    ttl: 30s
`
	rulesContent := `
rules:
  - name: default
    effect: allow
`

	envPath := filepath.Join(tmpDir, "environment.yaml")
	err := os.WriteFile(envPath, []byte(envContent), 0644)
	require.NoError(t, err)
	err = os.WriteFile(svcPath, []byte(svcContent), 0644)
	require.NoError(t, err)
	err = os.WriteFile(rulesPath, []byte(rulesContent), 0644)
	require.NoError(t, err)

	loader, err := LoadAll(context.Background(), envPath)
	require.NoError(t, err)

	cfg := loader.ToConfig()
	assert.Equal(t, ":9000", cfg.Server.HTTP.Addr)
	assert.Equal(t, 30*time.Second, cfg.Server.HTTP.ReadTimeout)
	assert.True(t, cfg.Server.GRPC.Enabled)
	assert.Equal(t, ":9091", cfg.Server.GRPC.Addr)
	assert.Equal(t, "opa", cfg.Policy.Engine)
	assert.Equal(t, "http://opa:8181", cfg.Policy.OPA.URL)
	assert.Equal(t, 5000, cfg.Cache.L1.MaxSize)
	assert.Equal(t, 30*time.Second, cfg.Cache.L1.TTL)
	assert.Equal(t, "debug", cfg.Logging.Level)
}

func TestLoadAll_EnvironmentVariables(t *testing.T) {
	tmpDir := t.TempDir()
	envPath := createTestConfigFiles(t, tmpDir, "", "")

	// Set environment variables
	os.Setenv("AUTHZ_SERVER_HTTP_ADDR", ":7070")
	os.Setenv("AUTHZ_LOGGING_LEVEL", "warn")
	defer func() {
		os.Unsetenv("AUTHZ_SERVER_HTTP_ADDR")
		os.Unsetenv("AUTHZ_LOGGING_LEVEL")
	}()

	loader, err := LoadAll(context.Background(), envPath)
	require.NoError(t, err)

	cfg := loader.ToConfig()
	assert.Equal(t, ":7070", cfg.Server.HTTP.Addr)
	assert.Equal(t, "warn", cfg.Logging.Level)
}

func TestLoadAll_ConfigFileNotFound(t *testing.T) {
	loader, err := LoadAll(context.Background(), "/nonexistent/path/environment.yaml")

	assert.Error(t, err)
	assert.Nil(t, loader)
}

func TestLoadAll_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	envPath := filepath.Join(tmpDir, "environment.yaml")

	// Write invalid YAML
	err := os.WriteFile(envPath, []byte("invalid: yaml: content: ["), 0644)
	require.NoError(t, err)

	loader, err := LoadAll(context.Background(), envPath)
	assert.Error(t, err)
	assert.Nil(t, loader)
}

func TestLoadAll_JWTConfig(t *testing.T) {
	tmpDir := t.TempDir()
	svcPath := filepath.Join(tmpDir, "services.yaml")
	rulesPath := filepath.Join(tmpDir, "rules.yaml")

	envContent := `
config_source:
  type: file
  file:
    services_path: ` + svcPath + `
    rules_path: ` + rulesPath + `
`
	svcContent := `
jwt:
  issuers:
    - name: keycloak
      issuer_url: https://auth.example.com/realms/test
      jwks_url: https://auth.example.com/realms/test/protocol/openid-connect/certs
      audience:
        - api.example.com
      algorithms:
        - RS256
        - ES256
  validation:
    clock_skew: 60s
    require_expiration: true
`
	rulesContent := `
rules:
  - name: default
    effect: allow
`

	envPath := filepath.Join(tmpDir, "environment.yaml")
	err := os.WriteFile(envPath, []byte(envContent), 0644)
	require.NoError(t, err)
	err = os.WriteFile(svcPath, []byte(svcContent), 0644)
	require.NoError(t, err)
	err = os.WriteFile(rulesPath, []byte(rulesContent), 0644)
	require.NoError(t, err)

	loader, err := LoadAll(context.Background(), envPath)
	require.NoError(t, err)

	cfg := loader.ToConfig()
	require.Len(t, cfg.JWT.Issuers, 1)
	assert.Equal(t, "keycloak", cfg.JWT.Issuers[0].Name)
	assert.Equal(t, "https://auth.example.com/realms/test", cfg.JWT.Issuers[0].IssuerURL)
	assert.Contains(t, cfg.JWT.Issuers[0].Algorithms, "RS256")
	assert.Contains(t, cfg.JWT.Issuers[0].Algorithms, "ES256")
	assert.Equal(t, 60*time.Second, cfg.JWT.Validation.ClockSkew)
	assert.True(t, cfg.JWT.Validation.RequireExpiration)
}

func TestLoadAll_ResilienceConfig(t *testing.T) {
	tmpDir := t.TempDir()
	svcPath := filepath.Join(tmpDir, "services.yaml")
	rulesPath := filepath.Join(tmpDir, "rules.yaml")

	envContent := `
config_source:
  type: file
  file:
    services_path: ` + svcPath + `
    rules_path: ` + rulesPath + `
`
	svcContent := `
resilience:
  rate_limit:
    enabled: true
    rate: "1000-S"
    store: redis
    redis:
      address: localhost:6379
      db: 1
    exclude_paths:
      - /health
      - /metrics
  circuit_breaker:
    enabled: true
    default:
      max_requests: 5
      interval: 30s
      timeout: 15s
      failure_threshold: 10
`
	rulesContent := `
rules:
  - name: default
    effect: allow
`

	envPath := filepath.Join(tmpDir, "environment.yaml")
	err := os.WriteFile(envPath, []byte(envContent), 0644)
	require.NoError(t, err)
	err = os.WriteFile(svcPath, []byte(svcContent), 0644)
	require.NoError(t, err)
	err = os.WriteFile(rulesPath, []byte(rulesContent), 0644)
	require.NoError(t, err)

	loader, err := LoadAll(context.Background(), envPath)
	require.NoError(t, err)

	cfg := loader.ToConfig()
	assert.True(t, cfg.Resilience.RateLimit.Enabled)
	assert.Equal(t, "1000-S", cfg.Resilience.RateLimit.Rate)
	assert.Equal(t, "redis", cfg.Resilience.RateLimit.Store)
	assert.Equal(t, "localhost:6379", cfg.Resilience.RateLimit.Redis.Address)
	assert.Contains(t, cfg.Resilience.RateLimit.ExcludePaths, "/health")

	assert.True(t, cfg.Resilience.CircuitBreaker.Enabled)
	assert.Equal(t, uint32(5), cfg.Resilience.CircuitBreaker.Default.MaxRequests)
	assert.Equal(t, 30*time.Second, cfg.Resilience.CircuitBreaker.Default.Interval)
	assert.Equal(t, uint32(10), cfg.Resilience.CircuitBreaker.Default.FailureThreshold)
}

func TestLoadAll_SensitiveDataConfig(t *testing.T) {
	tmpDir := t.TempDir()
	svcPath := filepath.Join(tmpDir, "services.yaml")
	rulesPath := filepath.Join(tmpDir, "rules.yaml")

	envContent := `
config_source:
  type: file
  file:
    services_path: ` + svcPath + `
    rules_path: ` + rulesPath + `
`
	svcContent := `
sensitive_data:
  enabled: true
  mask_value: "[REDACTED]"
  fields:
    - password
    - secret
    - api_key
  headers:
    - Authorization
    - X-API-Key
  mask_jwt: true
  partial_mask:
    enabled: true
    show_first: 4
    show_last: 4
`
	rulesContent := `
rules:
  - name: default
    effect: allow
`

	envPath := filepath.Join(tmpDir, "environment.yaml")
	err := os.WriteFile(envPath, []byte(envContent), 0644)
	require.NoError(t, err)
	err = os.WriteFile(svcPath, []byte(svcContent), 0644)
	require.NoError(t, err)
	err = os.WriteFile(rulesPath, []byte(rulesContent), 0644)
	require.NoError(t, err)

	loader, err := LoadAll(context.Background(), envPath)
	require.NoError(t, err)

	cfg := loader.ToConfig()
	assert.True(t, cfg.SensitiveData.Enabled)
	assert.Equal(t, "[REDACTED]", cfg.SensitiveData.MaskValue)
	assert.Contains(t, cfg.SensitiveData.Fields, "password")
	assert.Contains(t, cfg.SensitiveData.Headers, "Authorization")
	assert.True(t, cfg.SensitiveData.MaskJWT)
	assert.True(t, cfg.SensitiveData.PartialMask.Enabled)
	assert.Equal(t, 4, cfg.SensitiveData.PartialMask.ShowFirst)
}

func TestLoader_GetEnvironment(t *testing.T) {
	tmpDir := t.TempDir()
	svcPath := filepath.Join(tmpDir, "services.yaml")
	rulesPath := filepath.Join(tmpDir, "rules.yaml")

	envContent := `
server:
  http:
    addr: ":8888"
logging:
  level: warn
config_source:
  type: file
  file:
    services_path: ` + svcPath + `
    rules_path: ` + rulesPath + `
`
	envPath := filepath.Join(tmpDir, "environment.yaml")
	err := os.WriteFile(envPath, []byte(envContent), 0644)
	require.NoError(t, err)
	err = os.WriteFile(svcPath, []byte("{}"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(rulesPath, []byte("rules: []"), 0644)
	require.NoError(t, err)

	loader, err := LoadAll(context.Background(), envPath)
	require.NoError(t, err)

	env := loader.GetEnvironment()
	require.NotNil(t, env)
	assert.Equal(t, ":8888", env.Server.HTTP.Addr)
	assert.Equal(t, "warn", env.Logging.Level)
}

func TestLoader_GetServices(t *testing.T) {
	tmpDir := t.TempDir()
	svcPath := filepath.Join(tmpDir, "services.yaml")
	rulesPath := filepath.Join(tmpDir, "rules.yaml")

	envContent := `
config_source:
  type: file
  file:
    services_path: ` + svcPath + `
    rules_path: ` + rulesPath + `
`
	svcContent := `
cache:
  l1:
    max_size: 50000
`
	envPath := filepath.Join(tmpDir, "environment.yaml")
	err := os.WriteFile(envPath, []byte(envContent), 0644)
	require.NoError(t, err)
	err = os.WriteFile(svcPath, []byte(svcContent), 0644)
	require.NoError(t, err)
	err = os.WriteFile(rulesPath, []byte("rules: []"), 0644)
	require.NoError(t, err)

	loader, err := LoadAll(context.Background(), envPath)
	require.NoError(t, err)

	svc := loader.GetServices()
	require.NotNil(t, svc)
	assert.Equal(t, 50000, svc.Cache.L1.MaxSize)
}

// =============================================================================
// Config Struct Tests
// =============================================================================

func TestServerConfig_Defaults(t *testing.T) {
	cfg := ServerConfig{}

	// Verify zero values
	assert.False(t, cfg.HTTP.Enabled)
	assert.Empty(t, cfg.HTTP.Addr)
	assert.False(t, cfg.GRPC.Enabled)
}

func TestJWTConfig_Defaults(t *testing.T) {
	cfg := JWTConfig{}

	assert.Empty(t, cfg.Issuers)
	assert.Empty(t, cfg.Validation.ClockSkew)
}

func TestCacheConfig_Defaults(t *testing.T) {
	cfg := CacheConfig{}

	assert.False(t, cfg.L1.Enabled)
	assert.Equal(t, 0, cfg.L1.MaxSize)
	assert.False(t, cfg.L2.Enabled)
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkLoadAll(b *testing.B) {
	tmpDir := b.TempDir()
	svcPath := filepath.Join(tmpDir, "services.yaml")
	rulesPath := filepath.Join(tmpDir, "rules.yaml")

	envContent := `
server:
  http:
    addr: ":8080"
config_source:
  type: file
  file:
    services_path: ` + svcPath + `
    rules_path: ` + rulesPath + `
`
	svcContent := `
policy:
  engine: builtin
cache:
  l1:
    enabled: true
    max_size: 10000
`
	envPath := filepath.Join(tmpDir, "environment.yaml")
	os.WriteFile(envPath, []byte(envContent), 0644)
	os.WriteFile(svcPath, []byte(svcContent), 0644)
	os.WriteFile(rulesPath, []byte("rules: []"), 0644)

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		LoadAll(ctx, envPath)
	}
}
