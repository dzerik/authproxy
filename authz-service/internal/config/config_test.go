package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_DefaultValues(t *testing.T) {
	// Create a minimal config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte("{}"), 0644)
	require.NoError(t, err)

	cfg, err := Load(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Server defaults
	assert.True(t, cfg.Server.HTTP.Enabled)
	assert.Equal(t, ":8080", cfg.Server.HTTP.Addr)
	assert.Equal(t, 10*time.Second, cfg.Server.HTTP.ReadTimeout)
	assert.Equal(t, 10*time.Second, cfg.Server.HTTP.WriteTimeout)
	assert.Equal(t, 120*time.Second, cfg.Server.HTTP.IdleTimeout)
	assert.Equal(t, 30*time.Second, cfg.Server.HTTP.ShutdownTimeout)
	assert.Equal(t, 1<<20, cfg.Server.HTTP.MaxHeaderBytes) // 1MB

	assert.False(t, cfg.Server.GRPC.Enabled)
	assert.Equal(t, ":9090", cfg.Server.GRPC.Addr)

	// Proxy defaults
	assert.False(t, cfg.Proxy.Enabled)
	assert.Equal(t, "decision_only", cfg.Proxy.Mode)
	assert.Equal(t, 30*time.Second, cfg.Proxy.Timeout)

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

func TestLoad_CustomValues(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
server:
  http:
    addr: ":9000"
    read_timeout: 30s
  grpc:
    enabled: true
    addr: ":9091"
policy:
  engine: opa
  opa:
    url: http://opa:8181
cache:
  l1:
    max_size: 5000
    ttl: 30s
logging:
  level: debug
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := Load(configPath)
	require.NoError(t, err)

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

func TestLoad_EnvironmentVariables(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte("{}"), 0644)
	require.NoError(t, err)

	// Set environment variables
	os.Setenv("AUTHZ_SERVER_HTTP_ADDR", ":7070")
	os.Setenv("AUTHZ_LOGGING_LEVEL", "warn")
	os.Setenv("AUTHZ_CACHE_L1_MAX_SIZE", "20000")
	defer func() {
		os.Unsetenv("AUTHZ_SERVER_HTTP_ADDR")
		os.Unsetenv("AUTHZ_LOGGING_LEVEL")
		os.Unsetenv("AUTHZ_CACHE_L1_MAX_SIZE")
	}()

	cfg, err := Load(configPath)
	require.NoError(t, err)

	assert.Equal(t, ":7070", cfg.Server.HTTP.Addr)
	assert.Equal(t, "warn", cfg.Logging.Level)
	assert.Equal(t, 20000, cfg.Cache.L1.MaxSize)
}

func TestLoad_ConfigFileNotFound(t *testing.T) {
	// Load without config file should use defaults
	cfg, err := Load("/nonexistent/path/config.yaml")

	// Should fail with explicit path that doesn't exist
	assert.Error(t, err)
	assert.Nil(t, cfg)
}

func TestLoad_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Write invalid YAML
	err := os.WriteFile(configPath, []byte("invalid: yaml: content: ["), 0644)
	require.NoError(t, err)

	cfg, err := Load(configPath)
	assert.Error(t, err)
	assert.Nil(t, cfg)
}

func TestLoad_JWTConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
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
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := Load(configPath)
	require.NoError(t, err)

	require.Len(t, cfg.JWT.Issuers, 1)
	assert.Equal(t, "keycloak", cfg.JWT.Issuers[0].Name)
	assert.Equal(t, "https://auth.example.com/realms/test", cfg.JWT.Issuers[0].IssuerURL)
	assert.Contains(t, cfg.JWT.Issuers[0].Algorithms, "RS256")
	assert.Contains(t, cfg.JWT.Issuers[0].Algorithms, "ES256")
	assert.Equal(t, 60*time.Second, cfg.JWT.Validation.ClockSkew)
	assert.True(t, cfg.JWT.Validation.RequireExpiration)
}

func TestLoad_ProxyConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
proxy:
  enabled: true
  mode: reverse_proxy
  upstream:
    url: http://backend:8080
  routes:
    - path_prefix: /api/v1
      upstream: backend1
    - path_prefix: /api/v2
      upstream: backend2
  upstreams:
    backend1:
      url: http://backend1:8080
    backend2:
      url: http://backend2:8080
  headers:
    add_user_info: true
    user_id_header: X-User-ID
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := Load(configPath)
	require.NoError(t, err)

	assert.True(t, cfg.Proxy.Enabled)
	assert.Equal(t, "reverse_proxy", cfg.Proxy.Mode)
	assert.Equal(t, "http://backend:8080", cfg.Proxy.Upstream.URL)
	assert.Len(t, cfg.Proxy.Routes, 2)
	assert.Equal(t, "/api/v1", cfg.Proxy.Routes[0].PathPrefix)
	assert.Len(t, cfg.Proxy.Upstreams, 2)
	assert.True(t, cfg.Proxy.Headers.AddUserInfo)
}

func TestLoad_EgressConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
egress:
  enabled: true
  targets:
    external-api:
      url: https://api.external.com
      timeout: 15s
      auth:
        type: oauth2_client_credentials
        token_url: https://auth.external.com/token
        client_id: my-client
        client_secret: my-secret
        scopes:
          - read
          - write
  routes:
    - path_prefix: /external
      target: external-api
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := Load(configPath)
	require.NoError(t, err)

	assert.True(t, cfg.Egress.Enabled)
	require.Contains(t, cfg.Egress.Targets, "external-api")
	target := cfg.Egress.Targets["external-api"]
	assert.Equal(t, "https://api.external.com", target.URL)
	assert.Equal(t, 15*time.Second, target.Timeout)
	assert.Equal(t, "oauth2_client_credentials", target.Auth.Type)
	assert.Equal(t, "my-client", target.Auth.ClientID)
	assert.Contains(t, target.Auth.Scopes, "read")
	assert.Len(t, cfg.Egress.Routes, 1)
}

func TestLoad_ResilienceConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
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
    endpoint_rates:
      /v1/authorize: "500-S"
  circuit_breaker:
    enabled: true
    default:
      max_requests: 5
      interval: 30s
      timeout: 15s
      failure_threshold: 10
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := Load(configPath)
	require.NoError(t, err)

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

func TestLoad_EndpointsConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
endpoints:
  authorize: /api/v1/authorize
  health: /healthz
  metrics: /prometheus/metrics
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := Load(configPath)
	require.NoError(t, err)

	assert.Equal(t, "/api/v1/authorize", cfg.Endpoints.Authorize)
	assert.Equal(t, "/healthz", cfg.Endpoints.Health)
	assert.Equal(t, "/prometheus/metrics", cfg.Endpoints.Metrics)
	// Default values for unset endpoints
	assert.Equal(t, "/ready", cfg.Endpoints.Ready)
	assert.Equal(t, "/live", cfg.Endpoints.Live)
}

func TestLoad_SensitiveDataConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
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
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := Load(configPath)
	require.NoError(t, err)

	assert.True(t, cfg.SensitiveData.Enabled)
	assert.Equal(t, "[REDACTED]", cfg.SensitiveData.MaskValue)
	assert.Contains(t, cfg.SensitiveData.Fields, "password")
	assert.Contains(t, cfg.SensitiveData.Headers, "Authorization")
	assert.True(t, cfg.SensitiveData.MaskJWT)
	assert.True(t, cfg.SensitiveData.PartialMask.Enabled)
	assert.Equal(t, 4, cfg.SensitiveData.PartialMask.ShowFirst)
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

func BenchmarkLoad(b *testing.B) {
	tmpDir := b.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
server:
  http:
    addr: ":8080"
policy:
  engine: builtin
cache:
  l1:
    enabled: true
    max_size: 10000
`
	os.WriteFile(configPath, []byte(configContent), 0644)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Load(configPath)
	}
}
