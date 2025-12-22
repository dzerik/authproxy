package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Defaults(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)

	tests := []struct {
		name     string
		got      interface{}
		expected interface{}
	}{
		{"Server.HTTPPort", cfg.Server.HTTPPort, 8080},
		{"Server.HTTPSPort", cfg.Server.HTTPSPort, 443},
		{"Mode", cfg.Mode, "portal"},
		{"Session.Store", cfg.Session.Store, "cookie"},
		{"Session.CookieName", cfg.Session.CookieName, "_auth_session"},
		{"Session.TTL", cfg.Session.TTL, 24 * time.Hour},
		{"Session.SameSite", cfg.Session.SameSite, "lax"},
		{"Session.Cookie.MaxSize", cfg.Session.Cookie.MaxSize, 4096},
		{"Session.JWT.Algorithm", cfg.Session.JWT.Algorithm, "HS256"},
		{"Session.Redis.KeyPrefix", cfg.Session.Redis.KeyPrefix, "authportal:session:"},
		{"Session.Redis.PoolSize", cfg.Session.Redis.PoolSize, 10},
		{"Session.Redis.MinIdleConns", cfg.Session.Redis.MinIdleConns, 5},
		{"Token.RefreshThreshold", cfg.Token.RefreshThreshold, 5 * time.Minute},
		{"Nginx.WorkerProcesses", cfg.Nginx.WorkerProcesses, "auto"},
		{"Nginx.WorkerConnections", cfg.Nginx.WorkerConnections, 1024},
		{"Nginx.KeepaliveTimeout", cfg.Nginx.KeepaliveTimeout, 65},
		{"Nginx.ClientMaxBodySize", cfg.Nginx.ClientMaxBodySize, "100m"},
		{"Nginx.RateLimit.ZoneSize", cfg.Nginx.RateLimit.ZoneSize, "10m"},
		{"Nginx.RateLimit.RequestsPerSecond", cfg.Nginx.RateLimit.RequestsPerSecond, 10},
		{"Nginx.RateLimit.Burst", cfg.Nginx.RateLimit.Burst, 20},
		{"Nginx.AccessLog", cfg.Nginx.AccessLog, "/var/log/nginx/access.log"},
		{"Nginx.ErrorLog", cfg.Nginx.ErrorLog, "/var/log/nginx/error.log"},
		{"Observability.Metrics.Path", cfg.Observability.Metrics.Path, "/metrics"},
		{"Observability.Tracing.Endpoint", cfg.Observability.Tracing.Endpoint, "localhost:4317"},
		{"Observability.Tracing.Protocol", cfg.Observability.Tracing.Protocol, "grpc"},
		{"Observability.Tracing.SamplingRatio", cfg.Observability.Tracing.SamplingRatio, 1.0},
		{"Observability.Health.Path", cfg.Observability.Health.Path, "/health"},
		{"Observability.Ready.Path", cfg.Observability.Ready.Path, "/ready"},
		{"Log.Level", cfg.Log.Level, "info"},
		{"Log.Format", cfg.Log.Format, "json"},
		{"Resilience.RateLimit.Rate", cfg.Resilience.RateLimit.Rate, "100-S"},
		{"Resilience.CircuitBreaker.Default.MaxRequests", cfg.Resilience.CircuitBreaker.Default.MaxRequests, uint32(3)},
		{"Resilience.CircuitBreaker.Default.Interval", cfg.Resilience.CircuitBreaker.Default.Interval, 60 * time.Second},
		{"Resilience.CircuitBreaker.Default.Timeout", cfg.Resilience.CircuitBreaker.Default.Timeout, 30 * time.Second},
		{"Resilience.CircuitBreaker.Default.FailureThreshold", cfg.Resilience.CircuitBreaker.Default.FailureThreshold, uint32(5)},
		{"Resilience.CircuitBreaker.Default.SuccessThreshold", cfg.Resilience.CircuitBreaker.Default.SuccessThreshold, uint32(2)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.got)
		})
	}
}

func TestConfig_DefaultScopes(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)

	expectedScopes := []string{"openid", "profile", "email"}
	assert.Equal(t, expectedScopes, cfg.Auth.Keycloak.Scopes)
}

func TestConfig_DefaultExcludePaths(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)

	expectedPaths := []string{"/health", "/ready", "/metrics"}
	assert.Equal(t, expectedPaths, cfg.Resilience.RateLimit.ExcludePaths)
}

func TestConfig_ServiceDefaults(t *testing.T) {
	cfg := &Config{
		Services: []ServiceConfig{
			{Name: "test-service"},
		},
	}
	applyDefaults(cfg)

	assert.Equal(t, "test-service", cfg.Services[0].DisplayName)
	assert.NotNil(t, cfg.Services[0].Headers.Add)
}

func TestParseSameSite(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"strict", 4},
		{"Strict", 4},
		{"STRICT", 4},
		{"lax", 2},
		{"Lax", 2},
		{"LAX", 2},
		{"none", 3},
		{"None", 3},
		{"NONE", 3},
		{"", 2},       // default to lax
		{"invalid", 2}, // default to lax
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := ParseSameSite(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLoadFromString(t *testing.T) {
	yamlStr := `
mode: portal
server:
  http_port: 9090
session:
  store: jwt
  ttl: 12h
log:
  level: debug
`
	cfg, err := LoadFromString(yamlStr)
	require.NoError(t, err)

	assert.Equal(t, "portal", cfg.Mode)
	assert.Equal(t, 9090, cfg.Server.HTTPPort)
	assert.Equal(t, "jwt", cfg.Session.Store)
	assert.Equal(t, 12*time.Hour, cfg.Session.TTL)
	assert.Equal(t, "debug", cfg.Log.Level)

	// Check defaults were applied
	assert.Equal(t, 443, cfg.Server.HTTPSPort)
}

func TestLoadFromString_Invalid(t *testing.T) {
	yamlStr := `
invalid: yaml: content
  - broken
`
	_, err := LoadFromString(yamlStr)
	assert.Error(t, err)
}

func TestNewViper(t *testing.T) {
	v := NewViper()
	assert.NotNil(t, v)
}
