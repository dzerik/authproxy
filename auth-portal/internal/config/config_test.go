package config

import (
	"testing"
	"time"
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
			if tt.got != tt.expected {
				t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.expected)
			}
		})
	}
}

func TestConfig_DefaultScopes(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)

	expectedScopes := []string{"openid", "profile", "email"}
	if len(cfg.Auth.Keycloak.Scopes) != len(expectedScopes) {
		t.Errorf("Auth.Keycloak.Scopes length = %d, want %d", len(cfg.Auth.Keycloak.Scopes), len(expectedScopes))
		return
	}

	for i, scope := range expectedScopes {
		if cfg.Auth.Keycloak.Scopes[i] != scope {
			t.Errorf("Auth.Keycloak.Scopes[%d] = %s, want %s", i, cfg.Auth.Keycloak.Scopes[i], scope)
		}
	}
}

func TestConfig_DefaultExcludePaths(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)

	expectedPaths := []string{"/health", "/ready", "/metrics"}
	if len(cfg.Resilience.RateLimit.ExcludePaths) != len(expectedPaths) {
		t.Errorf("Resilience.RateLimit.ExcludePaths length = %d, want %d",
			len(cfg.Resilience.RateLimit.ExcludePaths), len(expectedPaths))
		return
	}

	for i, path := range expectedPaths {
		if cfg.Resilience.RateLimit.ExcludePaths[i] != path {
			t.Errorf("Resilience.RateLimit.ExcludePaths[%d] = %s, want %s",
				i, cfg.Resilience.RateLimit.ExcludePaths[i], path)
		}
	}
}

func TestConfig_ServiceDefaults(t *testing.T) {
	cfg := &Config{
		Services: []ServiceConfig{
			{Name: "test-service"},
		},
	}
	applyDefaults(cfg)

	if cfg.Services[0].DisplayName != "test-service" {
		t.Errorf("Services[0].DisplayName = %s, want %s", cfg.Services[0].DisplayName, "test-service")
	}

	if cfg.Services[0].Headers.Add == nil {
		t.Error("Services[0].Headers.Add should be initialized")
	}
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
			if result != tt.expected {
				t.Errorf("ParseSameSite(%q) = %d, want %d", tt.input, result, tt.expected)
			}
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
	if err != nil {
		t.Fatalf("LoadFromString failed: %v", err)
	}

	if cfg.Mode != "portal" {
		t.Errorf("Mode = %s, want portal", cfg.Mode)
	}

	if cfg.Server.HTTPPort != 9090 {
		t.Errorf("Server.HTTPPort = %d, want 9090", cfg.Server.HTTPPort)
	}

	if cfg.Session.Store != "jwt" {
		t.Errorf("Session.Store = %s, want jwt", cfg.Session.Store)
	}

	if cfg.Session.TTL != 12*time.Hour {
		t.Errorf("Session.TTL = %v, want 12h", cfg.Session.TTL)
	}

	if cfg.Log.Level != "debug" {
		t.Errorf("Log.Level = %s, want debug", cfg.Log.Level)
	}

	// Check defaults were applied
	if cfg.Server.HTTPSPort != 443 {
		t.Errorf("Server.HTTPSPort = %d, want 443 (default)", cfg.Server.HTTPSPort)
	}
}

func TestLoadFromString_Invalid(t *testing.T) {
	yamlStr := `
invalid: yaml: content
  - broken
`
	_, err := LoadFromString(yamlStr)
	if err == nil {
		t.Error("LoadFromString should fail with invalid YAML")
	}
}

func TestNewViper(t *testing.T) {
	v := NewViper()
	if v == nil {
		t.Error("NewViper should return non-nil viper instance")
	}
}
