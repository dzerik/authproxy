package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Load loads configuration from a YAML file using viper.
// It supports:
// - YAML configuration files
// - Environment variable substitution with AUTH_PORTAL_ prefix
// - Default values for common settings
func Load(path string) (*Config, error) {
	v := viper.New()

	// Set config file
	v.SetConfigFile(path)
	v.SetConfigType("yaml")

	// Environment variable support
	v.SetEnvPrefix("AUTH_PORTAL")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Bind specific environment variables
	bindEnvVars(v)

	// Set defaults
	setDefaults(v)

	// Read configuration file
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Unmarshal into struct
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Apply post-processing defaults
	applyDefaults(&cfg)

	return &cfg, nil
}

// bindEnvVars binds specific environment variables to config keys.
func bindEnvVars(v *viper.Viper) {
	// Auth secrets
	_ = v.BindEnv("auth.keycloak.client_secret", "KC_CLIENT_SECRET")
	_ = v.BindEnv("auth.keycloak.issuer_url", "KC_ISSUER_URL")
	_ = v.BindEnv("auth.keycloak.client_id", "KC_CLIENT_ID")
	_ = v.BindEnv("auth.keycloak.redirect_url", "KC_REDIRECT_URL")

	// Session secrets
	_ = v.BindEnv("session.encryption.key", "ENCRYPTION_KEY")
	_ = v.BindEnv("session.jwt.signing_key", "JWT_SIGNING_KEY")
	_ = v.BindEnv("session.cookie.secret", "SESSION_SECRET")

	// Redis
	_ = v.BindEnv("session.redis.password", "REDIS_PASSWORD")

	// Server
	_ = v.BindEnv("server.http_port", "HTTP_PORT")
	_ = v.BindEnv("server.https_port", "HTTPS_PORT")

	// Logging
	_ = v.BindEnv("log.level", "LOG_LEVEL")
	_ = v.BindEnv("log.development", "DEV_MODE")

	// Dev mode
	_ = v.BindEnv("dev_mode.enabled", "DEV_MODE")
}

// setDefaults sets default values for configuration.
func setDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.http_port", 8080)
	v.SetDefault("server.https_port", 443)

	// Mode defaults
	v.SetDefault("mode", "portal")

	// Auth defaults
	v.SetDefault("auth.keycloak.scopes", []string{"openid", "profile", "email"})

	// Session defaults
	v.SetDefault("session.store", "cookie")
	v.SetDefault("session.cookie_name", "_auth_session")
	v.SetDefault("session.ttl", "24h")
	v.SetDefault("session.same_site", "lax")
	v.SetDefault("session.cookie.max_size", 4096)
	v.SetDefault("session.jwt.algorithm", "HS256")
	v.SetDefault("session.redis.key_prefix", "authportal:session:")
	v.SetDefault("session.redis.pool_size", 10)
	v.SetDefault("session.redis.min_idle_conns", 5)

	// Token defaults
	v.SetDefault("token.refresh_threshold", "5m")

	// Nginx defaults
	v.SetDefault("nginx.worker_processes", "auto")
	v.SetDefault("nginx.worker_connections", 1024)
	v.SetDefault("nginx.keepalive_timeout", 65)
	v.SetDefault("nginx.client_max_body_size", "100m")
	v.SetDefault("nginx.rate_limit.zone_size", "10m")
	v.SetDefault("nginx.rate_limit.requests_per_second", 10)
	v.SetDefault("nginx.rate_limit.burst", 20)
	v.SetDefault("nginx.access_log", "/var/log/nginx/access.log")
	v.SetDefault("nginx.error_log", "/var/log/nginx/error.log")

	// Observability defaults
	v.SetDefault("observability.metrics.enabled", true)
	v.SetDefault("observability.metrics.path", "/metrics")
	v.SetDefault("observability.tracing.enabled", false)
	v.SetDefault("observability.tracing.endpoint", "localhost:4317")
	v.SetDefault("observability.tracing.protocol", "grpc")
	v.SetDefault("observability.tracing.insecure", true)
	v.SetDefault("observability.tracing.sampling_ratio", 1.0)
	v.SetDefault("observability.health.path", "/health")
	v.SetDefault("observability.ready.path", "/ready")

	// Logging defaults
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("log.development", false)
}

// applyDefaults applies default values to configuration after unmarshaling.
// This handles cases where viper defaults don't work well with nested structs.
func applyDefaults(cfg *Config) {
	// Server defaults
	if cfg.Server.HTTPPort == 0 {
		cfg.Server.HTTPPort = 8080
	}
	if cfg.Server.HTTPSPort == 0 {
		cfg.Server.HTTPSPort = 443
	}

	// Mode defaults
	if cfg.Mode == "" {
		cfg.Mode = "portal"
	}

	// Auth defaults
	if len(cfg.Auth.Keycloak.Scopes) == 0 {
		cfg.Auth.Keycloak.Scopes = []string{"openid", "profile", "email"}
	}

	// Session defaults
	if cfg.Session.Store == "" {
		cfg.Session.Store = "cookie"
	}
	if cfg.Session.CookieName == "" {
		cfg.Session.CookieName = "_auth_session"
	}
	if cfg.Session.TTL == 0 {
		cfg.Session.TTL = 24 * time.Hour
	}
	if cfg.Session.SameSite == "" {
		cfg.Session.SameSite = "lax"
	}
	if cfg.Session.Cookie.MaxSize == 0 {
		cfg.Session.Cookie.MaxSize = 4096
	}
	if cfg.Session.JWT.Algorithm == "" {
		cfg.Session.JWT.Algorithm = "HS256"
	}
	if cfg.Session.Redis.KeyPrefix == "" {
		cfg.Session.Redis.KeyPrefix = "authportal:session:"
	}
	if cfg.Session.Redis.PoolSize == 0 {
		cfg.Session.Redis.PoolSize = 10
	}
	if cfg.Session.Redis.MinIdleConns == 0 {
		cfg.Session.Redis.MinIdleConns = 5
	}

	// Token defaults
	if cfg.Token.RefreshThreshold == 0 {
		cfg.Token.RefreshThreshold = 5 * time.Minute
	}

	// Nginx defaults
	if cfg.Nginx.WorkerProcesses == "" {
		cfg.Nginx.WorkerProcesses = "auto"
	}
	if cfg.Nginx.WorkerConnections == 0 {
		cfg.Nginx.WorkerConnections = 1024
	}
	if cfg.Nginx.KeepaliveTimeout == 0 {
		cfg.Nginx.KeepaliveTimeout = 65
	}
	if cfg.Nginx.ClientMaxBodySize == "" {
		cfg.Nginx.ClientMaxBodySize = "100m"
	}
	if cfg.Nginx.RateLimit.ZoneSize == "" {
		cfg.Nginx.RateLimit.ZoneSize = "10m"
	}
	if cfg.Nginx.RateLimit.RequestsPerSecond == 0 {
		cfg.Nginx.RateLimit.RequestsPerSecond = 10
	}
	if cfg.Nginx.RateLimit.Burst == 0 {
		cfg.Nginx.RateLimit.Burst = 20
	}
	if cfg.Nginx.AccessLog == "" {
		cfg.Nginx.AccessLog = "/var/log/nginx/access.log"
	}
	if cfg.Nginx.ErrorLog == "" {
		cfg.Nginx.ErrorLog = "/var/log/nginx/error.log"
	}

	// Observability defaults
	if cfg.Observability.Metrics.Path == "" {
		cfg.Observability.Metrics.Path = "/metrics"
	}
	if cfg.Observability.Tracing.Endpoint == "" {
		cfg.Observability.Tracing.Endpoint = "localhost:4317"
	}
	if cfg.Observability.Tracing.Protocol == "" {
		cfg.Observability.Tracing.Protocol = "grpc"
	}
	if cfg.Observability.Tracing.SamplingRatio == 0 {
		cfg.Observability.Tracing.SamplingRatio = 1.0
	}
	if cfg.Observability.Health.Path == "" {
		cfg.Observability.Health.Path = "/health"
	}
	if cfg.Observability.Ready.Path == "" {
		cfg.Observability.Ready.Path = "/ready"
	}

	// Logging defaults
	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}
	if cfg.Log.Format == "" {
		cfg.Log.Format = "json"
	}

	// Service defaults
	for i := range cfg.Services {
		if cfg.Services[i].DisplayName == "" {
			cfg.Services[i].DisplayName = cfg.Services[i].Name
		}
		if cfg.Services[i].Headers.Add == nil {
			cfg.Services[i].Headers.Add = make(map[string]string)
		}
	}
}

// LoadFromString loads configuration from a YAML string (useful for testing).
func LoadFromString(yamlStr string) (*Config, error) {
	v := viper.New()
	v.SetConfigType("yaml")

	if err := v.ReadConfig(strings.NewReader(yamlStr)); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	applyDefaults(&cfg)
	return &cfg, nil
}

// MustLoad loads configuration or panics.
func MustLoad(path string) *Config {
	cfg, err := Load(path)
	if err != nil {
		panic(err)
	}
	return cfg
}

// ParseSameSite converts string to http.SameSite value.
func ParseSameSite(s string) int {
	switch strings.ToLower(s) {
	case "strict":
		return 4 // http.SameSiteStrictMode
	case "lax":
		return 2 // http.SameSiteLaxMode
	case "none":
		return 3 // http.SameSiteNoneMode
	default:
		return 2 // http.SameSiteLaxMode (default)
	}
}

// NewViper creates a new viper instance with common configuration.
// Useful for creating sub-configurations or testing.
func NewViper() *viper.Viper {
	v := viper.New()
	v.SetEnvPrefix("AUTH_PORTAL")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	return v
}
