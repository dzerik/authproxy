package config

import "time"

// Config represents the main application configuration
type Config struct {
	Server        ServerConfig        `yaml:"server" mapstructure:"server"`
	Mode          string              `yaml:"mode" mapstructure:"mode"` // portal | single-service
	SingleService SingleServiceConfig `yaml:"single_service" mapstructure:"single_service"`
	Auth          AuthConfig          `yaml:"auth" mapstructure:"auth"`
	Session       SessionConfig       `yaml:"session" mapstructure:"session"`
	Token         TokenConfig         `yaml:"token" mapstructure:"token"`
	Services      []ServiceConfig     `yaml:"services" mapstructure:"services"`
	DevMode       DevModeConfig       `yaml:"dev_mode" mapstructure:"dev_mode"`
	Nginx         NginxConfig         `yaml:"nginx" mapstructure:"nginx"`
	Observability ObservabilityConfig `yaml:"observability" mapstructure:"observability"`
	Resilience    ResilienceConfig    `yaml:"resilience" mapstructure:"resilience"`
	Log           LogConfig           `yaml:"log" mapstructure:"log"`
}

// LogConfig represents logging configuration
type LogConfig struct {
	Level       string `yaml:"level" mapstructure:"level"`             // debug, info, warn, error
	Format      string `yaml:"format" mapstructure:"format"`           // json, console
	Development bool   `yaml:"development" mapstructure:"development"` // Enable development mode
}

// ServerConfig represents HTTP server configuration
type ServerConfig struct {
	HTTPPort  int       `yaml:"http_port" mapstructure:"http_port"`
	HTTPSPort int       `yaml:"https_port" mapstructure:"https_port"`
	TLS       TLSConfig `yaml:"tls" mapstructure:"tls"`
}

// TLSConfig represents TLS configuration
type TLSConfig struct {
	Enabled  bool           `yaml:"enabled" mapstructure:"enabled"`
	Cert     string         `yaml:"cert" mapstructure:"cert"`
	Key      string         `yaml:"key" mapstructure:"key"`
	AutoCert AutoCertConfig `yaml:"auto_cert" mapstructure:"auto_cert"`
}

// AutoCertConfig represents automatic certificate configuration (Let's Encrypt)
type AutoCertConfig struct {
	Enabled bool     `yaml:"enabled" mapstructure:"enabled"`
	Email   string   `yaml:"email" mapstructure:"email"`
	Domains []string `yaml:"domains" mapstructure:"domains"`
}

// SingleServiceConfig represents single-service mode configuration
type SingleServiceConfig struct {
	TargetURL string `yaml:"target_url" mapstructure:"target_url"`
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	Keycloak KeycloakConfig `yaml:"keycloak" mapstructure:"keycloak"`
}

// KeycloakConfig represents Keycloak OIDC configuration
type KeycloakConfig struct {
	IssuerURL       string           `yaml:"issuer_url" mapstructure:"issuer_url"`
	ClientID        string           `yaml:"client_id" mapstructure:"client_id"`
	ClientSecret    string           `yaml:"client_secret" mapstructure:"client_secret"`
	RedirectURL     string           `yaml:"redirect_url" mapstructure:"redirect_url"`
	Scopes          []string         `yaml:"scopes" mapstructure:"scopes"`
	SocialProviders []SocialProvider `yaml:"social_providers" mapstructure:"social_providers"`
}

// SocialProvider represents a social login provider
type SocialProvider struct {
	Name        string `yaml:"name" mapstructure:"name"`
	DisplayName string `yaml:"display_name" mapstructure:"display_name"`
	IDPHint     string `yaml:"idp_hint" mapstructure:"idp_hint"`
	Icon        string `yaml:"icon" mapstructure:"icon"`
}

// SessionConfig represents session storage configuration
type SessionConfig struct {
	Store      string            `yaml:"store" mapstructure:"store"` // cookie | jwt | redis
	CookieName string            `yaml:"cookie_name" mapstructure:"cookie_name"`
	TTL        time.Duration     `yaml:"ttl" mapstructure:"ttl"`
	Secure     bool              `yaml:"secure" mapstructure:"secure"`
	SameSite   string            `yaml:"same_site" mapstructure:"same_site"` // strict | lax | none
	Encryption EncryptionConfig  `yaml:"encryption" mapstructure:"encryption"`
	Cookie     CookieStoreConfig `yaml:"cookie" mapstructure:"cookie"`
	JWT        JWTStoreConfig    `yaml:"jwt" mapstructure:"jwt"`
	Redis      RedisStoreConfig  `yaml:"redis" mapstructure:"redis"`
}

// EncryptionConfig represents data encryption configuration
type EncryptionConfig struct {
	Enabled bool   `yaml:"enabled" mapstructure:"enabled"`
	Key     string `yaml:"key" mapstructure:"key"` // 32 bytes for AES-256
}

// CookieStoreConfig represents cookie store configuration
type CookieStoreConfig struct {
	MaxSize int `yaml:"max_size" mapstructure:"max_size"`
}

// JWTStoreConfig represents JWT store configuration
type JWTStoreConfig struct {
	SigningKey string `yaml:"signing_key" mapstructure:"signing_key"`
	Algorithm  string `yaml:"algorithm" mapstructure:"algorithm"` // HS256 | RS256
	PrivateKey string `yaml:"private_key" mapstructure:"private_key"`
	PublicKey  string `yaml:"public_key" mapstructure:"public_key"`
}

// RedisStoreConfig represents Redis store configuration
type RedisStoreConfig struct {
	Enabled      bool           `yaml:"enabled" mapstructure:"enabled"`
	Addresses    []string       `yaml:"addresses" mapstructure:"addresses"`
	Password     string         `yaml:"password" mapstructure:"password"`
	DB           int            `yaml:"db" mapstructure:"db"`
	MasterName   string         `yaml:"master_name" mapstructure:"master_name"` // For Sentinel
	TLS          RedisTLSConfig `yaml:"tls" mapstructure:"tls"`
	PoolSize     int            `yaml:"pool_size" mapstructure:"pool_size"`
	MinIdleConns int            `yaml:"min_idle_conns" mapstructure:"min_idle_conns"`
	KeyPrefix    string         `yaml:"key_prefix" mapstructure:"key_prefix"`
}

// RedisTLSConfig represents Redis TLS configuration
type RedisTLSConfig struct {
	Enabled bool   `yaml:"enabled" mapstructure:"enabled"`
	Cert    string `yaml:"cert" mapstructure:"cert"`
	Key     string `yaml:"key" mapstructure:"key"`
	CA      string `yaml:"ca" mapstructure:"ca"`
}

// TokenConfig represents token refresh configuration
type TokenConfig struct {
	AutoRefresh      bool          `yaml:"auto_refresh" mapstructure:"auto_refresh"`
	RefreshThreshold time.Duration `yaml:"refresh_threshold" mapstructure:"refresh_threshold"`
}

// ServiceConfig represents a backend service (junction)
type ServiceConfig struct {
	Name         string        `yaml:"name" mapstructure:"name"`
	DisplayName  string        `yaml:"display_name" mapstructure:"display_name"`
	Description  string        `yaml:"description" mapstructure:"description"`
	Icon         string        `yaml:"icon" mapstructure:"icon"`
	Location     string        `yaml:"location" mapstructure:"location"`
	Upstream     string        `yaml:"upstream" mapstructure:"upstream"`
	AuthRequired bool          `yaml:"auth_required" mapstructure:"auth_required"`
	Rewrite      string        `yaml:"rewrite" mapstructure:"rewrite"`
	Headers      HeadersConfig `yaml:"headers" mapstructure:"headers"`
	NginxExtra   string        `yaml:"nginx_extra" mapstructure:"nginx_extra"`
}

// HeadersConfig represents header manipulation configuration
type HeadersConfig struct {
	Add    map[string]string `yaml:"add" mapstructure:"add"`
	Remove []string          `yaml:"remove" mapstructure:"remove"`
}

// DevModeConfig represents development mode configuration
type DevModeConfig struct {
	Enabled        bool   `yaml:"enabled" mapstructure:"enabled"`
	ProfilesDir    string `yaml:"profiles_dir" mapstructure:"profiles_dir"`
	DefaultProfile string `yaml:"default_profile" mapstructure:"default_profile"`
}

// NginxConfig represents Nginx configuration
type NginxConfig struct {
	WorkerProcesses   string          `yaml:"worker_processes" mapstructure:"worker_processes"`
	WorkerConnections int             `yaml:"worker_connections" mapstructure:"worker_connections"`
	KeepaliveTimeout  int             `yaml:"keepalive_timeout" mapstructure:"keepalive_timeout"`
	ClientMaxBodySize string          `yaml:"client_max_body_size" mapstructure:"client_max_body_size"`
	RateLimit         RateLimitConfig `yaml:"rate_limit" mapstructure:"rate_limit"`
	AccessLog         string          `yaml:"access_log" mapstructure:"access_log"`
	ErrorLog          string          `yaml:"error_log" mapstructure:"error_log"`
	LogFormat         string          `yaml:"log_format" mapstructure:"log_format"`
}

// RateLimitConfig represents rate limiting configuration
type RateLimitConfig struct {
	Enabled           bool   `yaml:"enabled" mapstructure:"enabled"`
	ZoneSize          string `yaml:"zone_size" mapstructure:"zone_size"`
	RequestsPerSecond int    `yaml:"requests_per_second" mapstructure:"requests_per_second"`
	Burst             int    `yaml:"burst" mapstructure:"burst"`
}

// ObservabilityConfig represents observability configuration
type ObservabilityConfig struct {
	Metrics MetricsConfig `yaml:"metrics" mapstructure:"metrics"`
	Tracing TracingConfig `yaml:"tracing" mapstructure:"tracing"`
	Health  HealthConfig  `yaml:"health" mapstructure:"health"`
	Ready   ReadyConfig   `yaml:"ready" mapstructure:"ready"`
}

// TracingConfig represents distributed tracing configuration
type TracingConfig struct {
	Enabled       bool              `yaml:"enabled" mapstructure:"enabled"`
	Endpoint      string            `yaml:"endpoint" mapstructure:"endpoint"`
	Protocol      string            `yaml:"protocol" mapstructure:"protocol"`         // grpc or http
	Insecure      bool              `yaml:"insecure" mapstructure:"insecure"`         // disable TLS
	SamplingRatio float64           `yaml:"sampling_ratio" mapstructure:"sampling_ratio"` // 0.0 to 1.0
	Headers       map[string]string `yaml:"headers" mapstructure:"headers"`           // additional headers
}

// MetricsConfig represents metrics configuration
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled" mapstructure:"enabled"`
	Path    string `yaml:"path" mapstructure:"path"`
}

// HealthConfig represents health check configuration
type HealthConfig struct {
	Path string `yaml:"path" mapstructure:"path"`
}

// ReadyConfig represents readiness check configuration
type ReadyConfig struct {
	Path string `yaml:"path" mapstructure:"path"`
}

// ResilienceConfig holds resilience configuration
type ResilienceConfig struct {
	// RateLimit configuration for incoming requests
	RateLimit HTTPRateLimitConfig `yaml:"rate_limit" mapstructure:"rate_limit"`
	// CircuitBreaker configuration for external calls
	CircuitBreaker CircuitBreakerConfig `yaml:"circuit_breaker" mapstructure:"circuit_breaker"`
}

// HTTPRateLimitConfig holds HTTP rate limiting configuration for resilience
type HTTPRateLimitConfig struct {
	// Enabled enables rate limiting
	Enabled bool `yaml:"enabled" mapstructure:"enabled"`
	// Rate is the rate limit in format 'requests-period' (e.g. '100-S' for 100 requests per second)
	Rate string `yaml:"rate" mapstructure:"rate"`
	// TrustForwardedFor trusts X-Forwarded-For header for client IP
	TrustForwardedFor bool `yaml:"trust_forwarded_for" mapstructure:"trust_forwarded_for"`
	// ExcludePaths excludes paths from rate limiting
	ExcludePaths []string `yaml:"exclude_paths" mapstructure:"exclude_paths"`
	// ByEndpoint enables per-endpoint rate limiting
	ByEndpoint bool `yaml:"by_endpoint" mapstructure:"by_endpoint"`
	// EndpointRates defines per-endpoint rate limits
	EndpointRates map[string]string `yaml:"endpoint_rates" mapstructure:"endpoint_rates"`
	// Headers configuration for rate limit response headers
	Headers HTTPRateLimitHeadersConfig `yaml:"headers" mapstructure:"headers"`
	// FailClose denies requests when rate limiter encounters an error
	FailClose bool `yaml:"fail_close" mapstructure:"fail_close"`
}

// HTTPRateLimitHeadersConfig holds rate limit headers configuration
type HTTPRateLimitHeadersConfig struct {
	// Enabled enables rate limit headers in response
	Enabled bool `yaml:"enabled" mapstructure:"enabled"`
	// LimitHeader is the header name for rate limit
	LimitHeader string `yaml:"limit_header" mapstructure:"limit_header"`
	// RemainingHeader is the header name for remaining requests
	RemainingHeader string `yaml:"remaining_header" mapstructure:"remaining_header"`
	// ResetHeader is the header name for reset timestamp
	ResetHeader string `yaml:"reset_header" mapstructure:"reset_header"`
}

// CircuitBreakerConfig holds circuit breaker configuration
type CircuitBreakerConfig struct {
	// Enabled enables circuit breaker
	Enabled bool `yaml:"enabled" mapstructure:"enabled"`
	// Default settings for all circuit breakers
	Default CircuitBreakerSettings `yaml:"default" mapstructure:"default"`
	// Services holds per-service circuit breaker settings
	Services map[string]CircuitBreakerSettings `yaml:"services" mapstructure:"services"`
}

// CircuitBreakerSettings holds settings for a single circuit breaker
type CircuitBreakerSettings struct {
	// MaxRequests is the maximum number of requests in half-open state
	MaxRequests uint32 `yaml:"max_requests" mapstructure:"max_requests"`
	// Interval is the cyclic period for clearing counts in closed state
	Interval time.Duration `yaml:"interval" mapstructure:"interval"`
	// Timeout is the period of open state before switching to half-open
	Timeout time.Duration `yaml:"timeout" mapstructure:"timeout"`
	// FailureThreshold is the number of consecutive failures to open circuit
	FailureThreshold uint32 `yaml:"failure_threshold" mapstructure:"failure_threshold"`
	// SuccessThreshold is the number of consecutive successes to close circuit
	SuccessThreshold uint32 `yaml:"success_threshold" mapstructure:"success_threshold"`
	// OnStateChange enables logging on state changes
	OnStateChange bool `yaml:"on_state_change" mapstructure:"on_state_change"`
}
