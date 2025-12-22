package config

import "time"

// Config represents the main application configuration
type Config struct {
	// Server contains HTTP server settings
	Server ServerConfig `yaml:"server" mapstructure:"server" jsonschema:"description=HTTP server configuration including ports and TLS settings"`
	// Mode defines the operation mode: portal or single-service
	Mode string `yaml:"mode" mapstructure:"mode" jsonschema:"required,enum=portal,enum=single-service,default=portal,description=Operation mode: portal (show service list) or single-service (redirect to single target)"`
	// SingleService configuration for single-service mode
	SingleService SingleServiceConfig `yaml:"single_service" mapstructure:"single_service" jsonschema:"description=Configuration for single-service mode"`
	// Auth contains authentication settings
	Auth AuthConfig `yaml:"auth" mapstructure:"auth" jsonschema:"required,description=Authentication configuration including Keycloak OIDC settings"`
	// Session contains session management settings
	Session SessionConfig `yaml:"session" mapstructure:"session" jsonschema:"required,description=Session storage and cookie configuration"`
	// StateStore contains OAuth state storage settings (CRIT-02 security fix)
	StateStore StateStoreConfig `yaml:"state_store" mapstructure:"state_store" jsonschema:"description=OAuth state storage configuration for HA deployments"`
	// Token contains token refresh settings
	Token TokenConfig `yaml:"token" mapstructure:"token" jsonschema:"description=Token refresh and validation settings"`
	// Services defines backend services for portal mode
	Services []ServiceConfig `yaml:"services" mapstructure:"services" jsonschema:"description=List of backend services available in portal mode"`
	// DevMode enables development mode with mock authentication
	DevMode DevModeConfig `yaml:"dev_mode" mapstructure:"dev_mode" jsonschema:"description=Development mode settings for local testing without real IdP"`
	// Nginx contains nginx configuration generation settings
	Nginx NginxConfig `yaml:"nginx" mapstructure:"nginx" jsonschema:"description=Nginx reverse proxy configuration generation settings"`
	// Observability contains metrics, tracing, and health check settings
	Observability ObservabilityConfig `yaml:"observability" mapstructure:"observability" jsonschema:"description=Observability configuration including metrics and tracing and health checks"`
	// Resilience contains rate limiting and circuit breaker settings
	Resilience ResilienceConfig `yaml:"resilience" mapstructure:"resilience" jsonschema:"description=Resilience patterns including rate limiting and circuit breaker"`
	// Log contains logging configuration
	Log LogConfig `yaml:"log" mapstructure:"log" jsonschema:"description=Logging configuration including level and format and development mode"`
}

// LogConfig represents logging configuration
type LogConfig struct {
	// Level sets the minimum log level
	Level string `yaml:"level" mapstructure:"level" jsonschema:"enum=debug,enum=info,enum=warn,enum=error,default=info,description=Minimum log level (debug/info/warn/error)"`
	// Format sets the log output format
	Format string `yaml:"format" mapstructure:"format" jsonschema:"enum=json,enum=console,default=json,description=Log format - json for structured or console for human-readable"`
	// Development enables development mode logging
	Development bool `yaml:"development" mapstructure:"development" jsonschema:"default=false,description=Enable development mode with more verbose output"`
}

// StateStoreConfig represents OAuth state storage configuration (CRIT-02 security fix)
type StateStoreConfig struct {
	// Type is the state storage backend: memory or redis
	Type string `yaml:"type" mapstructure:"type" jsonschema:"enum=memory,enum=redis,default=memory,description=OAuth state storage backend - memory (single instance) or redis (distributed/HA)"`
	// TTL is the state token lifetime
	TTL time.Duration `yaml:"ttl" mapstructure:"ttl" jsonschema:"default=10m,description=OAuth state token time-to-live"`
	// Redis contains Redis-specific settings (used when type is redis)
	Redis StateStoreRedisConfig `yaml:"redis" mapstructure:"redis" jsonschema:"description=Redis state store configuration"`
}

// StateStoreRedisConfig represents Redis state store specific configuration
type StateStoreRedisConfig struct {
	// KeyPrefix is the prefix for state keys in Redis
	KeyPrefix string `yaml:"key_prefix" mapstructure:"key_prefix" jsonschema:"default=authportal:state:,description=Prefix for OAuth state keys in Redis"`
	// UseSessionRedis indicates whether to use the same Redis as session store
	UseSessionRedis bool `yaml:"use_session_redis" mapstructure:"use_session_redis" jsonschema:"default=true,description=Use same Redis configuration as session store"`
}

// ServerConfig represents HTTP server configuration
type ServerConfig struct {
	// HTTPPort is the HTTP listen port
	HTTPPort int `yaml:"http_port" mapstructure:"http_port" jsonschema:"default=8080,minimum=1,maximum=65535,description=HTTP server listen port"`
	// HTTPSPort is the HTTPS listen port
	HTTPSPort int `yaml:"https_port" mapstructure:"https_port" jsonschema:"default=443,minimum=1,maximum=65535,description=HTTPS server listen port (when TLS enabled)"`
	// TLS contains TLS/HTTPS configuration
	TLS TLSConfig `yaml:"tls" mapstructure:"tls" jsonschema:"description=TLS/HTTPS configuration"`
}

// TLSConfig represents TLS configuration
type TLSConfig struct {
	// Enabled enables HTTPS
	Enabled bool `yaml:"enabled" mapstructure:"enabled" jsonschema:"default=false,description=Enable TLS/HTTPS"`
	// Cert is the path to TLS certificate file
	Cert string `yaml:"cert" mapstructure:"cert" jsonschema:"description=Path to TLS certificate file (PEM format)"`
	// Key is the path to TLS private key file
	Key string `yaml:"key" mapstructure:"key" jsonschema:"description=Path to TLS private key file (PEM format)"`
	// AutoCert enables automatic certificate from Let's Encrypt
	AutoCert AutoCertConfig `yaml:"auto_cert" mapstructure:"auto_cert" jsonschema:"description=Automatic TLS certificate configuration (Let's Encrypt)"`
}

// AutoCertConfig represents automatic certificate configuration (Let's Encrypt)
type AutoCertConfig struct {
	// Enabled enables automatic certificate management
	Enabled bool `yaml:"enabled" mapstructure:"enabled" jsonschema:"default=false,description=Enable automatic certificate management via Let's Encrypt"`
	// Email is the contact email for Let's Encrypt
	Email string `yaml:"email" mapstructure:"email" jsonschema:"format=email,description=Contact email for Let's Encrypt notifications"`
	// Domains is the list of domains for certificate
	Domains []string `yaml:"domains" mapstructure:"domains" jsonschema:"description=List of domains for the TLS certificate"`
}

// SingleServiceConfig represents single-service mode configuration
type SingleServiceConfig struct {
	// TargetURL is the URL to redirect after authentication
	TargetURL string `yaml:"target_url" mapstructure:"target_url" jsonschema:"format=uri,description=Target URL to redirect to after successful authentication in single-service mode"`
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	// Keycloak contains Keycloak OIDC settings
	Keycloak KeycloakConfig `yaml:"keycloak" mapstructure:"keycloak" jsonschema:"required,description=Keycloak OIDC configuration"`
}

// KeycloakConfig represents Keycloak OIDC configuration
type KeycloakConfig struct {
	// IssuerURL is the Keycloak realm URL
	IssuerURL string `yaml:"issuer_url" mapstructure:"issuer_url" jsonschema:"required,format=uri,description=Keycloak issuer URL (realm URL)"`
	// ClientID is the OAuth2 client ID
	ClientID string `yaml:"client_id" mapstructure:"client_id" jsonschema:"required,description=OAuth2/OIDC client ID registered in Keycloak"`
	// ClientSecret is the OAuth2 client secret
	ClientSecret string `yaml:"client_secret" mapstructure:"client_secret" jsonschema:"required,description=OAuth2/OIDC client secret - use env var KC_CLIENT_SECRET"`
	// RedirectURL is the OAuth2 callback URL
	RedirectURL string `yaml:"redirect_url" mapstructure:"redirect_url" jsonschema:"required,format=uri,description=OAuth2 callback URL for authentication flow"`
	// Scopes are the OAuth2 scopes to request
	Scopes []string `yaml:"scopes" mapstructure:"scopes" jsonschema:"description=OAuth2 scopes to request from Keycloak"`
	// SocialProviders configures social login buttons
	SocialProviders []SocialProvider `yaml:"social_providers" mapstructure:"social_providers" jsonschema:"description=Social login providers configured in Keycloak"`
}

// SocialProvider represents a social login provider
type SocialProvider struct {
	// Name is the provider identifier
	Name string `yaml:"name" mapstructure:"name" jsonschema:"required,description=Provider identifier such as google or github"`
	// DisplayName is shown on the login button
	DisplayName string `yaml:"display_name" mapstructure:"display_name" jsonschema:"description=Display name for the login button"`
	// IDPHint is the Keycloak IdP hint for this provider
	IDPHint string `yaml:"idp_hint" mapstructure:"idp_hint" jsonschema:"required,description=Keycloak identity provider hint (kc_idp_hint value)"`
	// Icon is the icon class or URL
	Icon string `yaml:"icon" mapstructure:"icon" jsonschema:"description=Icon class (FontAwesome) or URL for the login button"`
}

// SessionConfig represents session storage configuration
type SessionConfig struct {
	// Store is the session storage backend type
	Store string `yaml:"store" mapstructure:"store" jsonschema:"required,enum=cookie,enum=jwt,enum=redis,default=cookie,description=Session storage backend - cookie (encrypted) or jwt (stateless) or redis (distributed)"`
	// CookieName is the session cookie name
	CookieName string `yaml:"cookie_name" mapstructure:"cookie_name" jsonschema:"default=_auth_session,description=Name of the session cookie"`
	// CookieDomain is the domain for session cookie (MED-02 security fix)
	CookieDomain string `yaml:"cookie_domain" mapstructure:"cookie_domain" jsonschema:"description=Domain for session cookie - set to share across subdomains (e.g. .example.com)"`
	// TTL is the session lifetime
	TTL time.Duration `yaml:"ttl" mapstructure:"ttl" jsonschema:"default=24h,description=Session time-to-live (24h or 7d)"`
	// Secure enables secure cookie flag
	Secure bool `yaml:"secure" mapstructure:"secure" jsonschema:"default=true,description=Set Secure flag on session cookie (requires HTTPS)"`
	// SameSite sets the cookie SameSite attribute
	SameSite string `yaml:"same_site" mapstructure:"same_site" jsonschema:"enum=strict,enum=lax,enum=none,default=lax,description=Cookie SameSite attribute - strict or lax or none"`
	// Encryption contains session data encryption settings
	Encryption EncryptionConfig `yaml:"encryption" mapstructure:"encryption" jsonschema:"description=Session data encryption configuration"`
	// Cookie contains cookie store specific settings
	Cookie CookieStoreConfig `yaml:"cookie" mapstructure:"cookie" jsonschema:"description=Cookie store specific configuration"`
	// JWT contains JWT store specific settings
	JWT JWTStoreConfig `yaml:"jwt" mapstructure:"jwt" jsonschema:"description=JWT store specific configuration"`
	// Redis contains Redis store specific settings
	Redis RedisStoreConfig `yaml:"redis" mapstructure:"redis" jsonschema:"description=Redis store specific configuration"`
}

// EncryptionConfig represents data encryption configuration
type EncryptionConfig struct {
	// Enabled enables session data encryption
	Enabled bool `yaml:"enabled" mapstructure:"enabled" jsonschema:"default=true,description=Enable AES-256 encryption for session data"`
	// Key is the encryption key (32 bytes for AES-256)
	Key string `yaml:"key" mapstructure:"key" jsonschema:"description=AES-256 encryption key (32 bytes) - use env var ENCRYPTION_KEY"`
}

// CookieStoreConfig represents cookie store configuration
type CookieStoreConfig struct {
	// MaxSize is the maximum cookie size in bytes
	MaxSize int `yaml:"max_size" mapstructure:"max_size" jsonschema:"default=4096,minimum=1024,maximum=8192,description=Maximum session cookie size in bytes"`
}

// JWTStoreConfig represents JWT store configuration
type JWTStoreConfig struct {
	// SigningKey is the HMAC signing key for HS256
	SigningKey string `yaml:"signing_key" mapstructure:"signing_key" jsonschema:"description=HMAC signing key for HS256 (use ${JWT_SIGNING_KEY} for env var)"`
	// Algorithm is the JWT signing algorithm
	Algorithm string `yaml:"algorithm" mapstructure:"algorithm" jsonschema:"enum=HS256,enum=RS256,default=HS256,description=JWT signing algorithm"`
	// PrivateKey is the path to RSA private key for RS256
	PrivateKey string `yaml:"private_key" mapstructure:"private_key" jsonschema:"description=Path to RSA private key file (for RS256)"`
	// PublicKey is the path to RSA public key for RS256
	PublicKey string `yaml:"public_key" mapstructure:"public_key" jsonschema:"description=Path to RSA public key file (for RS256)"`
}

// RedisStoreConfig represents Redis store configuration
type RedisStoreConfig struct {
	// Enabled enables Redis session storage
	Enabled bool `yaml:"enabled" mapstructure:"enabled" jsonschema:"default=false,description=Enable Redis as session storage backend"`
	// Addresses are Redis server addresses
	Addresses []string `yaml:"addresses" mapstructure:"addresses" jsonschema:"description=Redis server addresses like localhost:6379"`
	// Password is the Redis password
	Password string `yaml:"password" mapstructure:"password" jsonschema:"description=Redis password - use env var REDIS_PASSWORD"`
	// DB is the Redis database number
	DB int `yaml:"db" mapstructure:"db" jsonschema:"default=0,minimum=0,maximum=15,description=Redis database number"`
	// MasterName is the Sentinel master name
	MasterName string `yaml:"master_name" mapstructure:"master_name" jsonschema:"description=Redis Sentinel master name (for HA setup)"`
	// TLS contains Redis TLS settings
	TLS RedisTLSConfig `yaml:"tls" mapstructure:"tls" jsonschema:"description=Redis TLS/SSL configuration"`
	// PoolSize is the Redis connection pool size
	PoolSize int `yaml:"pool_size" mapstructure:"pool_size" jsonschema:"default=10,minimum=1,description=Redis connection pool size"`
	// MinIdleConns is the minimum idle connections
	MinIdleConns int `yaml:"min_idle_conns" mapstructure:"min_idle_conns" jsonschema:"default=5,minimum=0,description=Minimum idle connections in pool"`
	// KeyPrefix is the Redis key prefix
	KeyPrefix string `yaml:"key_prefix" mapstructure:"key_prefix" jsonschema:"default=authportal:session:,description=Redis key prefix for session keys"`
}

// RedisTLSConfig represents Redis TLS configuration
type RedisTLSConfig struct {
	// Enabled enables TLS for Redis connection
	Enabled bool `yaml:"enabled" mapstructure:"enabled" jsonschema:"default=false,description=Enable TLS for Redis connection"`
	// Cert is the path to client certificate
	Cert string `yaml:"cert" mapstructure:"cert" jsonschema:"description=Path to client TLS certificate file"`
	// Key is the path to client private key
	Key string `yaml:"key" mapstructure:"key" jsonschema:"description=Path to client TLS private key file"`
	// CA is the path to CA certificate
	CA string `yaml:"ca" mapstructure:"ca" jsonschema:"description=Path to CA certificate file for server verification"`
}

// TokenConfig represents token refresh configuration
type TokenConfig struct {
	// AutoRefresh enables automatic token refresh
	AutoRefresh bool `yaml:"auto_refresh" mapstructure:"auto_refresh" jsonschema:"default=true,description=Enable automatic token refresh before expiry"`
	// RefreshThreshold is when to refresh before expiry
	RefreshThreshold time.Duration `yaml:"refresh_threshold" mapstructure:"refresh_threshold" jsonschema:"default=5m,description=Refresh token when this much time remains before expiry"`
}

// ServiceConfig represents a backend service (junction)
type ServiceConfig struct {
	// Name is the service identifier
	Name string `yaml:"name" mapstructure:"name" jsonschema:"required,pattern=^[a-z0-9-]+$,description=Unique service identifier (lowercase alphanumeric with hyphens)"`
	// DisplayName is shown in the portal UI
	DisplayName string `yaml:"display_name" mapstructure:"display_name" jsonschema:"description=Display name shown in the portal UI"`
	// Description is the service description
	Description string `yaml:"description" mapstructure:"description" jsonschema:"description=Service description shown in the portal"`
	// Icon is the service icon
	Icon string `yaml:"icon" mapstructure:"icon" jsonschema:"description=Icon class (FontAwesome) or URL for the service card"`
	// Location is the nginx location path
	Location string `yaml:"location" mapstructure:"location" jsonschema:"description=Nginx location path like /grafana/"`
	// Upstream is the backend URL
	Upstream string `yaml:"upstream" mapstructure:"upstream" jsonschema:"required,format=uri,description=Backend service URL like http://grafana:3000"`
	// AuthRequired requires authentication for this service
	AuthRequired bool `yaml:"auth_required" mapstructure:"auth_required" jsonschema:"default=true,description=Require authentication to access this service"`
	// Rewrite is the URL rewrite rule
	Rewrite string `yaml:"rewrite" mapstructure:"rewrite" jsonschema:"description=URL rewrite rule (nginx rewrite syntax)"`
	// Headers contains header manipulation rules
	Headers HeadersConfig `yaml:"headers" mapstructure:"headers" jsonschema:"description=HTTP header manipulation rules"`
	// NginxExtra contains additional nginx configuration
	NginxExtra string `yaml:"nginx_extra" mapstructure:"nginx_extra" jsonschema:"description=Additional nginx configuration for this location"`
	// Visibility controls which users can see this service in the portal
	Visibility *VisibilityConfig `yaml:"visibility,omitempty" mapstructure:"visibility" jsonschema:"description=Role/group-based visibility control for this service in the portal"`
}

// HeadersConfig represents header manipulation configuration
type HeadersConfig struct {
	// Add contains headers to add to requests
	Add map[string]string `yaml:"add" mapstructure:"add" jsonschema:"description=Headers to add to proxied requests (supports {{.User.*}} templates)"`
	// Remove contains headers to remove from requests
	Remove []string `yaml:"remove" mapstructure:"remove" jsonschema:"description=Headers to remove from proxied requests"`
}

// VisibilityConfig controls which users can see the service in the portal
type VisibilityConfig struct {
	// Roles specifies which roles can see this service
	Roles []string `yaml:"roles" mapstructure:"roles" jsonschema:"description=List of roles that can see this service (user must have at least one if mode=any or all if mode=all)"`
	// Groups specifies which groups can see this service
	Groups []string `yaml:"groups" mapstructure:"groups" jsonschema:"description=List of groups that can see this service (user must be in at least one if mode=any or all if mode=all)"`
	// Mode specifies how to combine role/group requirements: 'any' (OR) or 'all' (AND)
	Mode string `yaml:"mode" mapstructure:"mode" jsonschema:"default=any,enum=any,enum=all,description=How to combine role and group requirements: any (OR) or all (AND)"`
}

// DevModeConfig represents development mode configuration
type DevModeConfig struct {
	// Enabled enables development mode
	Enabled bool `yaml:"enabled" mapstructure:"enabled" jsonschema:"default=false,description=Enable development mode with mock authentication"`
	// ProfilesDir is the directory with user profiles
	ProfilesDir string `yaml:"profiles_dir" mapstructure:"profiles_dir" jsonschema:"default=./profiles,description=Directory containing mock user profile YAML files"`
	// DefaultProfile is the default user profile
	DefaultProfile string `yaml:"default_profile" mapstructure:"default_profile" jsonschema:"default=developer,description=Default mock user profile to use"`
}

// NginxConfig represents Nginx configuration
type NginxConfig struct {
	// WorkerProcesses is the number of nginx worker processes
	WorkerProcesses string `yaml:"worker_processes" mapstructure:"worker_processes" jsonschema:"default=auto,description=Number of nginx worker processes (auto or number)"`
	// WorkerConnections is the max connections per worker
	WorkerConnections int `yaml:"worker_connections" mapstructure:"worker_connections" jsonschema:"default=1024,minimum=256,description=Maximum connections per nginx worker"`
	// KeepaliveTimeout is the keepalive timeout in seconds
	KeepaliveTimeout int `yaml:"keepalive_timeout" mapstructure:"keepalive_timeout" jsonschema:"default=65,minimum=0,description=HTTP keepalive timeout in seconds"`
	// ClientMaxBodySize is the max request body size
	ClientMaxBodySize string `yaml:"client_max_body_size" mapstructure:"client_max_body_size" jsonschema:"default=100m,pattern=^[0-9]+(k|m|g)?$,description=Maximum client request body size like 100m or 1g"`
	// RateLimit contains nginx rate limiting settings
	RateLimit RateLimitConfig `yaml:"rate_limit" mapstructure:"rate_limit" jsonschema:"description=Nginx rate limiting configuration"`
	// AccessLog is the path to access log
	AccessLog string `yaml:"access_log" mapstructure:"access_log" jsonschema:"default=/var/log/nginx/access.log,description=Path to nginx access log file"`
	// ErrorLog is the path to error log
	ErrorLog string `yaml:"error_log" mapstructure:"error_log" jsonschema:"default=/var/log/nginx/error.log,description=Path to nginx error log file"`
	// LogFormat is the custom log format name
	LogFormat string `yaml:"log_format" mapstructure:"log_format" jsonschema:"description=Custom nginx log format name"`
}

// RateLimitConfig represents nginx rate limiting configuration
type RateLimitConfig struct {
	// Enabled enables nginx rate limiting
	Enabled bool `yaml:"enabled" mapstructure:"enabled" jsonschema:"default=false,description=Enable nginx rate limiting"`
	// ZoneSize is the shared memory zone size
	ZoneSize string `yaml:"zone_size" mapstructure:"zone_size" jsonschema:"default=10m,pattern=^[0-9]+(k|m)?$,description=Shared memory zone size for rate limiting like 10m"`
	// RequestsPerSecond is the rate limit
	RequestsPerSecond int `yaml:"requests_per_second" mapstructure:"requests_per_second" jsonschema:"default=10,minimum=1,description=Maximum requests per second per client IP"`
	// Burst is the burst size
	Burst int `yaml:"burst" mapstructure:"burst" jsonschema:"default=20,minimum=0,description=Maximum burst of requests allowed"`
}

// ObservabilityConfig represents observability configuration
type ObservabilityConfig struct {
	// Metrics contains Prometheus metrics settings
	Metrics MetricsConfig `yaml:"metrics" mapstructure:"metrics" jsonschema:"description=Prometheus metrics configuration"`
	// Tracing contains distributed tracing settings
	Tracing TracingConfig `yaml:"tracing" mapstructure:"tracing" jsonschema:"description=OpenTelemetry distributed tracing configuration"`
	// Health contains health check settings
	Health HealthConfig `yaml:"health" mapstructure:"health" jsonschema:"description=Health check endpoint configuration"`
	// Ready contains readiness check settings
	Ready ReadyConfig `yaml:"ready" mapstructure:"ready" jsonschema:"description=Readiness probe endpoint configuration"`
}

// TracingConfig represents distributed tracing configuration
type TracingConfig struct {
	// Enabled enables distributed tracing
	Enabled bool `yaml:"enabled" mapstructure:"enabled" jsonschema:"default=false,description=Enable OpenTelemetry distributed tracing"`
	// Endpoint is the OTLP collector endpoint
	Endpoint string `yaml:"endpoint" mapstructure:"endpoint" jsonschema:"default=localhost:4317,description=OTLP collector endpoint (host:port)"`
	// Protocol is the OTLP protocol
	Protocol string `yaml:"protocol" mapstructure:"protocol" jsonschema:"enum=grpc,enum=http,default=grpc,description=OTLP protocol: grpc or http"`
	// Insecure disables TLS for collector connection
	Insecure bool `yaml:"insecure" mapstructure:"insecure" jsonschema:"default=true,description=Disable TLS for OTLP collector connection"`
	// SamplingRatio is the trace sampling rate
	SamplingRatio float64 `yaml:"sampling_ratio" mapstructure:"sampling_ratio" jsonschema:"default=1.0,minimum=0.0,maximum=1.0,description=Trace sampling ratio (0.0 to 1.0)"`
	// Headers are additional OTLP headers
	Headers map[string]string `yaml:"headers" mapstructure:"headers" jsonschema:"description=Additional HTTP headers for OTLP requests"`
}

// MetricsConfig represents metrics configuration
type MetricsConfig struct {
	// Enabled enables Prometheus metrics
	Enabled bool `yaml:"enabled" mapstructure:"enabled" jsonschema:"default=true,description=Enable Prometheus metrics endpoint"`
	// Path is the metrics endpoint path
	Path string `yaml:"path" mapstructure:"path" jsonschema:"default=/metrics,description=Prometheus metrics endpoint path"`
	// AllowedCIDRs restricts metrics endpoint access to specified CIDR ranges (HIGH-03 security fix)
	AllowedCIDRs []string `yaml:"allowed_cidrs" mapstructure:"allowed_cidrs" jsonschema:"description=CIDR ranges allowed to access metrics endpoint (e.g. 10.0.0.0/8 or 192.168.0.0/16)"`
}

// HealthConfig represents health check configuration
type HealthConfig struct {
	// Path is the health check endpoint path
	Path string `yaml:"path" mapstructure:"path" jsonschema:"default=/health,description=Health check endpoint path"`
}

// ReadyConfig represents readiness check configuration
type ReadyConfig struct {
	// Path is the readiness endpoint path
	Path string `yaml:"path" mapstructure:"path" jsonschema:"default=/ready,description=Readiness probe endpoint path"`
}

// ResilienceConfig holds resilience configuration
type ResilienceConfig struct {
	// RateLimit configuration for incoming HTTP requests
	RateLimit HTTPRateLimitConfig `yaml:"rate_limit" mapstructure:"rate_limit" jsonschema:"description=HTTP rate limiting configuration for incoming requests"`
	// CircuitBreaker configuration for external service calls
	CircuitBreaker CircuitBreakerConfig `yaml:"circuit_breaker" mapstructure:"circuit_breaker" jsonschema:"description=Circuit breaker configuration for external service calls"`
}

// HTTPRateLimitConfig holds HTTP rate limiting configuration for resilience
type HTTPRateLimitConfig struct {
	// Enabled enables rate limiting
	Enabled bool `yaml:"enabled" mapstructure:"enabled" jsonschema:"default=false,description=Enable HTTP rate limiting"`
	// Rate is the rate limit in format 'requests-period'
	Rate string `yaml:"rate" mapstructure:"rate" jsonschema:"default=100-S,pattern=^[0-9]+-[SMHD]$,description=Rate limit format requests-period like 100-S for 100 req/sec or 1000-M for 1000 req/min"`
	// TrustForwardedFor trusts X-Forwarded-For header for client IP
	TrustForwardedFor bool `yaml:"trust_forwarded_for" mapstructure:"trust_forwarded_for" jsonschema:"default=false,description=Trust X-Forwarded-For header for client IP detection (enable behind proxy)"`
	// ExcludePaths excludes paths from rate limiting
	ExcludePaths []string `yaml:"exclude_paths" mapstructure:"exclude_paths" jsonschema:"description=Paths to exclude from rate limiting"`
	// ByEndpoint enables per-endpoint rate limiting
	ByEndpoint bool `yaml:"by_endpoint" mapstructure:"by_endpoint" jsonschema:"default=false,description=Enable different rate limits per endpoint"`
	// EndpointRates defines per-endpoint rate limits
	EndpointRates map[string]string `yaml:"endpoint_rates" mapstructure:"endpoint_rates" jsonschema:"description=Per-endpoint rate limits (path to rate format)"`
	// Headers configuration for rate limit response headers
	Headers HTTPRateLimitHeadersConfig `yaml:"headers" mapstructure:"headers" jsonschema:"description=Rate limit headers configuration"`
	// FailClose denies requests when rate limiter encounters an error
	FailClose bool `yaml:"fail_close" mapstructure:"fail_close" jsonschema:"default=false,description=Deny requests when rate limiter encounters an error"`
}

// HTTPRateLimitHeadersConfig holds rate limit headers configuration
type HTTPRateLimitHeadersConfig struct {
	// Enabled enables rate limit headers in response
	Enabled bool `yaml:"enabled" mapstructure:"enabled" jsonschema:"default=true,description=Include rate limit headers in responses"`
	// LimitHeader is the header name for rate limit
	LimitHeader string `yaml:"limit_header" mapstructure:"limit_header" jsonschema:"default=X-RateLimit-Limit,description=Header name for rate limit value"`
	// RemainingHeader is the header name for remaining requests
	RemainingHeader string `yaml:"remaining_header" mapstructure:"remaining_header" jsonschema:"default=X-RateLimit-Remaining,description=Header name for remaining requests"`
	// ResetHeader is the header name for reset timestamp
	ResetHeader string `yaml:"reset_header" mapstructure:"reset_header" jsonschema:"default=X-RateLimit-Reset,description=Header name for rate limit reset timestamp"`
}

// CircuitBreakerConfig holds circuit breaker configuration
type CircuitBreakerConfig struct {
	// Enabled enables circuit breaker
	Enabled bool `yaml:"enabled" mapstructure:"enabled" jsonschema:"default=false,description=Enable circuit breaker for external service calls"`
	// Default settings for all circuit breakers
	Default CircuitBreakerSettings `yaml:"default" mapstructure:"default" jsonschema:"description=Default settings for all circuit breakers"`
	// Services holds per-service circuit breaker settings
	Services map[string]CircuitBreakerSettings `yaml:"services" mapstructure:"services" jsonschema:"description=Per-service circuit breaker settings (overrides defaults)"`
}

// CircuitBreakerSettings holds settings for a single circuit breaker
type CircuitBreakerSettings struct {
	// MaxRequests is the maximum number of requests in half-open state
	MaxRequests uint32 `yaml:"max_requests" mapstructure:"max_requests" jsonschema:"default=3,minimum=1,description=Maximum requests allowed in half-open state"`
	// Interval is the cyclic period for clearing counts in closed state
	Interval time.Duration `yaml:"interval" mapstructure:"interval" jsonschema:"default=60s,description=Period for clearing failure counts in closed state"`
	// Timeout is the period of open state before switching to half-open
	Timeout time.Duration `yaml:"timeout" mapstructure:"timeout" jsonschema:"default=30s,description=Duration in open state before transitioning to half-open"`
	// FailureThreshold is the number of consecutive failures to open circuit
	FailureThreshold uint32 `yaml:"failure_threshold" mapstructure:"failure_threshold" jsonschema:"default=5,minimum=1,description=Consecutive failures required to open circuit"`
	// SuccessThreshold is the number of consecutive successes to close circuit
	SuccessThreshold uint32 `yaml:"success_threshold" mapstructure:"success_threshold" jsonschema:"default=2,minimum=1,description=Consecutive successes required to close circuit"`
	// OnStateChange enables logging on state changes
	OnStateChange bool `yaml:"on_state_change" mapstructure:"on_state_change" jsonschema:"default=true,description=Log circuit breaker state changes"`
}
