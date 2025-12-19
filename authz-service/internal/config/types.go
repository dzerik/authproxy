package config

import (
	"time"
)

// ConfigType represents the type of configuration.
type ConfigType string

const (
	// ConfigTypeEnvironment is static configuration loaded at startup.
	ConfigTypeEnvironment ConfigType = "environment"
	// ConfigTypeServices is dynamic service configuration.
	ConfigTypeServices ConfigType = "services"
	// ConfigTypeRules is dynamic authorization rules configuration.
	ConfigTypeRules ConfigType = "rules"
)

// =============================================================================
// Environment Configuration (Static - requires restart)
// =============================================================================

// EnvironmentConfig holds static configuration that requires restart to change.
// This includes server ports, logging format, and config source settings.
type EnvironmentConfig struct {
	// Env holds environment information
	Env EnvConfig `mapstructure:"env" jsonschema:"description=Environment information for deployment context." jsonschema_extras:"x-runtime-updatable=false"`
	// Server configuration for HTTP and gRPC endpoints
	Server ServerConfig `mapstructure:"server" jsonschema:"description=Server configuration for HTTP and gRPC endpoints." jsonschema_extras:"x-runtime-updatable=false"`
	// Management server configuration for admin endpoints
	Management ManagementServerConfig `mapstructure:"management" jsonschema:"description=Management server configuration for admin/debug endpoints (Istio-style)." jsonschema_extras:"x-runtime-updatable=false"`
	// Logging configuration
	Logging LoggingConfig `mapstructure:"logging" jsonschema:"description=Application logging configuration." jsonschema_extras:"x-runtime-updatable=false"`
	// Tracing configuration for OpenTelemetry
	Tracing TracingConfig `mapstructure:"tracing" jsonschema:"description=OpenTelemetry distributed tracing configuration." jsonschema_extras:"x-runtime-updatable=false"`
	// ConfigSource defines where to load services and rules configuration
	ConfigSource ConfigSourceSettings `mapstructure:"config_source" jsonschema:"description=Configuration source settings for services and rules." jsonschema_extras:"x-runtime-updatable=false"`
}

// ManagementServerConfig holds management/admin server configuration.
type ManagementServerConfig struct {
	// Enabled enables the management server
	Enabled bool `mapstructure:"enabled" jsonschema:"description=Enable management server for admin endpoints.,default=true" jsonschema_extras:"x-runtime-updatable=false"`
	// AdminAddr is the admin interface address (like Istio :15000)
	AdminAddr string `mapstructure:"admin_addr" jsonschema:"description=Admin interface listen address (config_dump\\, stats\\, logging).,default=:15000" jsonschema_extras:"x-runtime-updatable=false"`
	// HealthAddr is the aggregated health/metrics address (like Istio :15020)
	HealthAddr string `mapstructure:"health_addr" jsonschema:"description=Aggregated health and metrics listen address.,default=:15020" jsonschema_extras:"x-runtime-updatable=false"`
	// ReadyAddr is the readiness probe address (like Istio :15021)
	ReadyAddr string `mapstructure:"ready_addr" jsonschema:"description=Dedicated readiness probe listen address.,default=:15021" jsonschema_extras:"x-runtime-updatable=false"`
}

// LoggingConfig holds logging configuration.
type LoggingConfig struct {
	// Level is the logging level
	Level string `mapstructure:"level" jsonschema:"description=Log level.,enum=debug,enum=info,enum=warn,enum=error,default=info" jsonschema_extras:"x-runtime-updatable=false"`
	// Format is the log output format
	Format string `mapstructure:"format" jsonschema:"description=Log output format.,enum=json,enum=text,default=json" jsonschema_extras:"x-runtime-updatable=false"`
	// Output is the log output destination
	Output string `mapstructure:"output" jsonschema:"description=Log output destination.,enum=stdout,enum=stderr,default=stdout" jsonschema_extras:"x-runtime-updatable=false"`
	// AddCaller adds caller information to logs
	AddCaller bool `mapstructure:"add_caller" jsonschema:"description=Add caller information to log entries.,default=true" jsonschema_extras:"x-runtime-updatable=false"`
}

// ConfigSourceSettings defines configuration source settings.
type ConfigSourceSettings struct {
	// Type is the config source type
	Type string `mapstructure:"type" jsonschema:"description=Configuration source type.,enum=file,enum=remote,enum=hybrid,default=file"`
	// File holds file-based config source settings
	File FileSourceSettings `mapstructure:"file" jsonschema:"description=File-based configuration source settings."`
	// Remote holds remote config service settings
	Remote RemoteSourceSettings `mapstructure:"remote" jsonschema:"description=Remote configuration service settings."`
	// Fallback configuration when remote is unavailable
	Fallback FallbackSourceSettings `mapstructure:"fallback" jsonschema:"description=Fallback settings when remote config source is unavailable."`
}

// FileSourceSettings holds file-based config source settings.
type FileSourceSettings struct {
	// ServicesPath is the path to services configuration file
	ServicesPath string `mapstructure:"services_path" jsonschema:"description=Path to services configuration file.,default=/etc/authz/services.yaml"`
	// RulesPath is the path to rules configuration file
	RulesPath string `mapstructure:"rules_path" jsonschema:"description=Path to authorization rules file.,default=/etc/authz/rules.yaml"`
	// WatchEnabled enables file watching for hot reload
	WatchEnabled bool `mapstructure:"watch_enabled" jsonschema:"description=Enable file watching for automatic reload on changes.,default=true"`
}

// RemoteSourceSettings holds remote config service settings.
type RemoteSourceSettings struct {
	// Endpoint is the config service URL
	Endpoint string `mapstructure:"endpoint" jsonschema:"description=Remote configuration service endpoint URL."`
	// Auth holds authentication settings for config service
	Auth RemoteAuthSettings `mapstructure:"auth" jsonschema:"description=Authentication settings for remote config service."`
	// Paths holds API paths for different config types
	Paths RemotePathSettings `mapstructure:"paths" jsonschema:"description=API paths for configuration resources."`
	// Polling configuration
	Polling PollingSettings `mapstructure:"polling" jsonschema:"description=Polling configuration for config updates."`
	// Push configuration for real-time updates
	Push PushSettings `mapstructure:"push" jsonschema:"description=Push notification settings for real-time config updates."`
}

// RemoteAuthSettings holds authentication settings for remote config service.
type RemoteAuthSettings struct {
	// Type is the authentication type
	Type string `mapstructure:"type" jsonschema:"description=Authentication type for config service.,enum=none,enum=mtls,enum=token,enum=oidc,default=none"`
	// ClientCert is path to client certificate (for mTLS)
	ClientCert string `mapstructure:"client_cert" jsonschema:"description=Path to client certificate for mTLS authentication."`
	// ClientKey is path to client key (for mTLS)
	ClientKey string `mapstructure:"client_key" jsonschema:"description=Path to client key for mTLS authentication."`
	// CACert is path to CA certificate
	CACert string `mapstructure:"ca_cert" jsonschema:"description=Path to CA certificate for server verification."`
	// Token is the bearer token (for token auth)
	Token string `mapstructure:"token" jsonschema:"description=Bearer token for authentication. Consider using environment variable."`
	// TokenFile is path to file containing token
	TokenFile string `mapstructure:"token_file" jsonschema:"description=Path to file containing bearer token."`
}

// RemotePathSettings holds API paths for config resources.
type RemotePathSettings struct {
	// Services is the path to services config
	Services string `mapstructure:"services" jsonschema:"description=API path for services configuration.,default=/api/v1/configs/authz/services"`
	// Rules is the path to rules config
	Rules string `mapstructure:"rules" jsonschema:"description=API path for authorization rules.,default=/api/v1/configs/authz/rules"`
}

// PollingSettings holds polling configuration.
type PollingSettings struct {
	// Enabled enables polling for config updates
	Enabled bool `mapstructure:"enabled" jsonschema:"description=Enable polling for configuration updates.,default=true"`
	// Interval is the polling interval
	Interval time.Duration `mapstructure:"interval" jsonschema:"description=Polling interval for configuration updates.,default=30s"`
	// Timeout is the request timeout
	Timeout time.Duration `mapstructure:"timeout" jsonschema:"description=Timeout for polling requests.,default=10s"`
	// Retry configuration
	Retry RetrySettings `mapstructure:"retry" jsonschema:"description=Retry settings for failed polling requests."`
}

// RetrySettings holds retry configuration.
type RetrySettings struct {
	// MaxAttempts is the maximum retry attempts
	MaxAttempts int `mapstructure:"max_attempts" jsonschema:"description=Maximum retry attempts.,default=3"`
	// Backoff is the initial backoff duration
	Backoff time.Duration `mapstructure:"backoff" jsonschema:"description=Initial backoff duration.,default=1s"`
	// MaxBackoff is the maximum backoff duration
	MaxBackoff time.Duration `mapstructure:"max_backoff" jsonschema:"description=Maximum backoff duration.,default=30s"`
}

// PushSettings holds push notification configuration.
type PushSettings struct {
	// Enabled enables push notifications
	Enabled bool `mapstructure:"enabled" jsonschema:"description=Enable push notifications for real-time updates.,default=false"`
	// Type is the push notification type
	Type string `mapstructure:"type" jsonschema:"description=Push notification type.,enum=sse,enum=websocket,enum=grpc-stream,default=sse"`
}

// FallbackSourceSettings holds fallback configuration.
type FallbackSourceSettings struct {
	// Enabled enables fallback to cached config
	Enabled bool `mapstructure:"enabled" jsonschema:"description=Enable fallback to cached configuration when remote is unavailable.,default=true"`
	// CachePath is the path to cached configurations
	CachePath string `mapstructure:"cache_path" jsonschema:"description=Path to store cached configurations.,default=/var/cache/authz/"`
	// MaxAge is the maximum age of cached config to use
	MaxAge time.Duration `mapstructure:"max_age" jsonschema:"description=Maximum age of cached configuration to use as fallback.,default=1h"`
}

// =============================================================================
// Services Configuration (Dynamic - runtime updatable)
// =============================================================================

// ServicesConfig holds dynamic service configuration that can be updated at runtime.
type ServicesConfig struct {
	// Version is the configuration version
	Version string `mapstructure:"version" jsonschema:"description=Configuration version for change tracking." jsonschema_extras:"x-runtime-updatable=true"`
	// JWT validation configuration
	JWT JWTConfig `mapstructure:"jwt" jsonschema:"description=JWT token validation configuration." jsonschema_extras:"x-runtime-updatable=true"`
	// TokenExchange configuration (RFC 8693)
	TokenExchange TokenExchangeConfig `mapstructure:"token_exchange" jsonschema:"description=OAuth2 Token Exchange configuration." jsonschema_extras:"x-runtime-updatable=true"`
	// Policy engine configuration
	Policy PolicyConfig `mapstructure:"policy" jsonschema:"description=Policy engine configuration." jsonschema_extras:"x-runtime-updatable=true"`
	// Cache configuration
	Cache CacheConfig `mapstructure:"cache" jsonschema:"description=Caching configuration." jsonschema_extras:"x-runtime-updatable=true"`
	// Audit logging configuration
	Audit AuditConfig `mapstructure:"audit" jsonschema:"description=Audit logging configuration." jsonschema_extras:"x-runtime-updatable=true"`
	// Health check configuration
	Health HealthConfig `mapstructure:"health" jsonschema:"description=Health check configuration." jsonschema_extras:"x-runtime-updatable=true"`
	// Resilience configuration
	Resilience ResilienceConfig `mapstructure:"resilience" jsonschema:"description=Resilience patterns configuration." jsonschema_extras:"x-runtime-updatable=true"`
	// SensitiveData handling configuration
	SensitiveData SensitiveDataConfig `mapstructure:"sensitive_data" jsonschema:"description=Sensitive data handling configuration." jsonschema_extras:"x-runtime-updatable=true"`
	// TLSClientCert configuration
	TLSClientCert TLSClientCertConfig `mapstructure:"tls_client_cert" jsonschema:"description=TLS client certificate configuration." jsonschema_extras:"x-runtime-updatable=true"`
	// RequestBody access configuration
	RequestBody RequestBodyConfig `mapstructure:"request_body" jsonschema:"description=Request body access configuration." jsonschema_extras:"x-runtime-updatable=true"`
	// Proxy holds proxy listener configurations
	Proxy ProxyListenersConfig `mapstructure:"proxy" jsonschema:"description=Reverse proxy listeners configuration." jsonschema_extras:"x-runtime-updatable=true"`
	// Egress holds egress listener configurations
	Egress EgressListenersConfig `mapstructure:"egress" jsonschema:"description=Egress proxy listeners configuration." jsonschema_extras:"x-runtime-updatable=true"`
}

// =============================================================================
// Multi-Listener Proxy Configuration
// =============================================================================

// ProxyListenersConfig holds configuration for multiple proxy listeners.
type ProxyListenersConfig struct {
	// Enabled enables proxy mode globally
	Enabled bool `mapstructure:"enabled" jsonschema:"description=Enable reverse proxy mode globally.,default=false" jsonschema_extras:"x-runtime-updatable=true"`
	// Listeners is a list of proxy listener configurations
	Listeners []ProxyListenerConfig `mapstructure:"listeners" jsonschema:"description=List of proxy listener configurations. Each listener runs on a separate port." jsonschema_extras:"x-runtime-updatable=true,x-runtime-update-note=Adding new listeners may require port binding"`
	// Defaults holds default settings for all listeners
	Defaults ProxyDefaultsConfig `mapstructure:"defaults" jsonschema:"description=Default settings applied to all proxy listeners." jsonschema_extras:"x-runtime-updatable=true"`
}

// ProxyListenerConfig holds configuration for a single proxy listener.
type ProxyListenerConfig struct {
	// Name is the unique listener name
	Name string `mapstructure:"name" jsonschema:"description=Unique listener name for identification.,required" jsonschema_extras:"x-runtime-updatable=false"`
	// Port is the listener port (bound from environment config or dynamic)
	Port int `mapstructure:"port" jsonschema:"description=Listener port. Can reference environment server ports or be a new dynamic port." jsonschema_extras:"x-runtime-updatable=false,x-runtime-update-note=Port change requires restart"`
	// Bind is the bind address
	Bind string `mapstructure:"bind" jsonschema:"description=Bind address for the listener.,default=0.0.0.0" jsonschema_extras:"x-runtime-updatable=false"`
	// Mode is the proxy mode
	Mode string `mapstructure:"mode" jsonschema:"description=Proxy operation mode.,enum=reverse_proxy,enum=decision_only,default=reverse_proxy" jsonschema_extras:"x-runtime-updatable=true"`
	// Upstreams is a map of named upstreams
	Upstreams map[string]UpstreamConfig `mapstructure:"upstreams" jsonschema:"description=Named upstream servers for this listener." jsonschema_extras:"x-runtime-updatable=true"`
	// Routes are routing rules for this listener
	Routes []RouteConfig `mapstructure:"routes" jsonschema:"description=Routing rules for this listener." jsonschema_extras:"x-runtime-updatable=true"`
	// Headers configuration for this listener
	Headers ProxyHeadersConfig `mapstructure:"headers" jsonschema:"description=Header manipulation for this listener." jsonschema_extras:"x-runtime-updatable=true"`
	// Timeout for requests on this listener
	Timeout time.Duration `mapstructure:"timeout" jsonschema:"description=Request timeout for this listener." jsonschema_extras:"x-runtime-updatable=true"`
	// Retry configuration for this listener
	Retry ProxyRetryConfig `mapstructure:"retry" jsonschema:"description=Retry configuration for this listener." jsonschema_extras:"x-runtime-updatable=true"`
	// RequireAuth requires authorization for all requests
	RequireAuth bool `mapstructure:"require_auth" jsonschema:"description=Require authorization for all requests on this listener.,default=true" jsonschema_extras:"x-runtime-updatable=true"`
}

// ProxyDefaultsConfig holds default settings for proxy listeners.
type ProxyDefaultsConfig struct {
	// Timeout is the default request timeout
	Timeout time.Duration `mapstructure:"timeout" jsonschema:"description=Default request timeout.,default=30s"`
	// IdleConnTimeout is the idle connection timeout
	IdleConnTimeout time.Duration `mapstructure:"idle_conn_timeout" jsonschema:"description=Idle connection timeout.,default=90s"`
	// MaxIdleConns is the maximum idle connections
	MaxIdleConns int `mapstructure:"max_idle_conns" jsonschema:"description=Maximum idle connections per host.,default=100"`
	// Headers are default header settings
	Headers ProxyHeadersConfig `mapstructure:"headers" jsonschema:"description=Default header settings."`
	// Retry are default retry settings
	Retry ProxyRetryConfig `mapstructure:"retry" jsonschema:"description=Default retry settings."`
}

// =============================================================================
// Multi-Listener Egress Configuration
// =============================================================================

// EgressListenersConfig holds configuration for multiple egress listeners.
type EgressListenersConfig struct {
	// Enabled enables egress mode globally
	Enabled bool `mapstructure:"enabled" jsonschema:"description=Enable egress proxy mode globally.,default=false" jsonschema_extras:"x-runtime-updatable=true"`
	// Listeners is a list of egress listener configurations
	Listeners []EgressListenerConfig `mapstructure:"listeners" jsonschema:"description=List of egress listener configurations. Each listener handles different external API categories." jsonschema_extras:"x-runtime-updatable=true,x-runtime-update-note=Adding new listeners may require port binding"`
	// Defaults holds default settings for all egress listeners
	Defaults EgressDefaultsConfig `mapstructure:"defaults" jsonschema:"description=Default settings for all egress listeners." jsonschema_extras:"x-runtime-updatable=true"`
	// TokenStore configuration for caching tokens
	TokenStore EgressTokenStoreConfig `mapstructure:"token_store" jsonschema:"description=Token storage configuration." jsonschema_extras:"x-runtime-updatable=true"`
	// LegacyEndpoint configuration for backward compatibility
	LegacyEndpoint LegacyEgressEndpoint `mapstructure:"legacy_endpoint" jsonschema:"description=Legacy egress endpoint on main server port for backward compatibility." jsonschema_extras:"x-runtime-updatable=true"`
}

// EgressListenerConfig holds configuration for a single egress listener.
type EgressListenerConfig struct {
	// Name is the unique listener name
	Name string `mapstructure:"name" jsonschema:"description=Unique listener name.,required" jsonschema_extras:"x-runtime-updatable=false"`
	// Port is the listener port
	Port int `mapstructure:"port" jsonschema:"description=Listener port for this egress category.,required" jsonschema_extras:"x-runtime-updatable=false,x-runtime-update-note=Port change requires restart"`
	// Bind is the bind address
	Bind string `mapstructure:"bind" jsonschema:"description=Bind address for the listener.,default=0.0.0.0" jsonschema_extras:"x-runtime-updatable=false"`
	// Targets is a map of named external targets
	Targets map[string]EgressTargetConfig `mapstructure:"targets" jsonschema:"description=External targets for this listener." jsonschema_extras:"x-runtime-updatable=true"`
	// Routes are routing rules for this listener
	Routes []EgressRouteConfig `mapstructure:"routes" jsonschema:"description=Routing rules mapping paths to targets." jsonschema_extras:"x-runtime-updatable=true"`
	// DefaultTarget is the default target when no route matches
	DefaultTarget string `mapstructure:"default_target" jsonschema:"description=Default target when no route matches." jsonschema_extras:"x-runtime-updatable=true"`
	// Timeout for requests on this listener
	Timeout time.Duration `mapstructure:"timeout" jsonschema:"description=Request timeout for this listener." jsonschema_extras:"x-runtime-updatable=true"`
	// Retry configuration for this listener
	Retry EgressRetryConfig `mapstructure:"retry" jsonschema:"description=Retry configuration for this listener." jsonschema_extras:"x-runtime-updatable=true"`
}

// LegacyEgressEndpoint holds legacy egress endpoint configuration.
type LegacyEgressEndpoint struct {
	// Enabled enables legacy egress endpoint on main port
	Enabled bool `mapstructure:"enabled" jsonschema:"description=Enable legacy egress endpoint on main server port.,default=true"`
	// Path is the legacy endpoint path prefix
	Path string `mapstructure:"path" jsonschema:"description=Legacy egress endpoint path prefix.,default=/egress"`
}

// =============================================================================
// Config Update Types
// =============================================================================

// ConfigUpdate represents a configuration update event.
type ConfigUpdate struct {
	// Type is the configuration type that was updated
	Type ConfigType `json:"type"`
	// Version is the new configuration version
	Version string `json:"version"`
	// Config is the new configuration (type depends on Type)
	Config interface{} `json:"config"`
	// Timestamp is when the update occurred
	Timestamp time.Time `json:"timestamp"`
	// Source indicates where the update came from
	Source string `json:"source"`
}

// ConfigVersion holds version information for configurations.
type ConfigVersion struct {
	// Environment version (changes require restart)
	Environment string `json:"environment"`
	// Services version (runtime updatable)
	Services string `json:"services"`
	// Rules version (runtime updatable)
	Rules string `json:"rules"`
}
