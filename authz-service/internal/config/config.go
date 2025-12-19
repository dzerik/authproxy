package config

import (
	"time"

	"github.com/your-org/authz-service/pkg/logger"
)

// Config holds all application configuration.
// Deprecated: Use EnvironmentConfig and ServicesConfig for new code.
// This struct is maintained for backward compatibility during migration.
// Use Loader.ToConfig() to get a Config from the new split configurations.
type Config struct {
	// Server configuration for HTTP and gRPC endpoints
	Server ServerConfig `mapstructure:"server" jsonschema:"description=Server configuration for HTTP and gRPC endpoints."`
	// Proxy configuration for reverse proxy mode
	Proxy ProxyConfig `mapstructure:"proxy" jsonschema:"description=Reverse proxy configuration. When enabled\\, authz-service forwards authorized requests to upstream services."`
	// Egress configuration for outbound proxy mode
	Egress EgressConfig `mapstructure:"egress" jsonschema:"description=Egress proxy configuration. When enabled\\, adds authentication to outbound requests to external services."`
	// Endpoints configuration for API paths
	Endpoints EndpointsConfig `mapstructure:"endpoints" jsonschema:"description=Configurable API endpoint paths. Allows customizing URL paths for all service endpoints."`
	// JWT validation configuration
	JWT JWTConfig `mapstructure:"jwt" jsonschema:"description=JWT token validation configuration. Defines trusted issuers\\, JWKS caching\\, and validation rules."`
	// Token exchange configuration (RFC 8693)
	TokenExchange TokenExchangeConfig `mapstructure:"token_exchange" jsonschema:"description=OAuth2 Token Exchange (RFC 8693) configuration for token delegation scenarios."`
	// Policy engine configuration
	Policy PolicyConfig `mapstructure:"policy" jsonschema:"description=Policy engine configuration. Supports builtin YAML rules\\, embedded OPA\\, or external OPA sidecar."`
	// Cache configuration for performance
	Cache CacheConfig `mapstructure:"cache" jsonschema:"description=Caching configuration. L1 (in-memory) for low latency\\, L2 (Redis) for distributed caching."`
	// Audit logging configuration
	Audit AuditConfig `mapstructure:"audit" jsonschema:"description=Audit logging configuration. Records authorization decisions for compliance and debugging."`
	// Logging configuration
	Logging logger.Config `mapstructure:"logging" jsonschema:"description=Application logging configuration. Controls log level\\, format\\, and output."`
	// Health check configuration
	Health HealthConfig `mapstructure:"health" jsonschema:"description=Health check configuration for Kubernetes probes and monitoring."`
	// Resilience configuration (rate limiting, circuit breaker)
	Resilience ResilienceConfig `mapstructure:"resilience" jsonschema:"description=Resilience patterns configuration. Includes rate limiting for incoming requests and circuit breaker for external calls."`
	// Sensitive data handling configuration
	SensitiveData SensitiveDataConfig `mapstructure:"sensitive_data" jsonschema:"description=Sensitive data handling configuration. Controls masking of secrets\\, tokens\\, and PII in logs."`
	// Environment configuration for CEL expressions
	Env EnvConfig `mapstructure:"env" jsonschema:"description=Environment information for context-aware authorization. Available in CEL expressions as 'env' variable."`
	// TLS client certificate configuration for mTLS/SPIFFE identity
	TLSClientCert TLSClientCertConfig `mapstructure:"tls_client_cert" jsonschema:"description=Client certificate extraction configuration for mTLS and SPIFFE identity. Available in CEL expressions as 'tls' variable."`
	// Request body access configuration for authorization rules
	RequestBody RequestBodyConfig `mapstructure:"request_body" jsonschema:"description=Request body access configuration. WARNING: Enabling this feature has security and performance implications. Available in CEL expressions as 'body' variable."`
	// Tracing configuration for OpenTelemetry distributed tracing
	Tracing TracingConfig `mapstructure:"tracing" jsonschema:"description=OpenTelemetry distributed tracing configuration. Enables request tracing across services."`
	// Management server configuration for admin/debug endpoints (Istio-style)
	Management ManagementServerConfig `mapstructure:"management" jsonschema:"description=Management server configuration for admin/health/readiness endpoints on separate ports."`
}

// ProxyConfig holds reverse proxy configuration for forwarding authorized requests.
type ProxyConfig struct {
	// Enabled enables proxy mode
	Enabled bool `mapstructure:"enabled" jsonschema:"description=Enable reverse proxy mode. When true\\, authorized requests are forwarded to upstream services.,default=false"`
	// Mode determines proxy behavior
	Mode string `mapstructure:"mode" jsonschema:"description=Proxy operation mode.,enum=reverse_proxy,enum=decision_only,default=decision_only"`
	// Upstream is the default upstream destination
	Upstream UpstreamConfig `mapstructure:"upstream" jsonschema:"description=Default upstream server configuration. Used when no specific route matches."`
	// Upstreams is a map of named upstreams for routing
	Upstreams map[string]UpstreamConfig `mapstructure:"upstreams" jsonschema:"description=Named upstream servers for advanced routing. Reference by name in routes."`
	// Routes for selecting upstream based on path/headers
	Routes []RouteConfig `mapstructure:"routes" jsonschema:"description=Routing rules for selecting upstream based on request attributes (path\\, headers\\, methods)."`
	// Headers configuration
	Headers ProxyHeadersConfig `mapstructure:"headers" jsonschema:"description=Header manipulation settings for proxied requests."`
	// Timeout for proxy requests
	Timeout time.Duration `mapstructure:"timeout" jsonschema:"description=Request timeout for upstream connections.,default=30s"`
	// IdleConnTimeout for connection pool
	IdleConnTimeout time.Duration `mapstructure:"idle_conn_timeout" jsonschema:"description=Idle connection timeout for HTTP connection pool.,default=90s"`
	// Retry configuration
	Retry ProxyRetryConfig `mapstructure:"retry" jsonschema:"description=Retry configuration for failed upstream requests."`
}

// UpstreamConfig holds upstream server configuration.
type UpstreamConfig struct {
	// URL is the upstream base URL
	URL string `mapstructure:"url" jsonschema:"description=Base URL of the upstream server. Example: 'http://backend:8080' or 'https://api.internal.local'.,required"`
	// TLS configuration for upstream
	TLS UpstreamTLSConfig `mapstructure:"tls" jsonschema:"description=TLS configuration for secure upstream connections."`
	// HealthCheck configuration
	HealthCheck UpstreamHealthConfig `mapstructure:"health_check" jsonschema:"description=Health check configuration for upstream availability monitoring."`
}

// UpstreamTLSConfig holds TLS settings for upstream connections.
type UpstreamTLSConfig struct {
	// Enabled enables TLS for upstream
	Enabled bool `mapstructure:"enabled" jsonschema:"description=Enable TLS for upstream connections.,default=false"`
	// InsecureSkipVerify skips certificate verification
	InsecureSkipVerify bool `mapstructure:"insecure_skip_verify" jsonschema:"description=Skip server certificate verification. WARNING: Not recommended for production!,default=false"`
	// CACert is the path to CA certificate
	CACert string `mapstructure:"ca_cert" jsonschema:"description=Path to CA certificate file for server verification. Required for self-signed certificates."`
	// ClientCert is the path to client certificate for mTLS
	ClientCert string `mapstructure:"client_cert" jsonschema:"description=Path to client certificate for mutual TLS (mTLS) authentication."`
	// ClientKey is the path to client key for mTLS
	ClientKey string `mapstructure:"client_key" jsonschema:"description=Path to client private key for mutual TLS (mTLS) authentication."`
}

// UpstreamHealthConfig holds health check settings for upstream.
type UpstreamHealthConfig struct {
	Enabled  bool          `mapstructure:"enabled" jsonschema:"description=Enable periodic health checks for this upstream.,default=false"`
	Path     string        `mapstructure:"path" jsonschema:"description=HTTP path for health check requests.,default=/health"`
	Interval time.Duration `mapstructure:"interval" jsonschema:"description=Interval between health check requests.,default=10s"`
	Timeout  time.Duration `mapstructure:"timeout" jsonschema:"description=Timeout for health check requests.,default=5s"`
}

// RouteConfig holds routing configuration.
type RouteConfig struct {
	// PathPrefix matches requests starting with this prefix
	PathPrefix string `mapstructure:"path_prefix" jsonschema:"description=Match requests where path starts with this prefix. Example: '/api/v1'."`
	// PathExact matches requests with exact path
	PathExact string `mapstructure:"path_exact" jsonschema:"description=Match requests with exactly this path. Example: '/health'."`
	// PathRegex matches requests using regex
	PathRegex string `mapstructure:"path_regex" jsonschema:"description=Match requests using regex pattern. Example: '^/api/v[0-9]+/.*$'."`
	// Methods restricts to specific HTTP methods
	Methods []string `mapstructure:"methods" jsonschema:"description=HTTP methods to match. Empty means all methods.,example=GET,example=POST"`
	// Headers to match (exact values)
	Headers map[string]string `mapstructure:"headers" jsonschema:"description=Request headers to match (exact values). Example: {'X-Tenant': 'acme'}."`
	// Upstream is the target upstream name
	Upstream string `mapstructure:"upstream" jsonschema:"description=Name of the target upstream from 'upstreams' map."`
	// RewritePrefix replaces path prefix
	RewritePrefix string `mapstructure:"rewrite_prefix" jsonschema:"description=Replace matched prefix with this value. Used with strip_prefix."`
	// StripPrefix removes this prefix from path
	StripPrefix string `mapstructure:"strip_prefix" jsonschema:"description=Remove this prefix from path before forwarding. Example: '/api' strips '/api/users' to '/users'."`
}

// ProxyHeadersConfig holds header manipulation settings.
type ProxyHeadersConfig struct {
	// Add headers to forwarded requests
	Add map[string]string `mapstructure:"add" jsonschema:"description=Headers to add to forwarded requests. Example: {'X-Forwarded-Proto': 'https'}."`
	// Remove headers from forwarded requests
	Remove []string `mapstructure:"remove" jsonschema:"description=Headers to remove from forwarded requests. Example: ['Authorization'\\, 'Cookie']."`
	// Forward original headers (whitelist)
	Forward []string `mapstructure:"forward" jsonschema:"description=Headers to forward from original request (whitelist). Empty means forward all (except removed)."`
	// AddUserInfo adds user info headers after authorization
	AddUserInfo bool `mapstructure:"add_user_info" jsonschema:"description=Add user information headers (ID\\, roles) to forwarded requests.,default=true"`
	// UserIDHeader is the header name for user ID
	UserIDHeader string `mapstructure:"user_id_header" jsonschema:"description=Header name for user ID (from JWT 'sub' claim).,default=X-User-ID"`
	// UserRolesHeader is the header name for user roles
	UserRolesHeader string `mapstructure:"user_roles_header" jsonschema:"description=Header name for user roles (comma-separated).,default=X-User-Roles"`
}

// ProxyRetryConfig holds retry settings for proxy.
type ProxyRetryConfig struct {
	Enabled        bool          `mapstructure:"enabled" jsonschema:"description=Enable automatic retry for failed upstream requests.,default=true"`
	MaxAttempts    int           `mapstructure:"max_attempts" jsonschema:"description=Maximum number of retry attempts.,default=3,minimum=1,maximum=10"`
	InitialBackoff time.Duration `mapstructure:"initial_backoff" jsonschema:"description=Initial backoff delay before first retry.,default=100ms"`
	MaxBackoff     time.Duration `mapstructure:"max_backoff" jsonschema:"description=Maximum backoff delay between retries.,default=1s"`
	RetryOn        []int         `mapstructure:"retry_on" jsonschema:"description=HTTP status codes that trigger retry.,default=[502\\,503\\,504]"`
}

// =============================================================================
// Egress Proxy Configuration
// =============================================================================

// EgressConfig holds egress proxy configuration for outgoing requests to external systems.
type EgressConfig struct {
	// Enabled enables egress proxy mode
	Enabled bool `mapstructure:"enabled" jsonschema:"description=Enable egress proxy mode for authenticated outbound requests.,default=false"`
	// Targets is a map of named external systems
	Targets map[string]EgressTargetConfig `mapstructure:"targets" jsonschema:"description=Named external systems configuration. Each target defines URL\\, authentication\\, and TLS settings."`
	// Routes maps incoming paths to targets
	Routes []EgressRouteConfig `mapstructure:"routes" jsonschema:"description=Routing rules mapping request paths to external targets."`
	// Defaults holds default settings for all targets
	Defaults EgressDefaultsConfig `mapstructure:"defaults" jsonschema:"description=Default settings applied to all targets unless overridden."`
	// TokenStore configuration for caching tokens
	TokenStore EgressTokenStoreConfig `mapstructure:"token_store" jsonschema:"description=Token storage configuration for caching OAuth2 tokens."`
}

// EgressTargetConfig holds configuration for an external system.
type EgressTargetConfig struct {
	// URL is the base URL of the external system
	URL string `mapstructure:"url" jsonschema:"description=Base URL of the external service. Example: 'https://api.partner.com'.,required"`
	// Timeout for requests to this target
	Timeout time.Duration `mapstructure:"timeout" jsonschema:"description=Request timeout for this target. Overrides defaults.timeout.,default=30s"`
	// Auth configuration for this target
	Auth EgressAuthConfig `mapstructure:"auth" jsonschema:"description=Authentication configuration for requests to this target.,required"`
	// TLS configuration for this target
	TLS EgressTLSConfig `mapstructure:"tls" jsonschema:"description=TLS configuration for secure connections to this target."`
	// Retry configuration
	Retry EgressRetryConfig `mapstructure:"retry" jsonschema:"description=Retry configuration for failed requests to this target."`
}

// EgressAuthConfig holds authentication configuration for a target.
type EgressAuthConfig struct {
	// Type specifies the authentication method
	Type string `mapstructure:"type" jsonschema:"description=Authentication type for this target.,enum=oauth2_client_credentials,enum=oauth2_refresh_token,enum=gcp_service_account,enum=aws_iam,enum=api_key,enum=mtls,enum=basic,enum=bearer,required"`

	// OAuth2 Client Credentials fields
	TokenURL     string   `mapstructure:"token_url" jsonschema:"description=OAuth2 token endpoint URL. Used with oauth2_client_credentials and oauth2_refresh_token."`
	ClientID     string   `mapstructure:"client_id" jsonschema:"description=OAuth2 client ID."`
	ClientSecret string   `mapstructure:"client_secret" jsonschema:"description=OAuth2 client secret. Consider using environment variable: AUTHZ_EGRESS_TARGETS_<NAME>_AUTH_CLIENT_SECRET."`
	Scopes       []string `mapstructure:"scopes" jsonschema:"description=OAuth2 scopes to request.,example=read,example=write"`

	// OAuth2 Refresh Token field
	RefreshToken string `mapstructure:"refresh_token" jsonschema:"description=OAuth2 refresh token for oauth2_refresh_token type."`

	// RefreshBeforeExpiry refreshes token before it expires
	RefreshBeforeExpiry time.Duration `mapstructure:"refresh_before_expiry" jsonschema:"description=Refresh token this duration before expiry.,default=60s"`

	// GCP Service Account field
	CredentialsFile string `mapstructure:"credentials_file" jsonschema:"description=Path to GCP service account JSON key file. Used with gcp_service_account type."`

	// AWS IAM fields
	RoleARN string `mapstructure:"role_arn" jsonschema:"description=AWS IAM role ARN to assume. Used with aws_iam type."`
	Region  string `mapstructure:"region" jsonschema:"description=AWS region for IAM authentication.,example=us-east-1"`

	// API Key fields
	Header   string `mapstructure:"header" jsonschema:"description=Header name for API key. Example: 'X-API-Key'. Used with api_key type."`
	QueryKey string `mapstructure:"query_key" jsonschema:"description=Query parameter name for API key. Alternative to header."`
	Key      string `mapstructure:"key" jsonschema:"description=The API key value. Consider using environment variable."`

	// Basic Auth fields
	Username string `mapstructure:"username" jsonschema:"description=Username for basic authentication."`
	Password string `mapstructure:"password" jsonschema:"description=Password for basic authentication. Consider using environment variable."`

	// Bearer Token field
	Token string `mapstructure:"token" jsonschema:"description=Static bearer token. Consider using environment variable. Used with bearer type."`
}

// EgressTLSConfig holds TLS configuration for egress targets.
type EgressTLSConfig struct {
	// Enabled enables TLS
	Enabled bool `mapstructure:"enabled" jsonschema:"description=Enable TLS for connections to this target.,default=true"`
	// InsecureSkipVerify skips certificate verification
	InsecureSkipVerify bool `mapstructure:"insecure_skip_verify" jsonschema:"description=Skip server certificate verification. WARNING: Not recommended for production!,default=false"`
	// CACert is the path to CA certificate
	CACert string `mapstructure:"ca_cert" jsonschema:"description=Path to CA certificate for server verification."`
	// ClientCert is the path to client certificate for mTLS
	ClientCert string `mapstructure:"client_cert" jsonschema:"description=Path to client certificate for mTLS authentication."`
	// ClientKey is the path to client key for mTLS
	ClientKey string `mapstructure:"client_key" jsonschema:"description=Path to client private key for mTLS authentication."`
}

// EgressRetryConfig holds retry configuration for egress targets.
type EgressRetryConfig struct {
	MaxAttempts    int           `mapstructure:"max_attempts" jsonschema:"description=Maximum number of retry attempts.,default=3,minimum=1"`
	InitialBackoff time.Duration `mapstructure:"initial_backoff" jsonschema:"description=Initial backoff delay.,default=100ms"`
	MaxBackoff     time.Duration `mapstructure:"max_backoff" jsonschema:"description=Maximum backoff delay.,default=2s"`
}

// EgressRouteConfig holds routing configuration for egress.
type EgressRouteConfig struct {
	// PathPrefix matches requests starting with this prefix
	PathPrefix string `mapstructure:"path_prefix" jsonschema:"description=Match requests with path starting with this prefix. Example: '/external/partner-api'.,required"`
	// Target is the name of the target to route to
	Target string `mapstructure:"target" jsonschema:"description=Name of the target from 'targets' map to route to.,required"`
	// StripPrefix removes this prefix before forwarding
	StripPrefix string `mapstructure:"strip_prefix" jsonschema:"description=Remove this prefix from path before forwarding."`
	// RewritePrefix replaces the stripped prefix
	RewritePrefix string `mapstructure:"rewrite_prefix" jsonschema:"description=Replace stripped prefix with this value."`
	// Methods restricts to specific HTTP methods
	Methods []string `mapstructure:"methods" jsonschema:"description=Restrict to these HTTP methods. Empty means all methods."`
}

// EgressDefaultsConfig holds default settings for egress targets.
type EgressDefaultsConfig struct {
	Timeout time.Duration     `mapstructure:"timeout" jsonschema:"description=Default request timeout for all targets.,default=30s"`
	Retry   EgressRetryConfig `mapstructure:"retry" jsonschema:"description=Default retry configuration for all targets."`
}

// EgressTokenStoreConfig holds token store configuration.
type EgressTokenStoreConfig struct {
	// Type specifies the storage backend
	Type string `mapstructure:"type" jsonschema:"description=Token storage backend type.,enum=memory,enum=redis,default=memory"`
	// Redis configuration
	Redis EgressRedisConfig `mapstructure:"redis" jsonschema:"description=Redis configuration (when type=redis)."`
}

// EgressRedisConfig holds Redis configuration for egress token store.
type EgressRedisConfig struct {
	Address   string `mapstructure:"address" jsonschema:"description=Redis server address. Example: 'localhost:6379'."`
	Password  string `mapstructure:"password" jsonschema:"description=Redis password. Consider using environment variable."`
	DB        int    `mapstructure:"db" jsonschema:"description=Redis database number.,default=0"`
	KeyPrefix string `mapstructure:"key_prefix" jsonschema:"description=Prefix for token keys in Redis.,default=egress:tokens:"`
}

// EndpointsConfig holds configurable endpoint paths.
type EndpointsConfig struct {
	// Authorization endpoints
	Authorize      string `mapstructure:"authorize" jsonschema:"description=Single authorization check endpoint path.,default=/v1/authorize"`
	AuthorizeBatch string `mapstructure:"authorize_batch" jsonschema:"description=Batch authorization check endpoint path.,default=/v1/authorize/batch"`
	TokenValidate  string `mapstructure:"token_validate" jsonschema:"description=JWT token validation endpoint path.,default=/v1/token/validate"`
	TokenExchange  string `mapstructure:"token_exchange" jsonschema:"description=Token exchange endpoint path (RFC 8693).,default=/v1/token/exchange"`
	// Egress proxy endpoint prefix
	Egress string `mapstructure:"egress" jsonschema:"description=Egress proxy endpoint prefix. Requests to this prefix are forwarded to external targets.,default=/egress"`
	// Health endpoints
	Health string `mapstructure:"health" jsonschema:"description=Health check endpoint path.,default=/health"`
	Ready  string `mapstructure:"ready" jsonschema:"description=Readiness probe endpoint path (Kubernetes).,default=/ready"`
	Live   string `mapstructure:"live" jsonschema:"description=Liveness probe endpoint path (Kubernetes).,default=/live"`
	// Metrics endpoint
	Metrics string `mapstructure:"metrics" jsonschema:"description=Prometheus metrics endpoint path.,default=/metrics"`
	// Admin endpoints
	CacheInvalidate string `mapstructure:"cache_invalidate" jsonschema:"description=Cache invalidation admin endpoint.,default=/admin/cache/invalidate"`
	PolicyReload    string `mapstructure:"policy_reload" jsonschema:"description=Policy reload admin endpoint.,default=/admin/policy/reload"`
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	HTTP HTTPServerConfig `mapstructure:"http" jsonschema:"description=HTTP server configuration."`
	GRPC GRPCServerConfig `mapstructure:"grpc" jsonschema:"description=gRPC server configuration."`
}

// HTTPServerConfig holds HTTP server settings.
type HTTPServerConfig struct {
	Enabled         bool          `mapstructure:"enabled" jsonschema:"description=Enable HTTP server.,default=true"`
	Addr            string        `mapstructure:"addr" jsonschema:"description=HTTP server listen address.,default=:8080,example=:8080,example=0.0.0.0:8080"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout" jsonschema:"description=Maximum duration for reading entire request.,default=10s"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout" jsonschema:"description=Maximum duration for writing response.,default=10s"`
	IdleTimeout     time.Duration `mapstructure:"idle_timeout" jsonschema:"description=Maximum duration for idle connections.,default=120s"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout" jsonschema:"description=Maximum duration for graceful shutdown.,default=30s"`
	MaxHeaderBytes  int           `mapstructure:"max_header_bytes" jsonschema:"description=Maximum size of request headers in bytes.,default=1048576"`
}

// GRPCServerConfig holds gRPC server settings.
type GRPCServerConfig struct {
	Enabled        bool            `mapstructure:"enabled" jsonschema:"description=Enable gRPC server.,default=false"`
	Addr           string          `mapstructure:"addr" jsonschema:"description=gRPC server listen address.,default=:9090"`
	MaxRecvMsgSize int             `mapstructure:"max_recv_msg_size" jsonschema:"description=Maximum size of received messages in bytes.,default=4194304"`
	MaxSendMsgSize int             `mapstructure:"max_send_msg_size" jsonschema:"description=Maximum size of sent messages in bytes.,default=4194304"`
	Keepalive      KeepaliveConfig `mapstructure:"keepalive" jsonschema:"description=gRPC keepalive configuration."`
}

// KeepaliveConfig holds gRPC keepalive settings.
type KeepaliveConfig struct {
	Time    time.Duration `mapstructure:"time" jsonschema:"description=Interval for keepalive pings.,default=30s"`
	Timeout time.Duration `mapstructure:"timeout" jsonschema:"description=Timeout for keepalive ping response.,default=10s"`
}

// JWTConfig holds JWT validation configuration.
type JWTConfig struct {
	Issuers    []IssuerConfig   `mapstructure:"issuers" jsonschema:"description=List of trusted JWT issuers. At least one issuer must be configured.,required"`
	JWKSCache  JWKSCacheConfig  `mapstructure:"jwks_cache" jsonschema:"description=JWKS (JSON Web Key Set) caching configuration."`
	Validation ValidationConfig `mapstructure:"validation" jsonschema:"description=Token validation settings."`
}

// IssuerConfig holds configuration for a trusted issuer.
type IssuerConfig struct {
	Name       string   `mapstructure:"name" jsonschema:"description=Friendly name for this issuer (used in logs and metrics)."`
	IssuerURL  string   `mapstructure:"issuer_url" jsonschema:"description=Expected 'iss' claim value. Must match exactly. Example: 'https://keycloak.example.com/realms/app'.,required"`
	JWKSURL    string   `mapstructure:"jwks_url" jsonschema:"description=URL to fetch JWKS (public keys) for signature verification. Usually: {issuer_url}/.well-known/jwks.json or {issuer_url}/protocol/openid-connect/certs.,required"`
	Audience   []string `mapstructure:"audience" jsonschema:"description=Expected 'aud' claim values. At least one must match if specified."`
	Algorithms []string `mapstructure:"algorithms" jsonschema:"description=Allowed signing algorithms. Restricts which algorithms are accepted.,example=RS256,example=ES256"`
}

// JWKSCacheConfig holds JWKS caching configuration.
type JWKSCacheConfig struct {
	RefreshInterval    time.Duration `mapstructure:"refresh_interval" jsonschema:"description=Interval for background JWKS refresh.,default=1h"`
	RefreshTimeout     time.Duration `mapstructure:"refresh_timeout" jsonschema:"description=Timeout for JWKS fetch requests.,default=10s"`
	MinRefreshInterval time.Duration `mapstructure:"min_refresh_interval" jsonschema:"description=Minimum interval between JWKS refreshes (rate limiting).,default=5m"`
}

// ValidationConfig holds token validation settings.
type ValidationConfig struct {
	ClockSkew         time.Duration `mapstructure:"clock_skew" jsonschema:"description=Allowed clock skew for exp/nbf/iat validation. Compensates for server time differences.,default=30s"`
	RequireExpiration bool          `mapstructure:"require_expiration" jsonschema:"description=Require 'exp' claim in tokens. Recommended for security.,default=true"`
	RequireNotBefore  bool          `mapstructure:"require_not_before" jsonschema:"description=Require 'nbf' claim in tokens.,default=false"`
}

// TokenExchangeConfig holds token exchange configuration.
type TokenExchangeConfig struct {
	Enabled      bool          `mapstructure:"enabled" jsonschema:"description=Enable OAuth2 Token Exchange (RFC 8693).,default=false"`
	TokenURL     string        `mapstructure:"token_url" jsonschema:"description=Token endpoint URL for exchange requests."`
	ClientID     string        `mapstructure:"client_id" jsonschema:"description=OAuth2 client ID for token exchange."`
	ClientSecret string        `mapstructure:"client_secret" jsonschema:"description=OAuth2 client secret. Consider using environment variable."`
	Timeout      time.Duration `mapstructure:"timeout" jsonschema:"description=Timeout for token exchange requests.,default=10s"`
}

// PolicyConfig holds policy engine configuration.
type PolicyConfig struct {
	Engine      string              `mapstructure:"engine" jsonschema:"description=Policy engine type.,enum=builtin,enum=opa_sidecar,enum=opa_embedded,default=builtin"`
	OPA         OPAConfig           `mapstructure:"opa" jsonschema:"description=OPA sidecar configuration (when engine=opa_sidecar)."`
	OPAEmbedded OPAEmbeddedConfig   `mapstructure:"opa_embedded" jsonschema:"description=Embedded OPA configuration (when engine=opa_embedded)."`
	Builtin     BuiltinPolicyConfig `mapstructure:"builtin" jsonschema:"description=Builtin YAML rules engine configuration (when engine=builtin)."`
	Fallback    FallbackConfig      `mapstructure:"fallback" jsonschema:"description=Fallback policy configuration when primary engine fails."`
}

// OPAConfig holds OPA HTTP client configuration.
type OPAConfig struct {
	URL        string        `mapstructure:"url" jsonschema:"description=OPA server URL.,default=http://localhost:8181"`
	PolicyPath string        `mapstructure:"policy_path" jsonschema:"description=OPA policy decision path.,default=/v1/data/authz/allow"`
	Timeout    time.Duration `mapstructure:"timeout" jsonschema:"description=Request timeout for OPA queries.,default=10ms"`
	Retry      RetryConfig   `mapstructure:"retry" jsonschema:"description=Retry configuration for OPA requests."`
	TLS        OPATLSConfig  `mapstructure:"tls" jsonschema:"description=TLS configuration for OPA connection."`
}

// OPATLSConfig holds TLS settings for OPA connection.
type OPATLSConfig struct {
	Enabled            bool   `mapstructure:"enabled" jsonschema:"description=Enable TLS for OPA connection.,default=false"`
	CACert             string `mapstructure:"ca_cert" jsonschema:"description=Path to CA certificate file for OPA server verification."`
	ClientCert         string `mapstructure:"client_cert" jsonschema:"description=Path to client certificate file for mTLS."`
	ClientKey          string `mapstructure:"client_key" jsonschema:"description=Path to client key file for mTLS."`
	InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify" jsonschema:"description=Skip TLS certificate verification (INSECURE - use only for testing).,default=false"`
	ServerName         string `mapstructure:"server_name" jsonschema:"description=Expected server name in OPA certificate for SNI verification."`
}

// RetryConfig holds retry settings.
type RetryConfig struct {
	MaxAttempts    int           `mapstructure:"max_attempts" jsonschema:"description=Maximum retry attempts.,default=3"`
	InitialBackoff time.Duration `mapstructure:"initial_backoff" jsonschema:"description=Initial backoff delay.,default=1ms"`
	MaxBackoff     time.Duration `mapstructure:"max_backoff" jsonschema:"description=Maximum backoff delay.,default=10ms"`
}

// OPAEmbeddedConfig holds embedded OPA configuration.
type OPAEmbeddedConfig struct {
	// BundlePath is the path to OPA bundle (tar.gz)
	BundlePath string `mapstructure:"bundle_path" jsonschema:"description=Path to OPA bundle file (tar.gz). Alternative to policy_dir."`
	// PolicyDir is the directory containing Rego policy files
	PolicyDir string `mapstructure:"policy_dir" jsonschema:"description=Directory containing Rego policy files (.rego).,default=/etc/authz/policies"`
	// DataDir is the directory containing JSON data files
	DataDir string `mapstructure:"data_dir" jsonschema:"description=Directory containing JSON data files for OPA.,default=/etc/authz/data"`
	// DecisionPath is the Rego decision path
	DecisionPath string `mapstructure:"decision_path" jsonschema:"description=Rego package path for authorization decision. Example: 'authz.allow' evaluates data.authz.allow.,default=authz.allow"`
	// HotReload enables automatic policy reload
	HotReload bool `mapstructure:"hot_reload" jsonschema:"description=Enable automatic policy reload on file changes.,default=true"`
}

// OPASidecarConfig is an alias for OPAConfig for clarity.
type OPASidecarConfig = OPAConfig

// BuiltinPolicyConfig holds built-in policy configuration.
type BuiltinPolicyConfig struct {
	RulesPath string `mapstructure:"rules_path" jsonschema:"description=Path to YAML rules file for builtin engine.,default=/etc/authz/rules.yaml"`
}

// FallbackConfig holds fallback policy configuration.
type FallbackConfig struct {
	Enabled  bool   `mapstructure:"enabled" jsonschema:"description=Enable fallback policy when primary engine fails.,default=true"`
	Engine   string `mapstructure:"engine" jsonschema:"description=Fallback policy engine.,enum=builtin,enum=opa_embedded,default=builtin"`
	Behavior string `mapstructure:"behavior" jsonschema:"description=Default decision when fallback is used.,enum=deny,enum=allow,default=deny"`
}

// CacheConfig holds caching configuration.
type CacheConfig struct {
	L1 L1CacheConfig `mapstructure:"l1" jsonschema:"description=L1 (in-memory) cache for lowest latency."`
	L2 L2CacheConfig `mapstructure:"l2" jsonschema:"description=L2 (distributed) cache for shared caching across instances."`
}

// L1CacheConfig holds in-memory cache configuration.
type L1CacheConfig struct {
	Enabled bool          `mapstructure:"enabled" jsonschema:"description=Enable in-memory L1 cache.,default=true"`
	MaxSize int           `mapstructure:"max_size" jsonschema:"description=Maximum number of entries in L1 cache.,default=10000"`
	TTL     time.Duration `mapstructure:"ttl" jsonschema:"description=Time-to-live for L1 cache entries.,default=10s"`
}

// L2CacheConfig holds distributed cache configuration.
type L2CacheConfig struct {
	Enabled   bool             `mapstructure:"enabled" jsonschema:"description=Enable distributed L2 cache (Redis).,default=false"`
	Backend   string           `mapstructure:"backend" jsonschema:"description=L2 cache backend type.,enum=redis,default=redis"`
	Redis     RedisCacheConfig `mapstructure:"redis" jsonschema:"description=Redis configuration for L2 cache."`
	TTL       CacheTTLConfig   `mapstructure:"ttl" jsonschema:"description=TTL settings for different cache entry types."`
	KeyPrefix string           `mapstructure:"key_prefix" jsonschema:"description=Prefix for all cache keys in Redis.,default=authz:"`
}

// RedisCacheConfig holds Redis configuration.
type RedisCacheConfig struct {
	Addresses    []string      `mapstructure:"addresses" jsonschema:"description=Redis server addresses. Multiple for cluster mode.,example=localhost:6379"`
	Password     string        `mapstructure:"password" jsonschema:"description=Redis password. Consider using environment variable."`
	DB           int           `mapstructure:"db" jsonschema:"description=Redis database number.,default=0"`
	PoolSize     int           `mapstructure:"pool_size" jsonschema:"description=Connection pool size per address.,default=10"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout" jsonschema:"description=Timeout for read operations.,default=3s"`
	WriteTimeout time.Duration `mapstructure:"write_timeout" jsonschema:"description=Timeout for write operations.,default=3s"`
}

// CacheTTLConfig holds TTL settings for different cache types.
type CacheTTLConfig struct {
	Authorization time.Duration `mapstructure:"authorization" jsonschema:"description=TTL for authorization decision cache.,default=60s"`
	JWT           time.Duration `mapstructure:"jwt" jsonschema:"description=TTL for validated JWT token cache.,default=300s"`
	JWKS          time.Duration `mapstructure:"jwks" jsonschema:"description=TTL for JWKS (public keys) cache.,default=3600s"`
}

// AuditConfig holds audit logging configuration.
type AuditConfig struct {
	Enabled    bool         `mapstructure:"enabled" jsonschema:"description=Enable audit logging for authorization decisions.,default=true"`
	Events     []string     `mapstructure:"events" jsonschema:"description=Event types to audit.,example=AUTHZ_DECISION,example=TOKEN_VALIDATED,default=[AUTHZ_DECISION]"`
	Export     ExportConfig `mapstructure:"export" jsonschema:"description=Audit log export configuration."`
	Enrichment EnrichConfig `mapstructure:"enrichment" jsonschema:"description=Audit log enrichment settings."`
}

// ExportConfig holds audit export configuration.
type ExportConfig struct {
	OTLP   OTLPExportConfig   `mapstructure:"otlp" jsonschema:"description=OpenTelemetry (OTLP) export configuration."`
	Stdout StdoutExportConfig `mapstructure:"stdout" jsonschema:"description=Stdout export configuration for local debugging."`
}

// OTLPExportConfig holds OTLP export configuration.
type OTLPExportConfig struct {
	Enabled  bool   `mapstructure:"enabled" jsonschema:"description=Enable OTLP export to collectors like Jaeger\\, Tempo.,default=false"`
	Endpoint string `mapstructure:"endpoint" jsonschema:"description=OTLP collector endpoint URL.,example=localhost:4317"`
	Insecure bool   `mapstructure:"insecure" jsonschema:"description=Use insecure (non-TLS) connection to collector.,default=false"`
}

// StdoutExportConfig holds stdout export configuration.
type StdoutExportConfig struct {
	Enabled bool   `mapstructure:"enabled" jsonschema:"description=Enable audit log output to stdout.,default=true"`
	Format  string `mapstructure:"format" jsonschema:"description=Output format for stdout audit logs.,enum=json,enum=text,default=json"`
}

// EnrichConfig holds audit enrichment configuration.
type EnrichConfig struct {
	IncludeHeaders []string `mapstructure:"include_headers" jsonschema:"description=Request headers to include in audit logs.,example=X-Request-ID,example=X-Correlation-ID"`
	MaskFields     []string `mapstructure:"mask_fields" jsonschema:"description=Fields to mask in audit logs (for PII/sensitive data).,example=password,example=token"`
}

// HealthConfig holds health check configuration.
type HealthConfig struct {
	CheckInterval time.Duration `mapstructure:"check_interval" jsonschema:"description=Interval between health checks.,default=10s"`
	Timeout       time.Duration `mapstructure:"timeout" jsonschema:"description=Timeout for individual health checks.,default=5s"`
	Checks        []CheckConfig `mapstructure:"checks" jsonschema:"description=Individual health check configurations."`
}

// CheckConfig holds individual health check configuration.
type CheckConfig struct {
	Name     string `mapstructure:"name" jsonschema:"description=Health check name (e.g. 'redis'\\, 'opa')."`
	Enabled  bool   `mapstructure:"enabled" jsonschema:"description=Enable this health check.,default=true"`
	Critical bool   `mapstructure:"critical" jsonschema:"description=If true\\, failure marks service as unhealthy.,default=false"`
}

// =============================================================================
// Resilience Configuration (Rate Limiting & Circuit Breaker)
// =============================================================================

// ResilienceConfig holds resilience patterns configuration.
type ResilienceConfig struct {
	// RateLimit configuration for incoming requests
	RateLimit RateLimitConfig `mapstructure:"rate_limit" jsonschema:"description=Rate limiting configuration for incoming HTTP requests. Protects service from overload."`
	// CircuitBreaker configuration for external calls
	CircuitBreaker CircuitBreakerConfig `mapstructure:"circuit_breaker" jsonschema:"description=Circuit breaker configuration for external service calls. Prevents cascade failures."`
}

// RateLimitConfig holds rate limiting configuration.
type RateLimitConfig struct {
	// Enabled enables rate limiting
	Enabled bool `mapstructure:"enabled" jsonschema:"description=Enable rate limiting for incoming requests.,default=true"`
	// Rate is the rate limit in format 'requests-period' (e.g. '100-S' for 100 requests per second)
	Rate string `mapstructure:"rate" jsonschema:"description=Rate limit in format 'requests-period'. Periods: S (second)\\, M (minute)\\, H (hour)\\, D (day). Example: '100-S' = 100 req/sec\\, '1000-M' = 1000 req/min.,default=100-S"`
	// Store is the rate limit store type
	Store string `mapstructure:"store" jsonschema:"description=Rate limit storage backend.,enum=memory,enum=redis,default=memory"`
	// Redis configuration for distributed rate limiting
	Redis RateLimitRedisConfig `mapstructure:"redis" jsonschema:"description=Redis configuration for distributed rate limiting (when store=redis)."`
	// TrustForwardedFor trusts X-Forwarded-For header for client IP
	TrustForwardedFor bool `mapstructure:"trust_forwarded_for" jsonschema:"description=Trust X-Forwarded-For header for client IP identification. Enable when behind proxy/load balancer.,default=true"`
	// ExcludePaths excludes paths from rate limiting
	ExcludePaths []string `mapstructure:"exclude_paths" jsonschema:"description=Paths to exclude from rate limiting. Supports glob patterns.,example=/health,example=/metrics,example=/ready"`
	// ByEndpoint enables per-endpoint rate limiting
	ByEndpoint bool `mapstructure:"by_endpoint" jsonschema:"description=Apply rate limits per endpoint instead of globally.,default=false"`
	// EndpointRates defines per-endpoint rate limits
	EndpointRates map[string]string `mapstructure:"endpoint_rates" jsonschema:"description=Per-endpoint rate limits. Key is path prefix\\, value is rate. Example: {'/v1/authorize': '1000-S'\\, '/v1/token': '100-S'}."`
	// Headers configuration for rate limit response headers
	Headers RateLimitHeadersConfig `mapstructure:"headers" jsonschema:"description=Rate limit response headers configuration."`
	// FailClose denies requests when rate limiter encounters an error (secure default)
	// When true (default): errors result in request denial (fail-close, secure)
	// When false: errors allow requests through (fail-open, less secure but more available)
	FailClose bool `mapstructure:"fail_close" jsonschema:"description=Deny requests when rate limiter encounters an error. True = fail-close (secure)\\, False = fail-open (available). Recommended: true for authorization services.,default=true"`
}

// RateLimitRedisConfig holds Redis configuration for rate limiting.
type RateLimitRedisConfig struct {
	// Address is Redis server address
	Address string `mapstructure:"address" jsonschema:"description=Redis server address.,example=localhost:6379"`
	// Password is Redis password
	Password string `mapstructure:"password" jsonschema:"description=Redis password. Consider using environment variable AUTHZ_RESILIENCE_RATE_LIMIT_REDIS_PASSWORD."`
	// DB is Redis database number
	DB int `mapstructure:"db" jsonschema:"description=Redis database number.,default=1"`
	// KeyPrefix is the prefix for rate limit keys
	KeyPrefix string `mapstructure:"key_prefix" jsonschema:"description=Prefix for rate limit keys in Redis.,default=authz:ratelimit:"`
}

// RateLimitHeadersConfig holds rate limit headers configuration.
type RateLimitHeadersConfig struct {
	// Enabled enables rate limit headers in response
	Enabled bool `mapstructure:"enabled" jsonschema:"description=Include rate limit headers in HTTP response (X-RateLimit-*).,default=true"`
	// LimitHeader is the header name for rate limit
	LimitHeader string `mapstructure:"limit_header" jsonschema:"description=Header name for rate limit value.,default=X-RateLimit-Limit"`
	// RemainingHeader is the header name for remaining requests
	RemainingHeader string `mapstructure:"remaining_header" jsonschema:"description=Header name for remaining requests.,default=X-RateLimit-Remaining"`
	// ResetHeader is the header name for reset timestamp
	ResetHeader string `mapstructure:"reset_header" jsonschema:"description=Header name for reset timestamp.,default=X-RateLimit-Reset"`
}

// CircuitBreakerConfig holds circuit breaker configuration.
type CircuitBreakerConfig struct {
	// Enabled enables circuit breaker
	Enabled bool `mapstructure:"enabled" jsonschema:"description=Enable circuit breaker for external service calls.,default=true"`
	// Default settings for all circuit breakers
	Default CircuitBreakerSettings `mapstructure:"default" jsonschema:"description=Default circuit breaker settings applied to all external calls."`
	// Services holds per-service circuit breaker settings
	Services map[string]CircuitBreakerSettings `mapstructure:"services" jsonschema:"description=Per-service circuit breaker settings. Key is service name (e.g. 'opa'\\, 'keycloak')."`
}

// CircuitBreakerSettings holds settings for a single circuit breaker.
type CircuitBreakerSettings struct {
	// MaxRequests is the maximum number of requests in half-open state
	MaxRequests uint32 `mapstructure:"max_requests" jsonschema:"description=Maximum requests allowed in half-open state before deciding to close or open.,default=3,minimum=1"`
	// Interval is the cyclic period for clearing counts in closed state
	Interval time.Duration `mapstructure:"interval" jsonschema:"description=Cyclic period for clearing failure counts when circuit is closed.,default=60s"`
	// Timeout is the period of open state before switching to half-open
	Timeout time.Duration `mapstructure:"timeout" jsonschema:"description=Duration of open state before switching to half-open.,default=30s"`
	// FailureThreshold is the number of consecutive failures to open circuit
	FailureThreshold uint32 `mapstructure:"failure_threshold" jsonschema:"description=Number of consecutive failures before opening circuit.,default=5,minimum=1"`
	// SuccessThreshold is the number of consecutive successes to close circuit
	SuccessThreshold uint32 `mapstructure:"success_threshold" jsonschema:"description=Number of consecutive successes in half-open state to close circuit.,default=2,minimum=1"`
	// OnStateChange enables logging on state changes
	OnStateChange bool `mapstructure:"on_state_change" jsonschema:"description=Log circuit breaker state changes.,default=true"`
}

// =============================================================================
// Sensitive Data Masking Configuration
// =============================================================================

// SensitiveDataConfig holds sensitive data handling configuration.
type SensitiveDataConfig struct {
	// Enabled enables sensitive data masking in logs
	Enabled bool `mapstructure:"enabled" jsonschema:"description=Enable automatic masking of sensitive data in logs.,default=true"`
	// MaskValue is the replacement value for masked data
	MaskValue string `mapstructure:"mask_value" jsonschema:"description=Value to replace sensitive data with.,default=***MASKED***"`
	// Fields are field names to mask (case-insensitive)
	Fields []string `mapstructure:"fields" jsonschema:"description=Field names to mask in logs (case-insensitive). Applied to JSON keys and struct fields.,default=[password\\,secret\\,token\\,api_key\\,apikey\\,authorization\\,client_secret\\,access_token\\,refresh_token\\,private_key\\,credential]"`
	// Headers are HTTP header names to mask
	Headers []string `mapstructure:"headers" jsonschema:"description=HTTP header names to mask in logs (case-insensitive).,default=[Authorization\\,X-API-Key\\,Cookie\\,Set-Cookie]"`
	// MaskJWT masks JWT token payload (keeps header visible)
	MaskJWT bool `mapstructure:"mask_jwt" jsonschema:"description=Mask JWT token payload in logs (keeps header and signature indicator visible).,default=true"`
	// PartialMask enables partial masking (show first/last N chars)
	PartialMask PartialMaskConfig `mapstructure:"partial_mask" jsonschema:"description=Partial masking configuration to show parts of sensitive values."`
}

// PartialMaskConfig holds partial masking configuration.
type PartialMaskConfig struct {
	// Enabled enables partial masking
	Enabled bool `mapstructure:"enabled" jsonschema:"description=Enable partial masking (show first/last characters).,default=false"`
	// ShowFirst is the number of first characters to show
	ShowFirst int `mapstructure:"show_first" jsonschema:"description=Number of first characters to show.,default=4"`
	// ShowLast is the number of last characters to show
	ShowLast int `mapstructure:"show_last" jsonschema:"description=Number of last characters to show.,default=4"`
	// MinLength is the minimum value length to apply partial masking
	MinLength int `mapstructure:"min_length" jsonschema:"description=Minimum value length for partial masking. Shorter values are fully masked.,default=12"`
}

// EnvConfig holds environment information for context-aware authorization.
// This data is available in CEL expressions via the 'env' variable.
type EnvConfig struct {
	// Name is the environment name (e.g., "production", "staging", "development")
	Name string `mapstructure:"name" jsonschema:"description=Environment name (e.g. production\\, staging\\, development). Available in CEL as env.name.,default=development"`
	// Region is the deployment region (e.g., "eu-west-1", "us-east-1")
	Region string `mapstructure:"region" jsonschema:"description=Deployment region (e.g. eu-west-1\\, us-east-1). Available in CEL as env.region."`
	// Cluster is the cluster identifier (e.g., "k8s-prod-01", "ecs-staging")
	Cluster string `mapstructure:"cluster" jsonschema:"description=Cluster identifier (e.g. k8s-prod-01). Available in CEL as env.cluster."`
	// Version is the service version (e.g., "2.1.0", "v1.2.3-beta")
	Version string `mapstructure:"version" jsonschema:"description=Service version (e.g. 2.1.0). Available in CEL as env.version."`
	// Features contains feature flags for gradual rollouts
	Features map[string]bool `mapstructure:"features" jsonschema:"description=Feature flags for gradual rollouts. Available in CEL as env.features['flag_name']."`
	// Custom contains any additional environment-specific attributes
	Custom map[string]any `mapstructure:"custom" jsonschema:"description=Custom environment attributes. Available in CEL as env.custom['key']."`
}

// =============================================================================
// TLS Client Certificate Configuration (mTLS/SPIFFE)
// =============================================================================

// TLSClientCertConfig holds configuration for extracting client certificate information.
// This enables authorization based on mTLS identity and SPIFFE IDs.
type TLSClientCertConfig struct {
	// Enabled enables client certificate extraction
	Enabled bool `mapstructure:"enabled" jsonschema:"description=Enable client certificate extraction for mTLS/SPIFFE identity. When enabled\\, certificate info is available in CEL as 'tls' variable.,default=false"`
	// Sources configures where to extract certificate information from
	Sources TLSSourcesConfig `mapstructure:"sources" jsonschema:"description=Certificate information sources. Multiple sources can be enabled and will be used in cascade (XFCC first\\, then headers)."`
	// TrustedSPIFFEDomains is a list of trusted SPIFFE trust domains
	TrustedSPIFFEDomains []string `mapstructure:"trusted_spiffe_domains" jsonschema:"description=List of trusted SPIFFE trust domains. If specified\\, only certificates with matching trust domains are accepted.,example=cluster.local,example=prod.example.com"`
	// TrustedProxyCIDRs is a list of trusted proxy CIDRs for XFCC header
	TrustedProxyCIDRs []string `mapstructure:"trusted_proxy_cidrs" jsonschema:"description=CIDR ranges of trusted proxies for XFCC header. Only accept XFCC from these sources to prevent header injection.,example=10.0.0.0/8,example=172.16.0.0/12"`
	// RequireVerified requires client certificate to be verified
	RequireVerified bool `mapstructure:"require_verified" jsonschema:"description=Require client certificate to be verified. When true\\, requests without verified certificates are rejected.,default=false"`
}

// TLSSourcesConfig holds configuration for certificate extraction sources.
type TLSSourcesConfig struct {
	// XFCC configures X-Forwarded-Client-Cert header parsing (Envoy/Istio standard)
	XFCC XFCCSourceConfig `mapstructure:"xfcc" jsonschema:"description=X-Forwarded-Client-Cert (XFCC) header configuration. This is the standard header used by Envoy/Istio for passing client certificate information."`
	// Headers configures individual header extraction (Nginx/HAProxy style)
	Headers HeadersSourceConfig `mapstructure:"headers" jsonschema:"description=Individual headers configuration for extracting certificate fields. Used by Nginx\\, HAProxy\\, and other reverse proxies."`
}

// XFCCSourceConfig holds X-Forwarded-Client-Cert header configuration.
type XFCCSourceConfig struct {
	// Enabled enables XFCC header parsing
	Enabled bool `mapstructure:"enabled" jsonschema:"description=Enable XFCC header parsing. This is the primary source when using Envoy/Istio.,default=true"`
	// Header is the XFCC header name
	Header string `mapstructure:"header" jsonschema:"description=XFCC header name.,default=X-Forwarded-Client-Cert"`
}

// HeadersSourceConfig holds individual headers configuration for certificate extraction.
type HeadersSourceConfig struct {
	// Enabled enables individual headers extraction
	Enabled bool `mapstructure:"enabled" jsonschema:"description=Enable individual header extraction. Used as fallback when XFCC is not available.,default=false"`
	// Subject is the header name for subject DN
	Subject string `mapstructure:"subject" jsonschema:"description=Header name for certificate subject DN.,default=X-SSL-Client-S-DN"`
	// Issuer is the header name for issuer DN
	Issuer string `mapstructure:"issuer" jsonschema:"description=Header name for certificate issuer DN.,default=X-SSL-Client-I-DN"`
	// CommonName is the header name for common name
	CommonName string `mapstructure:"common_name" jsonschema:"description=Header name for certificate common name (CN).,default=X-SSL-Client-CN"`
	// Serial is the header name for serial number
	Serial string `mapstructure:"serial" jsonschema:"description=Header name for certificate serial number.,default=X-SSL-Client-Serial"`
	// Verified is the header name for verification status
	Verified string `mapstructure:"verified" jsonschema:"description=Header name for certificate verification status.,default=X-SSL-Client-Verify"`
	// VerifiedValue is the value indicating successful verification
	VerifiedValue string `mapstructure:"verified_value" jsonschema:"description=Value in verified header that indicates successful verification.,default=SUCCESS"`
	// Fingerprint is the header name for certificate fingerprint
	Fingerprint string `mapstructure:"fingerprint" jsonschema:"description=Header name for certificate SHA256 fingerprint.,default=X-SSL-Client-Fingerprint"`
	// DNSNames is the header name for SAN DNS names
	DNSNames string `mapstructure:"dns_names" jsonschema:"description=Header name for SAN DNS names (comma-separated).,default=X-SSL-Client-DNS"`
	// URI is the header name for SAN URIs (including SPIFFE)
	URI string `mapstructure:"uri" jsonschema:"description=Header name for SAN URIs including SPIFFE IDs (comma-separated).,default=X-SSL-Client-URI"`
	// NotBefore is the header name for certificate not before timestamp
	NotBefore string `mapstructure:"not_before" jsonschema:"description=Header name for certificate not before timestamp.,default=X-SSL-Client-Not-Before"`
	// NotAfter is the header name for certificate not after timestamp
	NotAfter string `mapstructure:"not_after" jsonschema:"description=Header name for certificate not after timestamp.,default=X-SSL-Client-Not-After"`
}

// =============================================================================
// Request Body Configuration
// =============================================================================

// RequestBodyConfig holds configuration for request body access in authorization rules.
// WARNING: Enabling request body access has security and performance implications:
// - Memory: Body is buffered in memory (up to MaxSize)
// - Performance: Body must be read before forwarding to upstream
// - Security: Potential for DoS if MaxSize is too large
type RequestBodyConfig struct {
	// Enabled enables request body access in CEL expressions.
	// This is a potentially dangerous feature and should only be enabled when necessary.
	Enabled bool `mapstructure:"enabled" jsonschema:"description=Enable request body access in CEL expressions. WARNING: This feature has security and performance implications. Body is buffered in memory and requires JSON validation.,default=false"`
	// MaxSize is the maximum body size to read (in bytes).
	// Bodies larger than this will be rejected.
	MaxSize int64 `mapstructure:"max_size" jsonschema:"description=Maximum request body size in bytes. Bodies larger than this will be rejected with 413 Payload Too Large.,default=1048576,minimum=1024,maximum=10485760"`
	// AllowedContentTypes restricts which content types can have body access.
	// Empty means only application/json is allowed.
	AllowedContentTypes []string `mapstructure:"allowed_content_types" jsonschema:"description=Content types allowed for body access. Empty defaults to application/json only.,example=application/json"`
	// RequireContentType requires Content-Type header to be present.
	RequireContentType bool `mapstructure:"require_content_type" jsonschema:"description=Require Content-Type header for body parsing. When true\\, requests without Content-Type are rejected.,default=true"`
	// Schema validation configuration
	Schema RequestBodySchemaConfig `mapstructure:"schema" jsonschema:"description=JSON Schema validation configuration for request bodies."`
	// Methods restricts body access to specific HTTP methods.
	// Empty means POST, PUT, PATCH only (methods that typically have body).
	Methods []string `mapstructure:"methods" jsonschema:"description=HTTP methods for which body access is enabled. Empty defaults to POST\\, PUT\\, PATCH.,example=POST,example=PUT,example=PATCH"`
	// Paths restricts body access to specific path patterns (glob).
	// Empty means all paths.
	Paths []string `mapstructure:"paths" jsonschema:"description=Path patterns (glob) for which body access is enabled. Empty means all paths.,example=/api/v1/**"`
}

// RequestBodySchemaConfig holds JSON Schema validation configuration.
type RequestBodySchemaConfig struct {
	// Enabled enables JSON Schema validation.
	Enabled bool `mapstructure:"enabled" jsonschema:"description=Enable JSON Schema validation for request bodies.,default=false"`
	// SchemaDir is the directory containing JSON Schema files.
	// Schemas are loaded by path: /api/v1/users -> schemas/api/v1/users.json
	SchemaDir string `mapstructure:"schema_dir" jsonschema:"description=Directory containing JSON Schema files. Schema lookup: path + method -> {schema_dir}/{path}/{method}.json,default=/etc/authz/schemas"`
	// StrictValidation fails requests that don't have a matching schema.
	StrictValidation bool `mapstructure:"strict_validation" jsonschema:"description=Fail requests without matching schema. When false\\, requests without schema pass validation.,default=false"`
	// AllowAdditionalProperties allows properties not defined in schema.
	AllowAdditionalProperties bool `mapstructure:"allow_additional_properties" jsonschema:"description=Allow properties not defined in schema. Maps to JSON Schema additionalProperties.,default=true"`
}

// =============================================================================
// Tracing Configuration (OpenTelemetry)
// =============================================================================

// TracingConfig holds OpenTelemetry distributed tracing configuration.
type TracingConfig struct {
	// Enabled enables distributed tracing
	Enabled bool `mapstructure:"enabled" jsonschema:"description=Enable OpenTelemetry distributed tracing.,default=false"`
	// Endpoint is the OTLP collector endpoint (e.g., localhost:4317)
	Endpoint string `mapstructure:"endpoint" jsonschema:"description=OTLP gRPC collector endpoint (e.g. Jaeger\\, Tempo\\, Zipkin with OTLP).,example=localhost:4317,example=tempo:4317"`
	// Insecure disables TLS for collector connection
	Insecure bool `mapstructure:"insecure" jsonschema:"description=Use insecure (non-TLS) connection to collector. Set to false in production.,default=true"`
	// ServiceName is the service name in traces
	ServiceName string `mapstructure:"service_name" jsonschema:"description=Service name for traces.,default=authz-service"`
	// ServiceVersion is the service version in traces
	ServiceVersion string `mapstructure:"service_version" jsonschema:"description=Service version for traces. If empty\\, uses build version."`
	// Environment is the deployment environment
	Environment string `mapstructure:"environment" jsonschema:"description=Deployment environment (e.g. production\\, staging).,default=development"`
	// SampleRate is the trace sampling rate (0.0-1.0)
	SampleRate float64 `mapstructure:"sample_rate" jsonschema:"description=Trace sampling rate (0.0=none\\, 1.0=all). Use lower values in production for high-traffic services.,default=1.0,minimum=0.0,maximum=1.0"`
	// BatchTimeout is the maximum time before exporting a batch
	BatchTimeout string `mapstructure:"batch_timeout" jsonschema:"description=Maximum time before exporting a trace batch.,default=5s"`
	// ExportTimeout is the timeout for export operations
	ExportTimeout string `mapstructure:"export_timeout" jsonschema:"description=Timeout for trace export operations.,default=30s"`
	// PropagateHeaders propagates trace context to upstream services
	PropagateHeaders bool `mapstructure:"propagate_headers" jsonschema:"description=Propagate W3C trace context headers to upstream services.,default=true"`
}
