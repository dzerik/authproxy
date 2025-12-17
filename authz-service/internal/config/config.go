package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/your-org/authz-service/pkg/logger"
)

// Config holds all application configuration.
type Config struct {
	Server        ServerConfig        `mapstructure:"server"`
	Proxy         ProxyConfig         `mapstructure:"proxy"`
	Egress        EgressConfig        `mapstructure:"egress"`
	Endpoints     EndpointsConfig     `mapstructure:"endpoints"`
	JWT           JWTConfig           `mapstructure:"jwt"`
	TokenExchange TokenExchangeConfig `mapstructure:"token_exchange"`
	Policy        PolicyConfig        `mapstructure:"policy"`
	Cache         CacheConfig         `mapstructure:"cache"`
	Audit         AuditConfig         `mapstructure:"audit"`
	Logging       logger.Config       `mapstructure:"logging"`
	Health        HealthConfig        `mapstructure:"health"`
}

// ProxyConfig holds reverse proxy configuration for forwarding authorized requests.
type ProxyConfig struct {
	// Enabled enables proxy mode (forward requests after authorization)
	Enabled bool `mapstructure:"enabled"`

	// Mode: "reverse_proxy" (forward to upstream) or "decision_only" (just return decision)
	Mode string `mapstructure:"mode"`

	// Upstream is the default upstream destination
	Upstream UpstreamConfig `mapstructure:"upstream"`

	// Upstreams is a map of named upstreams for routing
	Upstreams map[string]UpstreamConfig `mapstructure:"upstreams"`

	// Routing rules for selecting upstream based on path/headers
	Routes []RouteConfig `mapstructure:"routes"`

	// Headers configuration
	Headers ProxyHeadersConfig `mapstructure:"headers"`

	// Timeouts
	Timeout        time.Duration `mapstructure:"timeout"`
	IdleConnTimeout time.Duration `mapstructure:"idle_conn_timeout"`

	// Retries
	Retry ProxyRetryConfig `mapstructure:"retry"`
}

// UpstreamConfig holds upstream server configuration.
type UpstreamConfig struct {
	// URL is the upstream base URL
	URL string `mapstructure:"url"`

	// TLS configuration
	TLS UpstreamTLSConfig `mapstructure:"tls"`

	// HealthCheck configuration
	HealthCheck UpstreamHealthConfig `mapstructure:"health_check"`
}

// UpstreamTLSConfig holds TLS settings for upstream connections.
type UpstreamTLSConfig struct {
	// Enabled enables TLS for upstream
	Enabled bool `mapstructure:"enabled"`

	// InsecureSkipVerify skips certificate verification (not recommended for production)
	InsecureSkipVerify bool `mapstructure:"insecure_skip_verify"`

	// CACert is the path to CA certificate
	CACert string `mapstructure:"ca_cert"`

	// ClientCert is the path to client certificate for mTLS
	ClientCert string `mapstructure:"client_cert"`

	// ClientKey is the path to client key for mTLS
	ClientKey string `mapstructure:"client_key"`
}

// UpstreamHealthConfig holds health check settings for upstream.
type UpstreamHealthConfig struct {
	Enabled  bool          `mapstructure:"enabled"`
	Path     string        `mapstructure:"path"`
	Interval time.Duration `mapstructure:"interval"`
	Timeout  time.Duration `mapstructure:"timeout"`
}

// RouteConfig holds routing configuration.
type RouteConfig struct {
	// Match conditions
	PathPrefix string            `mapstructure:"path_prefix"`
	PathExact  string            `mapstructure:"path_exact"`
	PathRegex  string            `mapstructure:"path_regex"`
	Methods    []string          `mapstructure:"methods"`
	Headers    map[string]string `mapstructure:"headers"`

	// Target upstream name
	Upstream string `mapstructure:"upstream"`

	// Optional: rewrite path
	RewritePrefix string `mapstructure:"rewrite_prefix"`
	StripPrefix   string `mapstructure:"strip_prefix"`
}

// ProxyHeadersConfig holds header manipulation settings.
type ProxyHeadersConfig struct {
	// Add headers to forwarded requests
	Add map[string]string `mapstructure:"add"`

	// Remove headers from forwarded requests
	Remove []string `mapstructure:"remove"`

	// Forward original headers (whitelist)
	Forward []string `mapstructure:"forward"`

	// Headers with user info to add after authorization
	AddUserInfo bool `mapstructure:"add_user_info"`

	// Custom header names for user info
	UserIDHeader    string `mapstructure:"user_id_header"`
	UserRolesHeader string `mapstructure:"user_roles_header"`
}

// ProxyRetryConfig holds retry settings for proxy.
type ProxyRetryConfig struct {
	Enabled        bool          `mapstructure:"enabled"`
	MaxAttempts    int           `mapstructure:"max_attempts"`
	InitialBackoff time.Duration `mapstructure:"initial_backoff"`
	MaxBackoff     time.Duration `mapstructure:"max_backoff"`
	RetryOn        []int         `mapstructure:"retry_on"` // HTTP status codes to retry
}

// =============================================================================
// Egress Proxy Configuration
// =============================================================================

// EgressConfig holds egress proxy configuration for outgoing requests to external systems.
type EgressConfig struct {
	// Enabled enables egress proxy mode
	Enabled bool `mapstructure:"enabled"`

	// Targets is a map of named external systems
	Targets map[string]EgressTargetConfig `mapstructure:"targets"`

	// Routes maps incoming paths to targets
	Routes []EgressRouteConfig `mapstructure:"routes"`

	// Defaults holds default settings for all targets
	Defaults EgressDefaultsConfig `mapstructure:"defaults"`

	// TokenStore configuration for caching tokens
	TokenStore EgressTokenStoreConfig `mapstructure:"token_store"`
}

// EgressTargetConfig holds configuration for an external system.
type EgressTargetConfig struct {
	// URL is the base URL of the external system
	URL string `mapstructure:"url"`

	// Timeout for requests to this target
	Timeout time.Duration `mapstructure:"timeout"`

	// Auth configuration for this target
	Auth EgressAuthConfig `mapstructure:"auth"`

	// TLS configuration for this target
	TLS EgressTLSConfig `mapstructure:"tls"`

	// Retry configuration
	Retry EgressRetryConfig `mapstructure:"retry"`
}

// EgressAuthConfig holds authentication configuration for a target.
type EgressAuthConfig struct {
	// Type: oauth2_client_credentials, oauth2_refresh_token, gcp_service_account,
	//       aws_iam, api_key, mtls, basic, bearer
	Type string `mapstructure:"type"`

	// OAuth2 Client Credentials
	TokenURL     string   `mapstructure:"token_url"`
	ClientID     string   `mapstructure:"client_id"`
	ClientSecret string   `mapstructure:"client_secret"`
	Scopes       []string `mapstructure:"scopes"`

	// OAuth2 Refresh Token
	RefreshToken string `mapstructure:"refresh_token"`

	// Refresh before expiry (default: 60s)
	RefreshBeforeExpiry time.Duration `mapstructure:"refresh_before_expiry"`

	// GCP Service Account
	CredentialsFile string `mapstructure:"credentials_file"`

	// AWS IAM
	RoleARN string `mapstructure:"role_arn"`
	Region  string `mapstructure:"region"`

	// API Key
	Header   string `mapstructure:"header"` // Header name for API key
	QueryKey string `mapstructure:"query_key"` // Query parameter name
	Key      string `mapstructure:"key"`    // The API key value

	// Basic Auth
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`

	// Bearer Token (static)
	Token string `mapstructure:"token"`

	// mTLS (uses TLS config from EgressTargetConfig.TLS)
}

// EgressTLSConfig holds TLS configuration for egress targets.
type EgressTLSConfig struct {
	// Enabled enables TLS
	Enabled bool `mapstructure:"enabled"`

	// InsecureSkipVerify skips certificate verification
	InsecureSkipVerify bool `mapstructure:"insecure_skip_verify"`

	// CACert is the path to CA certificate for server verification
	CACert string `mapstructure:"ca_cert"`

	// ClientCert is the path to client certificate for mTLS
	ClientCert string `mapstructure:"client_cert"`

	// ClientKey is the path to client key for mTLS
	ClientKey string `mapstructure:"client_key"`
}

// EgressRetryConfig holds retry configuration for egress targets.
type EgressRetryConfig struct {
	MaxAttempts    int           `mapstructure:"max_attempts"`
	InitialBackoff time.Duration `mapstructure:"initial_backoff"`
	MaxBackoff     time.Duration `mapstructure:"max_backoff"`
}

// EgressRouteConfig holds routing configuration for egress.
type EgressRouteConfig struct {
	// PathPrefix matches requests starting with this prefix
	PathPrefix string `mapstructure:"path_prefix"`

	// Target is the name of the target to route to
	Target string `mapstructure:"target"`

	// StripPrefix removes this prefix before forwarding
	StripPrefix string `mapstructure:"strip_prefix"`

	// RewritePrefix replaces the stripped prefix with this
	RewritePrefix string `mapstructure:"rewrite_prefix"`

	// Methods restricts to specific HTTP methods (empty = all)
	Methods []string `mapstructure:"methods"`
}

// EgressDefaultsConfig holds default settings for egress targets.
type EgressDefaultsConfig struct {
	Timeout time.Duration     `mapstructure:"timeout"`
	Retry   EgressRetryConfig `mapstructure:"retry"`
}

// EgressTokenStoreConfig holds token store configuration.
type EgressTokenStoreConfig struct {
	// Type: memory, redis
	Type string `mapstructure:"type"`

	// Redis configuration (if type = redis)
	Redis EgressRedisConfig `mapstructure:"redis"`
}

// EgressRedisConfig holds Redis configuration for egress token store.
type EgressRedisConfig struct {
	Address   string `mapstructure:"address"`
	Password  string `mapstructure:"password"`
	DB        int    `mapstructure:"db"`
	KeyPrefix string `mapstructure:"key_prefix"`
}

// EndpointsConfig holds configurable endpoint paths.
type EndpointsConfig struct {
	// API endpoints
	Authorize      string `mapstructure:"authorize"`
	AuthorizeBatch string `mapstructure:"authorize_batch"`
	TokenValidate  string `mapstructure:"token_validate"`
	TokenExchange  string `mapstructure:"token_exchange"`

	// Egress proxy endpoint prefix
	Egress string `mapstructure:"egress"`

	// Health endpoints
	Health string `mapstructure:"health"`
	Ready  string `mapstructure:"ready"`
	Live   string `mapstructure:"live"`

	// Metrics endpoint
	Metrics string `mapstructure:"metrics"`

	// Admin endpoints (optional)
	CacheInvalidate string `mapstructure:"cache_invalidate"`
	PolicyReload    string `mapstructure:"policy_reload"`
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	HTTP HTTPServerConfig `mapstructure:"http"`
	GRPC GRPCServerConfig `mapstructure:"grpc"`
}

// HTTPServerConfig holds HTTP server settings.
type HTTPServerConfig struct {
	Enabled        bool          `mapstructure:"enabled"`
	Addr           string        `mapstructure:"addr"`
	ReadTimeout    time.Duration `mapstructure:"read_timeout"`
	WriteTimeout   time.Duration `mapstructure:"write_timeout"`
	IdleTimeout    time.Duration `mapstructure:"idle_timeout"`
	MaxHeaderBytes int           `mapstructure:"max_header_bytes"`
}

// GRPCServerConfig holds gRPC server settings.
type GRPCServerConfig struct {
	Enabled        bool          `mapstructure:"enabled"`
	Addr           string        `mapstructure:"addr"`
	MaxRecvMsgSize int           `mapstructure:"max_recv_msg_size"`
	MaxSendMsgSize int           `mapstructure:"max_send_msg_size"`
	Keepalive      KeepaliveConfig `mapstructure:"keepalive"`
}

// KeepaliveConfig holds gRPC keepalive settings.
type KeepaliveConfig struct {
	Time    time.Duration `mapstructure:"time"`
	Timeout time.Duration `mapstructure:"timeout"`
}

// JWTConfig holds JWT validation configuration.
type JWTConfig struct {
	Issuers    []IssuerConfig    `mapstructure:"issuers"`
	JWKSCache  JWKSCacheConfig   `mapstructure:"jwks_cache"`
	Validation ValidationConfig  `mapstructure:"validation"`
}

// IssuerConfig holds configuration for a trusted issuer.
type IssuerConfig struct {
	Name       string   `mapstructure:"name"`
	IssuerURL  string   `mapstructure:"issuer_url"`
	JWKSURL    string   `mapstructure:"jwks_url"`
	Audience   []string `mapstructure:"audience"`
	Algorithms []string `mapstructure:"algorithms"`
}

// JWKSCacheConfig holds JWKS caching configuration.
type JWKSCacheConfig struct {
	RefreshInterval    time.Duration `mapstructure:"refresh_interval"`
	RefreshTimeout     time.Duration `mapstructure:"refresh_timeout"`
	MinRefreshInterval time.Duration `mapstructure:"min_refresh_interval"`
}

// ValidationConfig holds token validation settings.
type ValidationConfig struct {
	ClockSkew         time.Duration `mapstructure:"clock_skew"`
	RequireExpiration bool          `mapstructure:"require_expiration"`
	RequireNotBefore  bool          `mapstructure:"require_not_before"`
}

// TokenExchangeConfig holds token exchange configuration.
type TokenExchangeConfig struct {
	Enabled      bool          `mapstructure:"enabled"`
	TokenURL     string        `mapstructure:"token_url"`
	ClientID     string        `mapstructure:"client_id"`
	ClientSecret string        `mapstructure:"client_secret"`
	Timeout      time.Duration `mapstructure:"timeout"`
}

// PolicyConfig holds policy engine configuration.
type PolicyConfig struct {
	Engine      string              `mapstructure:"engine"` // builtin, opa-sidecar, opa-embedded
	OPA         OPAConfig           `mapstructure:"opa"`
	OPAEmbedded OPAEmbeddedConfig   `mapstructure:"opa_embedded"`
	Builtin     BuiltinPolicyConfig `mapstructure:"builtin"`
	Fallback    FallbackConfig      `mapstructure:"fallback"`
}

// OPAConfig holds OPA HTTP client configuration.
type OPAConfig struct {
	URL        string        `mapstructure:"url"`
	PolicyPath string        `mapstructure:"policy_path"`
	Timeout    time.Duration `mapstructure:"timeout"`
	Retry      RetryConfig   `mapstructure:"retry"`
}

// RetryConfig holds retry settings.
type RetryConfig struct {
	MaxAttempts    int           `mapstructure:"max_attempts"`
	InitialBackoff time.Duration `mapstructure:"initial_backoff"`
	MaxBackoff     time.Duration `mapstructure:"max_backoff"`
}

// OPAEmbeddedConfig holds embedded OPA configuration.
type OPAEmbeddedConfig struct {
	// BundlePath is the path to OPA bundle (tar.gz)
	BundlePath string `mapstructure:"bundle_path"`

	// PolicyDir is the directory containing Rego policy files
	PolicyDir string `mapstructure:"policy_dir"`

	// DataDir is the directory containing JSON data files
	DataDir string `mapstructure:"data_dir"`

	// DecisionPath is the Rego decision path (e.g., "authz/allow")
	DecisionPath string `mapstructure:"decision_path"`

	// HotReload enables automatic policy reload on file changes
	HotReload bool `mapstructure:"hot_reload"`
}

// OPASidecarConfig is an alias for OPAConfig for clarity.
type OPASidecarConfig = OPAConfig

// BuiltinPolicyConfig holds built-in policy configuration.
type BuiltinPolicyConfig struct {
	RulesPath string `mapstructure:"rules_path"`
}

// FallbackConfig holds fallback policy configuration.
type FallbackConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Engine   string `mapstructure:"engine"`
	Behavior string `mapstructure:"behavior"` // deny, allow
}

// CacheConfig holds caching configuration.
type CacheConfig struct {
	L1 L1CacheConfig `mapstructure:"l1"`
	L2 L2CacheConfig `mapstructure:"l2"`
}

// L1CacheConfig holds in-memory cache configuration.
type L1CacheConfig struct {
	Enabled bool          `mapstructure:"enabled"`
	MaxSize int           `mapstructure:"max_size"`
	TTL     time.Duration `mapstructure:"ttl"`
}

// L2CacheConfig holds distributed cache configuration.
type L2CacheConfig struct {
	Enabled   bool            `mapstructure:"enabled"`
	Backend   string          `mapstructure:"backend"` // redis
	Redis     RedisCacheConfig `mapstructure:"redis"`
	TTL       CacheTTLConfig  `mapstructure:"ttl"`
	KeyPrefix string          `mapstructure:"key_prefix"`
}

// RedisCacheConfig holds Redis configuration.
type RedisCacheConfig struct {
	Addresses    []string      `mapstructure:"addresses"`
	Password     string        `mapstructure:"password"`
	DB           int           `mapstructure:"db"`
	PoolSize     int           `mapstructure:"pool_size"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
}

// CacheTTLConfig holds TTL settings for different cache types.
type CacheTTLConfig struct {
	Authorization time.Duration `mapstructure:"authorization"`
	JWT           time.Duration `mapstructure:"jwt"`
	JWKS          time.Duration `mapstructure:"jwks"`
}

// AuditConfig holds audit logging configuration.
type AuditConfig struct {
	Enabled    bool          `mapstructure:"enabled"`
	Events     []string      `mapstructure:"events"`
	Export     ExportConfig  `mapstructure:"export"`
	Enrichment EnrichConfig  `mapstructure:"enrichment"`
}

// ExportConfig holds audit export configuration.
type ExportConfig struct {
	OTLP   OTLPExportConfig   `mapstructure:"otlp"`
	Stdout StdoutExportConfig `mapstructure:"stdout"`
}

// OTLPExportConfig holds OTLP export configuration.
type OTLPExportConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Endpoint string `mapstructure:"endpoint"`
	Insecure bool   `mapstructure:"insecure"`
}

// StdoutExportConfig holds stdout export configuration.
type StdoutExportConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Format  string `mapstructure:"format"` // json, text
}

// EnrichConfig holds audit enrichment configuration.
type EnrichConfig struct {
	IncludeHeaders []string `mapstructure:"include_headers"`
	MaskFields     []string `mapstructure:"mask_fields"`
}

// HealthConfig holds health check configuration.
type HealthConfig struct {
	CheckInterval time.Duration `mapstructure:"check_interval"`
	Timeout       time.Duration `mapstructure:"timeout"`
	Checks        []CheckConfig `mapstructure:"checks"`
}

// CheckConfig holds individual health check configuration.
type CheckConfig struct {
	Name     string `mapstructure:"name"`
	Enabled  bool   `mapstructure:"enabled"`
	Critical bool   `mapstructure:"critical"`
}

// Load loads configuration from file and environment.
func Load(configPath string) (*Config, error) {
	v := viper.New()

	// Set defaults
	setDefaults(v)

	// Read config file
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("./configs")
		v.AddConfigPath("/etc/authz")
	}

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config: %w", err)
		}
		// Config file not found, use defaults
	}

	// Read environment variables
	v.SetEnvPrefix("AUTHZ")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.http.enabled", true)
	v.SetDefault("server.http.addr", ":8080")
	v.SetDefault("server.http.read_timeout", "10s")
	v.SetDefault("server.http.write_timeout", "10s")
	v.SetDefault("server.http.idle_timeout", "120s")
	v.SetDefault("server.http.max_header_bytes", 1<<20) // 1MB

	v.SetDefault("server.grpc.enabled", false)
	v.SetDefault("server.grpc.addr", ":9090")
	v.SetDefault("server.grpc.max_recv_msg_size", 4<<20) // 4MB
	v.SetDefault("server.grpc.max_send_msg_size", 4<<20)
	v.SetDefault("server.grpc.keepalive.time", "30s")
	v.SetDefault("server.grpc.keepalive.timeout", "10s")

	// Proxy defaults
	v.SetDefault("proxy.enabled", false)
	v.SetDefault("proxy.mode", "decision_only") // decision_only, reverse_proxy
	v.SetDefault("proxy.timeout", "30s")
	v.SetDefault("proxy.idle_conn_timeout", "90s")
	v.SetDefault("proxy.headers.add_user_info", true)
	v.SetDefault("proxy.headers.user_id_header", "X-User-ID")
	v.SetDefault("proxy.headers.user_roles_header", "X-User-Roles")
	v.SetDefault("proxy.retry.enabled", true)
	v.SetDefault("proxy.retry.max_attempts", 3)
	v.SetDefault("proxy.retry.initial_backoff", "100ms")
	v.SetDefault("proxy.retry.max_backoff", "1s")
	v.SetDefault("proxy.retry.retry_on", []int{502, 503, 504})

	// Egress proxy defaults
	v.SetDefault("egress.enabled", false)
	v.SetDefault("egress.defaults.timeout", "30s")
	v.SetDefault("egress.defaults.retry.max_attempts", 3)
	v.SetDefault("egress.defaults.retry.initial_backoff", "100ms")
	v.SetDefault("egress.defaults.retry.max_backoff", "2s")
	v.SetDefault("egress.token_store.type", "memory")
	v.SetDefault("egress.token_store.redis.key_prefix", "egress:tokens:")

	// Endpoints defaults (configurable paths)
	v.SetDefault("endpoints.authorize", "/v1/authorize")
	v.SetDefault("endpoints.authorize_batch", "/v1/authorize/batch")
	v.SetDefault("endpoints.token_validate", "/v1/token/validate")
	v.SetDefault("endpoints.token_exchange", "/v1/token/exchange")
	v.SetDefault("endpoints.egress", "/egress")
	v.SetDefault("endpoints.health", "/health")
	v.SetDefault("endpoints.ready", "/ready")
	v.SetDefault("endpoints.live", "/live")
	v.SetDefault("endpoints.metrics", "/metrics")
	v.SetDefault("endpoints.cache_invalidate", "/admin/cache/invalidate")
	v.SetDefault("endpoints.policy_reload", "/admin/policy/reload")

	// JWT defaults
	v.SetDefault("jwt.jwks_cache.refresh_interval", "1h")
	v.SetDefault("jwt.jwks_cache.refresh_timeout", "10s")
	v.SetDefault("jwt.jwks_cache.min_refresh_interval", "5m")
	v.SetDefault("jwt.validation.clock_skew", "30s")
	v.SetDefault("jwt.validation.require_expiration", true)
	v.SetDefault("jwt.validation.require_not_before", false)

	// Policy defaults
	v.SetDefault("policy.engine", "builtin")
	v.SetDefault("policy.opa.url", "http://localhost:8181")
	v.SetDefault("policy.opa.policy_path", "/v1/data/authz/allow")
	v.SetDefault("policy.opa.timeout", "10ms")
	v.SetDefault("policy.opa.retry.max_attempts", 3)
	v.SetDefault("policy.opa.retry.initial_backoff", "1ms")
	v.SetDefault("policy.opa.retry.max_backoff", "10ms")
	v.SetDefault("policy.opa_embedded.policy_dir", "/etc/authz/policies")
	v.SetDefault("policy.opa_embedded.data_dir", "/etc/authz/data")
	v.SetDefault("policy.opa_embedded.decision_path", "authz.allow")
	v.SetDefault("policy.opa_embedded.hot_reload", true)
	v.SetDefault("policy.builtin.rules_path", "/etc/authz/rules.yaml")
	v.SetDefault("policy.fallback.enabled", true)
	v.SetDefault("policy.fallback.engine", "builtin")
	v.SetDefault("policy.fallback.behavior", "deny")

	// Cache defaults
	v.SetDefault("cache.l1.enabled", true)
	v.SetDefault("cache.l1.max_size", 10000)
	v.SetDefault("cache.l1.ttl", "10s")
	v.SetDefault("cache.l2.enabled", false)
	v.SetDefault("cache.l2.backend", "redis")
	v.SetDefault("cache.l2.ttl.authorization", "60s")
	v.SetDefault("cache.l2.ttl.jwt", "300s")
	v.SetDefault("cache.l2.ttl.jwks", "3600s")
	v.SetDefault("cache.l2.key_prefix", "authz:")

	// Audit defaults
	v.SetDefault("audit.enabled", true)
	v.SetDefault("audit.events", []string{"AUTHZ_DECISION"})
	v.SetDefault("audit.export.stdout.enabled", true)
	v.SetDefault("audit.export.stdout.format", "json")
	v.SetDefault("audit.export.otlp.enabled", false)

	// Logging defaults
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.output", "stdout")
	v.SetDefault("logging.add_caller", true)

	// Health defaults
	v.SetDefault("health.check_interval", "10s")
	v.SetDefault("health.timeout", "5s")
}
