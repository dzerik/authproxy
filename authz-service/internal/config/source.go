package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// ConfigSource defines the interface for configuration sources.
// It supports both initial loading and watching for changes.
type ConfigSource interface {
	// Load loads the specified configuration type.
	Load(ctx context.Context, configType ConfigType) (interface{}, error)

	// Watch starts watching for configuration changes.
	// Returns a channel that receives updates when configuration changes.
	Watch(ctx context.Context) (<-chan ConfigUpdate, error)

	// Close stops watching and releases resources.
	Close() error

	// GetVersion returns the current version of the specified config type.
	GetVersion(configType ConfigType) string
}

// =============================================================================
// File Config Source
// =============================================================================

// FileConfigSource loads configuration from local files.
type FileConfigSource struct {
	settings FileSourceSettings
	log      *zap.Logger
	watcher  *fsnotify.Watcher
	versions map[ConfigType]string
	mu       sync.RWMutex
	closed   bool
	closeCh  chan struct{}
}

// NewFileConfigSource creates a new file-based configuration source.
func NewFileConfigSource(settings FileSourceSettings, log *zap.Logger) (*FileConfigSource, error) {
	if log == nil {
		log = zap.NewNop()
	}

	source := &FileConfigSource{
		settings: settings,
		log:      log.Named("file-config-source"),
		versions: make(map[ConfigType]string),
		closeCh:  make(chan struct{}),
	}

	return source, nil
}

// Load loads the specified configuration type from file.
func (s *FileConfigSource) Load(ctx context.Context, configType ConfigType) (interface{}, error) {
	var path string
	switch configType {
	case ConfigTypeServices:
		path = s.settings.ServicesPath
	case ConfigTypeRules:
		path = s.settings.RulesPath
	default:
		return nil, fmt.Errorf("unsupported config type: %s", configType)
	}

	if path == "" {
		return nil, fmt.Errorf("path not configured for config type: %s", configType)
	}

	// Check file exists
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat config file %s: %w", path, err)
	}

	// Use modification time as version
	version := info.ModTime().Format(time.RFC3339Nano)

	v := viper.New()
	v.SetConfigFile(path)

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	var config interface{}

	switch configType {
	case ConfigTypeServices:
		// Set defaults for services configuration
		setServicesDefaults(v)
		var svc ServicesConfig
		if err := v.Unmarshal(&svc); err != nil {
			return nil, fmt.Errorf("failed to unmarshal services config: %w", err)
		}
		svc.Version = version
		config = &svc

	case ConfigTypeRules:
		var rules RulesConfig
		if err := v.Unmarshal(&rules); err != nil {
			return nil, fmt.Errorf("failed to unmarshal rules config: %w", err)
		}
		config = &rules
	}

	s.mu.Lock()
	s.versions[configType] = version
	s.mu.Unlock()

	s.log.Info("loaded config from file",
		zap.String("type", string(configType)),
		zap.String("path", path),
		zap.String("version", version))

	return config, nil
}

// Watch starts watching for configuration file changes.
func (s *FileConfigSource) Watch(ctx context.Context) (<-chan ConfigUpdate, error) {
	if !s.settings.WatchEnabled {
		s.log.Info("file watching is disabled")
		return nil, nil
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	s.mu.Lock()
	s.watcher = watcher
	s.mu.Unlock()

	updates := make(chan ConfigUpdate, 10)

	// Add files to watch
	filesToWatch := []struct {
		path       string
		configType ConfigType
	}{
		{s.settings.ServicesPath, ConfigTypeServices},
		{s.settings.RulesPath, ConfigTypeRules},
	}

	for _, file := range filesToWatch {
		if file.path == "" {
			continue
		}
		// Watch directory containing the file (for atomic writes)
		dir := filepath.Dir(file.path)
		if err := watcher.Add(dir); err != nil {
			s.log.Warn("failed to watch directory",
				zap.String("dir", dir),
				zap.Error(err))
		} else {
			s.log.Info("watching config file",
				zap.String("path", file.path),
				zap.String("type", string(file.configType)))
		}
	}

	// Start watching goroutine
	go s.watchLoop(ctx, watcher, updates)

	return updates, nil
}

func (s *FileConfigSource) watchLoop(ctx context.Context, watcher *fsnotify.Watcher, updates chan<- ConfigUpdate) {
	defer close(updates)

	// Debounce timer to avoid multiple reloads for same file
	debounceTimers := make(map[string]*time.Timer)
	debounceMu := sync.Mutex{}

	for {
		select {
		case <-ctx.Done():
			s.log.Info("stopping file watcher due to context cancellation")
			return

		case <-s.closeCh:
			s.log.Info("stopping file watcher due to close")
			return

		case event, ok := <-watcher.Events:
			if !ok {
				return
			}

			// Determine which config type this file belongs to
			var configType ConfigType
			switch event.Name {
			case s.settings.ServicesPath:
				configType = ConfigTypeServices
			case s.settings.RulesPath:
				configType = ConfigTypeRules
			default:
				// Check if the event is for a file we care about (handles symlinks)
				absPath, _ := filepath.Abs(event.Name)
				servicesAbs, _ := filepath.Abs(s.settings.ServicesPath)
				rulesAbs, _ := filepath.Abs(s.settings.RulesPath)

				switch absPath {
				case servicesAbs:
					configType = ConfigTypeServices
				case rulesAbs:
					configType = ConfigTypeRules
				default:
					continue
				}
			}

			// Only handle write/create events
			if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}

			// Debounce multiple events
			debounceMu.Lock()
			if timer, exists := debounceTimers[event.Name]; exists {
				timer.Stop()
			}
			debounceTimers[event.Name] = time.AfterFunc(100*time.Millisecond, func() {
				s.handleFileChange(ctx, configType, updates)
			})
			debounceMu.Unlock()

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			s.log.Error("file watcher error", zap.Error(err))
		}
	}
}

func (s *FileConfigSource) handleFileChange(ctx context.Context, configType ConfigType, updates chan<- ConfigUpdate) {
	config, err := s.Load(ctx, configType)
	if err != nil {
		s.log.Error("failed to reload config",
			zap.String("type", string(configType)),
			zap.Error(err))
		return
	}

	update := ConfigUpdate{
		Type:      configType,
		Version:   s.GetVersion(configType),
		Config:    config,
		Timestamp: time.Now(),
		Source:    "file",
	}

	select {
	case updates <- update:
		s.log.Info("config update sent",
			zap.String("type", string(configType)),
			zap.String("version", update.Version))
	case <-ctx.Done():
		return
	default:
		s.log.Warn("config update channel full, dropping update",
			zap.String("type", string(configType)))
	}
}

// Close stops watching and releases resources.
func (s *FileConfigSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true
	close(s.closeCh)

	if s.watcher != nil {
		return s.watcher.Close()
	}

	return nil
}

// GetVersion returns the current version of the specified config type.
func (s *FileConfigSource) GetVersion(configType ConfigType) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.versions[configType]
}

// =============================================================================
// Rules Config Type (moved from domain for convenience)
// =============================================================================

// RulesConfig holds authorization rules configuration.
type RulesConfig struct {
	// Version is the rules version
	Version string `mapstructure:"version" yaml:"version" json:"version"`
	// Description describes these rules
	Description string `mapstructure:"description" yaml:"description" json:"description"`
	// DefaultDeny sets default behavior when no rule matches
	DefaultDeny bool `mapstructure:"default_deny" yaml:"default_deny" json:"default_deny"`
	// Rules is the list of authorization rules
	Rules []Rule `mapstructure:"rules" yaml:"rules" json:"rules"`
}

// Rule represents a single authorization rule.
type Rule struct {
	// Name is the rule name
	Name string `mapstructure:"name" yaml:"name" json:"name"`
	// Description describes the rule
	Description string `mapstructure:"description" yaml:"description" json:"description"`
	// Priority determines rule evaluation order (higher = earlier)
	Priority int `mapstructure:"priority" yaml:"priority" json:"priority"`
	// Enabled indicates if the rule is active
	Enabled bool `mapstructure:"enabled" yaml:"enabled" json:"enabled"`
	// Conditions are the matching conditions
	Conditions RuleConditions `mapstructure:"conditions" yaml:"conditions" json:"conditions"`
	// Effect is the rule effect (allow/deny)
	Effect string `mapstructure:"effect" yaml:"effect" json:"effect"`
}

// RuleConditions holds rule matching conditions.
type RuleConditions struct {
	// Paths are path patterns to match
	Paths []string `mapstructure:"paths" yaml:"paths" json:"paths"`
	// Methods are HTTP methods to match
	Methods []string `mapstructure:"methods" yaml:"methods" json:"methods"`
	// Roles are required roles (any match)
	Roles []string `mapstructure:"roles" yaml:"roles" json:"roles"`
	// Scopes are required scopes (any match)
	Scopes []string `mapstructure:"scopes" yaml:"scopes" json:"scopes"`
	// IPs are allowed client IPs/CIDRs
	IPs []string `mapstructure:"ips" yaml:"ips" json:"ips"`
	// Headers are required headers
	Headers map[string]string `mapstructure:"headers" yaml:"headers" json:"headers"`
	// CEL is a CEL expression for custom conditions
	CEL string `mapstructure:"cel" yaml:"cel" json:"cel"`
}

// =============================================================================
// Services Configuration Defaults
// =============================================================================

// setServicesDefaults sets default values for services configuration.
func setServicesDefaults(v *viper.Viper) {
	// JWT defaults
	v.SetDefault("jwt.jwks_cache.refresh_interval", "1h")
	v.SetDefault("jwt.jwks_cache.refresh_timeout", "10s")
	v.SetDefault("jwt.jwks_cache.min_refresh_interval", "5m")
	v.SetDefault("jwt.validation.clock_skew", "30s")
	v.SetDefault("jwt.validation.require_expiration", true)
	v.SetDefault("jwt.validation.require_not_before", false)

	// Token Exchange defaults
	v.SetDefault("token_exchange.enabled", false)
	v.SetDefault("token_exchange.timeout", "10s")

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
	// Policy cache defaults
	v.SetDefault("policy.cache.cel_cache_size", 500)
	v.SetDefault("policy.cache.path_matcher_cache_size", 1000)
	v.SetDefault("policy.cache.cidr_matcher_cache_size", 500)

	// Cache defaults
	v.SetDefault("cache.l1.enabled", true)
	v.SetDefault("cache.l1.max_size", 10000)
	v.SetDefault("cache.l1.ttl", "10s")
	v.SetDefault("cache.l2.enabled", false)
	v.SetDefault("cache.l2.backend", "redis")
	v.SetDefault("cache.l2.key_prefix", "authz:")
	v.SetDefault("cache.l2.redis.pool_size", 10)
	v.SetDefault("cache.l2.redis.read_timeout", "3s")
	v.SetDefault("cache.l2.redis.write_timeout", "3s")
	v.SetDefault("cache.l2.ttl.authorization", "60s")
	v.SetDefault("cache.l2.ttl.jwt", "300s")
	v.SetDefault("cache.l2.ttl.jwks", "3600s")

	// Audit defaults
	v.SetDefault("audit.enabled", true)
	v.SetDefault("audit.events", []string{"AUTHZ_DECISION"})
	v.SetDefault("audit.export.stdout.enabled", true)
	v.SetDefault("audit.export.stdout.format", "json")
	v.SetDefault("audit.export.otlp.enabled", false)
	v.SetDefault("audit.export.otlp.insecure", false)

	// Health defaults
	v.SetDefault("health.check_interval", "10s")
	v.SetDefault("health.timeout", "5s")
	// SLO defaults
	v.SetDefault("health.slo.enabled", true)
	v.SetDefault("health.slo.latency_p99_threshold_ms", 100)
	v.SetDefault("health.slo.latency_p999_threshold_ms", 500)
	v.SetDefault("health.slo.availability_target", 99.9)
	v.SetDefault("health.slo.error_rate_threshold", 0.1)

	// Resilience defaults
	v.SetDefault("resilience.rate_limit.enabled", true)
	v.SetDefault("resilience.rate_limit.rate", "100-S")
	v.SetDefault("resilience.rate_limit.store", "memory")
	v.SetDefault("resilience.rate_limit.trust_forwarded_for", true)
	v.SetDefault("resilience.rate_limit.fail_close", true)
	v.SetDefault("resilience.rate_limit.headers.enabled", true)
	v.SetDefault("resilience.rate_limit.headers.limit_header", "X-RateLimit-Limit")
	v.SetDefault("resilience.rate_limit.headers.remaining_header", "X-RateLimit-Remaining")
	v.SetDefault("resilience.rate_limit.headers.reset_header", "X-RateLimit-Reset")
	v.SetDefault("resilience.rate_limit.redis.db", 1)
	v.SetDefault("resilience.rate_limit.redis.key_prefix", "authz:ratelimit:")

	v.SetDefault("resilience.circuit_breaker.enabled", true)
	v.SetDefault("resilience.circuit_breaker.default.max_requests", 3)
	v.SetDefault("resilience.circuit_breaker.default.interval", "60s")
	v.SetDefault("resilience.circuit_breaker.default.timeout", "30s")
	v.SetDefault("resilience.circuit_breaker.default.failure_threshold", 5)
	v.SetDefault("resilience.circuit_breaker.default.success_threshold", 2)
	v.SetDefault("resilience.circuit_breaker.default.on_state_change", true)

	// Sensitive data defaults (expanded lists)
	v.SetDefault("sensitive_data.enabled", true)
	v.SetDefault("sensitive_data.mask_value", "***MASKED***")
	v.SetDefault("sensitive_data.fields", []string{
		"password", "secret", "token", "api_key", "apikey",
		"authorization", "client_secret", "access_token", "refresh_token",
		"private_key", "credential", "credentials", "passwd", "pwd",
		"secret_key", "signing_key", "encryption_key", "bearer",
		"session_id", "session_token", "auth_token", "id_token",
	})
	v.SetDefault("sensitive_data.headers", []string{
		"Authorization", "X-API-Key", "Cookie", "Set-Cookie",
		"X-Auth-Token", "X-Session-ID", "X-CSRF-Token", "X-XSRF-Token",
		"Proxy-Authorization", "WWW-Authenticate", "X-Forwarded-Authorization",
	})
	v.SetDefault("sensitive_data.mask_jwt", true)
	v.SetDefault("sensitive_data.partial_mask.enabled", false)
	v.SetDefault("sensitive_data.partial_mask.show_first", 4)
	v.SetDefault("sensitive_data.partial_mask.show_last", 4)
	v.SetDefault("sensitive_data.partial_mask.min_length", 12)

	// TLS Client Cert defaults
	v.SetDefault("tls_client_cert.enabled", false)
	v.SetDefault("tls_client_cert.require_verified", false)
	v.SetDefault("tls_client_cert.sources.xfcc.enabled", true)
	v.SetDefault("tls_client_cert.sources.xfcc.header", "X-Forwarded-Client-Cert")
	v.SetDefault("tls_client_cert.sources.headers.enabled", false)
	v.SetDefault("tls_client_cert.sources.headers.subject", "X-SSL-Client-S-DN")
	v.SetDefault("tls_client_cert.sources.headers.issuer", "X-SSL-Client-I-DN")
	v.SetDefault("tls_client_cert.sources.headers.common_name", "X-SSL-Client-CN")
	v.SetDefault("tls_client_cert.sources.headers.serial", "X-SSL-Client-Serial")
	v.SetDefault("tls_client_cert.sources.headers.verified", "X-SSL-Client-Verify")
	v.SetDefault("tls_client_cert.sources.headers.verified_value", "SUCCESS")
	v.SetDefault("tls_client_cert.sources.headers.fingerprint", "X-SSL-Client-Fingerprint")
	v.SetDefault("tls_client_cert.sources.headers.dns_names", "X-SSL-Client-DNS")
	v.SetDefault("tls_client_cert.sources.headers.uri", "X-SSL-Client-URI")
	v.SetDefault("tls_client_cert.sources.headers.not_before", "X-SSL-Client-Not-Before")
	v.SetDefault("tls_client_cert.sources.headers.not_after", "X-SSL-Client-Not-After")

	// Request body defaults
	v.SetDefault("request_body.enabled", false)
	v.SetDefault("request_body.max_size", 1048576)
	v.SetDefault("request_body.require_content_type", true)
	v.SetDefault("request_body.schema.enabled", false)
	v.SetDefault("request_body.schema.schema_dir", "/etc/authz/schemas")
	v.SetDefault("request_body.schema.strict_validation", false)
	v.SetDefault("request_body.schema.allow_additional_properties", true)

	// Proxy defaults
	v.SetDefault("proxy.enabled", false)
	v.SetDefault("proxy.defaults.timeout", "30s")
	v.SetDefault("proxy.defaults.idle_conn_timeout", "90s")
	v.SetDefault("proxy.defaults.max_idle_conns", 100)
	v.SetDefault("proxy.defaults.headers.add_user_info", true)
	v.SetDefault("proxy.defaults.headers.user_id_header", "X-User-ID")
	v.SetDefault("proxy.defaults.headers.user_roles_header", "X-User-Roles")
	v.SetDefault("proxy.defaults.retry.enabled", true)
	v.SetDefault("proxy.defaults.retry.max_attempts", 3)
	v.SetDefault("proxy.defaults.retry.initial_backoff", "100ms")
	v.SetDefault("proxy.defaults.retry.max_backoff", "1s")
	v.SetDefault("proxy.defaults.retry.retry_on", []int{502, 503, 504})
	// Proxy error response defaults
	v.SetDefault("proxy.defaults.error_response.format", "json")
	v.SetDefault("proxy.defaults.error_response.include_request_id", true)
	v.SetDefault("proxy.defaults.error_response.include_reason", true)
	v.SetDefault("proxy.defaults.error_response.include_timestamp", false)
	v.SetDefault("proxy.defaults.error_response.include_path", false)

	// Egress defaults
	v.SetDefault("egress.enabled", false)
	v.SetDefault("egress.defaults.timeout", "30s")
	v.SetDefault("egress.defaults.retry.max_attempts", 3)
	v.SetDefault("egress.defaults.retry.initial_backoff", "100ms")
	v.SetDefault("egress.defaults.retry.max_backoff", "2s")
	v.SetDefault("egress.token_store.type", "memory")
	v.SetDefault("egress.token_store.redis.db", 0)
	v.SetDefault("egress.token_store.redis.key_prefix", "egress:tokens:")
	v.SetDefault("egress.legacy_endpoint.enabled", true)
	v.SetDefault("egress.legacy_endpoint.path", "/egress")
	// Egress error response defaults
	v.SetDefault("egress.defaults.error_response.format", "json")
	v.SetDefault("egress.defaults.error_response.include_request_id", true)
	v.SetDefault("egress.defaults.error_response.include_reason", true)
	v.SetDefault("egress.defaults.error_response.include_timestamp", false)
	v.SetDefault("egress.defaults.error_response.include_path", false)
}
