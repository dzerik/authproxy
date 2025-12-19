package config

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/your-org/authz-service/pkg/logger"
)

// Loader handles loading and watching configuration from multiple sources.
type Loader struct {
	// Environment config (static, loaded once)
	environment *EnvironmentConfig
	// Services config (dynamic, runtime updatable)
	services atomic.Pointer[ServicesConfig]
	// Rules config (dynamic, runtime updatable)
	rules atomic.Pointer[RulesConfig]

	source      ConfigSource
	log         *zap.Logger
	updateCh    chan ConfigUpdate
	subscribers []chan ConfigUpdate
	mu          sync.RWMutex
	started     bool
	ctx         context.Context
	cancel      context.CancelFunc
}

// LoaderOption configures the Loader.
type LoaderOption func(*Loader)

// WithLogger sets the logger for the loader.
func WithLogger(log *zap.Logger) LoaderOption {
	return func(l *Loader) {
		l.log = log
	}
}

// NewLoader creates a new configuration loader.
func NewLoader(opts ...LoaderOption) *Loader {
	l := &Loader{
		log:      zap.NewNop(),
		updateCh: make(chan ConfigUpdate, 10),
	}

	for _, opt := range opts {
		opt(l)
	}

	l.log = l.log.Named("config-loader")

	return l
}

// LoadEnvironment loads environment configuration from file.
// This should be called once at startup.
func (l *Loader) LoadEnvironment(path string) (*EnvironmentConfig, error) {
	v := viper.New()

	// Set defaults for environment config
	setEnvironmentDefaults(v)

	if path != "" {
		v.SetConfigFile(path)
	} else {
		v.SetConfigName("environment")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("./configs")
		v.AddConfigPath("/etc/authz")
	}

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read environment config: %w", err)
		}
		l.log.Warn("environment config file not found, using defaults")
	}

	// Read environment variables
	v.SetEnvPrefix("AUTHZ")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	var cfg EnvironmentConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal environment config: %w", err)
	}

	l.environment = &cfg

	l.log.Info("environment configuration loaded",
		zap.String("env", cfg.Env.Name),
		zap.String("config_source_type", cfg.ConfigSource.Type))

	return &cfg, nil
}

// InitSource initializes the configuration source based on environment settings.
func (l *Loader) InitSource(ctx context.Context) error {
	if l.environment == nil {
		return fmt.Errorf("environment config not loaded, call LoadEnvironment first")
	}

	settings := l.environment.ConfigSource

	switch settings.Type {
	case "file", "":
		source, err := NewFileConfigSource(settings.File, l.log)
		if err != nil {
			return fmt.Errorf("failed to create file config source: %w", err)
		}
		l.source = source

	case "remote":
		source, err := NewRemoteConfigSource(settings.Remote, l.log)
		if err != nil {
			return fmt.Errorf("failed to create remote config source: %w", err)
		}
		l.source = source

	default:
		return fmt.Errorf("unknown config source type: %s", settings.Type)
	}

	return nil
}

// LoadServices loads services configuration.
func (l *Loader) LoadServices(ctx context.Context) (*ServicesConfig, error) {
	if l.source == nil {
		return nil, fmt.Errorf("config source not initialized, call InitSource first")
	}

	config, err := l.source.Load(ctx, ConfigTypeServices)
	if err != nil {
		return nil, fmt.Errorf("failed to load services config: %w", err)
	}

	svc, ok := config.(*ServicesConfig)
	if !ok {
		return nil, fmt.Errorf("unexpected config type: %T", config)
	}

	// Validate configuration before storing
	validator := NewConfigValidator()
	if err := validator.ValidateServices(svc, l.environment, l.GetRules()); err != nil {
		return nil, err // Return validation errors as-is for pretty printing
	}

	l.services.Store(svc)

	l.log.Info("services configuration loaded",
		zap.String("version", svc.Version))

	return svc, nil
}

// LoadRules loads rules configuration.
func (l *Loader) LoadRules(ctx context.Context) (*RulesConfig, error) {
	if l.source == nil {
		return nil, fmt.Errorf("config source not initialized, call InitSource first")
	}

	config, err := l.source.Load(ctx, ConfigTypeRules)
	if err != nil {
		return nil, fmt.Errorf("failed to load rules config: %w", err)
	}

	rules, ok := config.(*RulesConfig)
	if !ok {
		return nil, fmt.Errorf("unexpected config type: %T", config)
	}

	// Validate rules configuration (priority conflicts, etc.)
	validator := NewConfigValidator()
	if err := validator.ValidateRules(rules); err != nil {
		return nil, err // Return validation errors as-is for pretty printing
	}

	l.rules.Store(rules)

	l.log.Info("rules configuration loaded",
		zap.String("version", rules.Version),
		zap.Int("rule_count", len(rules.Rules)))

	return rules, nil
}

// StartWatching starts watching for configuration changes.
func (l *Loader) StartWatching(ctx context.Context) error {
	if l.source == nil {
		return fmt.Errorf("config source not initialized")
	}

	l.mu.Lock()
	if l.started {
		l.mu.Unlock()
		return nil
	}
	l.started = true
	l.ctx, l.cancel = context.WithCancel(ctx)
	l.mu.Unlock()

	updates, err := l.source.Watch(l.ctx)
	if err != nil {
		return fmt.Errorf("failed to start watching: %w", err)
	}

	if updates == nil {
		l.log.Info("config watching is disabled")
		return nil
	}

	go l.watchLoop(updates)

	l.log.Info("started watching for configuration changes")
	return nil
}

func (l *Loader) watchLoop(updates <-chan ConfigUpdate) {
	for {
		select {
		case <-l.ctx.Done():
			return

		case update, ok := <-updates:
			if !ok {
				return
			}

			l.handleUpdate(update)
		}
	}
}

func (l *Loader) handleUpdate(update ConfigUpdate) {
	l.log.Info("received config update",
		zap.String("type", string(update.Type)),
		zap.String("version", update.Version))

	switch update.Type {
	case ConfigTypeServices:
		if svc, ok := update.Config.(*ServicesConfig); ok {
			// Validate before applying runtime update
			validator := NewConfigValidator()
			if err := validator.ValidateServices(svc, l.environment, l.GetRules()); err != nil {
				l.log.Error("config update rejected: validation failed",
					zap.String("type", string(update.Type)),
					zap.String("version", update.Version),
					zap.Error(err))
				return // Don't apply the update, keep using previous config
			}
			l.services.Store(svc)
			l.log.Info("services config updated successfully",
				zap.String("version", update.Version))
		}

	case ConfigTypeRules:
		if rules, ok := update.Config.(*RulesConfig); ok {
			// Validate before applying runtime update
			validator := NewConfigValidator()
			if err := validator.ValidateRules(rules); err != nil {
				l.log.Error("config update rejected: validation failed",
					zap.String("type", string(update.Type)),
					zap.String("version", update.Version),
					zap.Error(err))
				return // Don't apply the update, keep using previous config
			}
			l.rules.Store(rules)
			l.log.Info("rules config updated successfully",
				zap.String("version", update.Version))
		}
	}

	// Notify subscribers
	l.notifySubscribers(update)
}

func (l *Loader) notifySubscribers(update ConfigUpdate) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	for _, ch := range l.subscribers {
		select {
		case ch <- update:
		default:
			l.log.Warn("subscriber channel full, dropping update")
		}
	}
}

// Subscribe returns a channel that receives configuration updates.
func (l *Loader) Subscribe() <-chan ConfigUpdate {
	l.mu.Lock()
	defer l.mu.Unlock()

	ch := make(chan ConfigUpdate, 10)
	l.subscribers = append(l.subscribers, ch)
	return ch
}

// Stop stops the loader and releases resources.
func (l *Loader) Stop() error {
	l.mu.Lock()
	if l.cancel != nil {
		l.cancel()
	}
	l.started = false
	l.mu.Unlock()

	if l.source != nil {
		return l.source.Close()
	}

	return nil
}

// GetEnvironment returns the current environment configuration.
func (l *Loader) GetEnvironment() *EnvironmentConfig {
	return l.environment
}

// GetServices returns the current services configuration.
func (l *Loader) GetServices() *ServicesConfig {
	return l.services.Load()
}

// GetRules returns the current rules configuration.
func (l *Loader) GetRules() *RulesConfig {
	return l.rules.Load()
}

// ToConfig creates a legacy Config struct from the split configurations.
// Deprecated: Use GetEnvironment() and GetServices() for new code.
func (l *Loader) ToConfig() *Config {
	env := l.environment
	svc := l.services.Load()

	if env == nil {
		return nil
	}

	cfg := &Config{
		Server: env.Server,
		Logging: logger.Config{
			Level:     env.Logging.Level,
			Format:    env.Logging.Format,
			Output:    env.Logging.Output,
			AddCaller: env.Logging.AddCaller,
		},
		Tracing:    env.Tracing,
		Env:        env.Env,
		Management: env.Management,
	}

	if svc != nil {
		cfg.JWT = svc.JWT
		cfg.TokenExchange = svc.TokenExchange
		cfg.Policy = svc.Policy
		cfg.Cache = svc.Cache
		cfg.Audit = svc.Audit
		cfg.Health = svc.Health
		cfg.Resilience = svc.Resilience
		cfg.SensitiveData = svc.SensitiveData
		cfg.TLSClientCert = svc.TLSClientCert
		cfg.RequestBody = svc.RequestBody

		// Store multi-listener configs for new multi-port architecture
		cfg.ProxyListeners = svc.Proxy
		cfg.EgressListeners = svc.Egress

		// Convert new proxy listeners config to legacy proxy config (for backward compatibility)
		if svc.Proxy.Enabled && len(svc.Proxy.Listeners) > 0 {
			firstListener := svc.Proxy.Listeners[0]
			cfg.Proxy = ProxyConfig{
				Enabled:   svc.Proxy.Enabled,
				Mode:      firstListener.Mode,
				Upstreams: firstListener.Upstreams,
				Routes:    firstListener.Routes,
				Headers:   firstListener.Headers,
				Timeout:   firstListener.Timeout,
				Retry:     firstListener.Retry,
			}
			for _, up := range firstListener.Upstreams {
				cfg.Proxy.Upstream = up
				break
			}
		}

		// Convert new egress listeners config to legacy egress config (for backward compatibility)
		if svc.Egress.Enabled && len(svc.Egress.Listeners) > 0 {
			firstListener := svc.Egress.Listeners[0]
			cfg.Egress = EgressConfig{
				Enabled:    svc.Egress.Enabled,
				Targets:    firstListener.Targets,
				Routes:     firstListener.Routes,
				Defaults:   svc.Egress.Defaults,
				TokenStore: svc.Egress.TokenStore,
			}
		}
	}

	return cfg
}

// =============================================================================
// Environment Defaults
// =============================================================================

func setEnvironmentDefaults(v *viper.Viper) {
	// Env defaults
	v.SetDefault("env.name", "development")

	// Server defaults
	v.SetDefault("server.http.enabled", true)
	v.SetDefault("server.http.addr", ":8080")
	v.SetDefault("server.http.read_timeout", "10s")
	v.SetDefault("server.http.write_timeout", "30s")
	v.SetDefault("server.http.idle_timeout", "120s")
	v.SetDefault("server.http.shutdown_timeout", "30s")
	v.SetDefault("server.http.max_header_bytes", 1<<20)
	// Request tracking header defaults
	v.SetDefault("server.http.request_tracking.request_id_header", "X-Request-ID")
	v.SetDefault("server.http.request_tracking.correlation_id_header", "X-Correlation-ID")
	v.SetDefault("server.http.request_tracking.forwarded_auth_header", "X-Forwarded-Authorization")
	v.SetDefault("server.http.request_tracking.generate_if_missing", true)
	v.SetDefault("server.http.request_tracking.propagate_to_upstream", true)

	v.SetDefault("server.grpc.enabled", false)
	v.SetDefault("server.grpc.addr", ":9090")

	// Management server defaults
	v.SetDefault("management.enabled", true)
	v.SetDefault("management.admin_addr", ":15000")
	v.SetDefault("management.health_addr", ":15020")
	v.SetDefault("management.ready_addr", ":15021")

	// Logging defaults
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.output", "stdout")
	v.SetDefault("logging.add_caller", true)

	// Tracing defaults
	v.SetDefault("tracing.enabled", false)
	v.SetDefault("tracing.endpoint", "localhost:4317")
	v.SetDefault("tracing.insecure", true)
	v.SetDefault("tracing.service_name", "authz-service")
	v.SetDefault("tracing.environment", "development")
	v.SetDefault("tracing.sample_rate", 1.0)
	v.SetDefault("tracing.propagate_headers", true)

	// Config source defaults
	v.SetDefault("config_source.type", "file")
	v.SetDefault("config_source.file.services_path", "/etc/authz/services.yaml")
	v.SetDefault("config_source.file.rules_path", "/etc/authz/rules.yaml")
	v.SetDefault("config_source.file.watch_enabled", true)
	v.SetDefault("config_source.fallback.enabled", true)
	v.SetDefault("config_source.fallback.cache_path", "/var/cache/authz/")
	v.SetDefault("config_source.fallback.max_age", "1h")
	v.SetDefault("config_source.remote.polling.interval", "30s")
	v.SetDefault("config_source.remote.polling.timeout", "10s")
}

// LoadAll loads all configuration files (new style with split configs).
// Returns environment, services, and rules configs.
func LoadAll(ctx context.Context, envPath string) (*Loader, error) {
	log, _ := zap.NewProduction()

	loader := NewLoader(WithLogger(log))

	// Load environment config
	env, err := loader.LoadEnvironment(envPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load environment config: %w", err)
	}

	// Override paths for local development
	if env.ConfigSource.File.ServicesPath == "" || !fileExists(env.ConfigSource.File.ServicesPath) {
		env.ConfigSource.File.ServicesPath = "./configs/services.yaml"
	}
	if env.ConfigSource.File.RulesPath == "" || !fileExists(env.ConfigSource.File.RulesPath) {
		env.ConfigSource.File.RulesPath = "./configs/rules.yaml"
	}

	// Initialize config source
	if err := loader.InitSource(ctx); err != nil {
		return nil, fmt.Errorf("failed to init config source: %w", err)
	}

	// Load services config
	if _, err := loader.LoadServices(ctx); err != nil {
		return nil, fmt.Errorf("failed to load services config: %w", err)
	}

	// Load rules config
	if _, err := loader.LoadRules(ctx); err != nil {
		return nil, fmt.Errorf("failed to load rules config: %w", err)
	}

	return loader, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// GetConfigVersion returns the current version of all configurations.
func (l *Loader) GetConfigVersion() ConfigVersion {
	var svcVersion, rulesVersion string

	if svc := l.services.Load(); svc != nil {
		svcVersion = svc.Version
	}
	if rules := l.rules.Load(); rules != nil {
		rulesVersion = rules.Version
	}

	return ConfigVersion{
		Environment: l.environment.Env.Version,
		Services:    svcVersion,
		Rules:       rulesVersion,
	}
}
