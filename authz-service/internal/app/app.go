// Package app provides application lifecycle management and dependency injection.
package app

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/internal/service/audit"
	"github.com/your-org/authz-service/internal/service/cache"
	"github.com/your-org/authz-service/internal/service/egress"
	"github.com/your-org/authz-service/internal/service/jwt"
	"github.com/your-org/authz-service/internal/service/metrics"
	"github.com/your-org/authz-service/internal/service/policy"
	httpTransport "github.com/your-org/authz-service/internal/transport/http"
	"github.com/your-org/authz-service/pkg/logger"
	"github.com/your-org/authz-service/pkg/resilience/circuitbreaker"
	"github.com/your-org/authz-service/pkg/resilience/ratelimit"
	"github.com/your-org/authz-service/pkg/tracing"
)

// BuildInfo holds application build information.
type BuildInfo struct {
	Version   string
	BuildTime string
	GitCommit string
}

// App represents the application with all its services and dependencies.
type App struct {
	cfg    *config.Config
	loader *config.Loader // New config loader for hot-reload support

	// Static servers (managed directly)
	httpServer       *httpTransport.Server
	managementServer *httpTransport.ManagementServer

	// Dynamic listeners (managed via ListenerManager)
	listenerManager *httpTransport.ListenerManager

	// Services
	jwtService    *jwt.Service
	policyService *policy.Service
	cacheService  *cache.Service
	auditService  *audit.Service

	// Resilience components
	rateLimiter    *ratelimit.Limiter
	circuitBreaker *circuitbreaker.Manager

	// Observability
	tracingProvider *tracing.Provider

	// Build info
	buildInfo BuildInfo
}

// Option is a functional option for configuring the App.
type Option func(*App)

// WithBuildInfo sets the build information.
func WithBuildInfo(info BuildInfo) Option {
	return func(a *App) {
		a.buildInfo = info
	}
}

// WithLoader sets the configuration loader for hot-reload support.
func WithLoader(loader *config.Loader) Option {
	return func(a *App) {
		a.loader = loader
	}
}

// New creates a new App instance with the given configuration and options.
func New(cfg *config.Config, opts ...Option) (*App, error) {
	app := &App{
		cfg: cfg,
		buildInfo: BuildInfo{
			Version:   "dev",
			BuildTime: "unknown",
			GitCommit: "unknown",
		},
	}

	// Apply options
	for _, opt := range opts {
		opt(app)
	}

	return app, nil
}

// Initialize initializes all application services.
func (a *App) Initialize(ctx context.Context) error {
	var err error

	// Log security warnings for InsecureSkipVerify settings
	a.logSecurityWarnings()

	// Initialize tracing if enabled
	if a.cfg.Tracing.Enabled {
		tracingCfg := tracing.Config{
			Enabled:        a.cfg.Tracing.Enabled,
			Endpoint:       a.cfg.Tracing.Endpoint,
			Insecure:       a.cfg.Tracing.Insecure,
			ServiceName:    a.cfg.Tracing.ServiceName,
			ServiceVersion: a.cfg.Tracing.ServiceVersion,
			Environment:    a.cfg.Tracing.Environment,
			SampleRate:     a.cfg.Tracing.SampleRate,
		}

		// Parse durations
		if a.cfg.Tracing.BatchTimeout != "" {
			if d, parseErr := time.ParseDuration(a.cfg.Tracing.BatchTimeout); parseErr == nil {
				tracingCfg.BatchTimeout = d
			}
		}
		if a.cfg.Tracing.ExportTimeout != "" {
			if d, parseErr := time.ParseDuration(a.cfg.Tracing.ExportTimeout); parseErr == nil {
				tracingCfg.ExportTimeout = d
			}
		}

		// Use build info for service version if not configured
		if tracingCfg.ServiceVersion == "" && a.buildInfo.Version != "" {
			tracingCfg.ServiceVersion = a.buildInfo.Version
		}

		a.tracingProvider, err = tracing.NewProvider(ctx, tracingCfg)
		if err != nil {
			return fmt.Errorf("failed to initialize tracing: %w", err)
		}
		logger.Info("tracing initialized",
			logger.String("endpoint", a.cfg.Tracing.Endpoint),
			logger.Float64("sample_rate", a.cfg.Tracing.SampleRate),
		)
	}

	// Initialize rate limiter if enabled
	if a.cfg.Resilience.RateLimit.Enabled {
		a.rateLimiter, err = ratelimit.NewLimiter(a.cfg.Resilience.RateLimit)
		if err != nil {
			return fmt.Errorf("failed to create rate limiter: %w", err)
		}
		logger.Info("rate limiter initialized",
			logger.String("rate", a.cfg.Resilience.RateLimit.Rate),
			logger.String("store", a.cfg.Resilience.RateLimit.Store),
		)
	}

	// Initialize circuit breaker manager if enabled
	if a.cfg.Resilience.CircuitBreaker.Enabled {
		a.circuitBreaker = circuitbreaker.NewManager(a.cfg.Resilience.CircuitBreaker)
		logger.Info("circuit breaker manager initialized",
			logger.Int("service_count", len(a.cfg.Resilience.CircuitBreaker.Services)),
		)
	}

	// Initialize cache service
	a.cacheService = cache.NewService(a.cfg.Cache)
	if err := a.cacheService.Start(ctx); err != nil {
		return fmt.Errorf("failed to start cache service: %w", err)
	}

	// Initialize audit service
	a.auditService = audit.NewService(a.cfg.Audit)
	if err := a.auditService.Start(ctx); err != nil {
		return fmt.Errorf("failed to start audit service: %w", err)
	}

	// Initialize JWT service
	a.jwtService = jwt.NewService(a.cfg.JWT)
	if err := a.jwtService.Start(ctx); err != nil {
		return fmt.Errorf("failed to start JWT service: %w", err)
	}

	// Initialize policy service with cache and circuit breaker
	policyOpts := []policy.ServiceOption{}
	if a.cacheService.Enabled() {
		policyOpts = append(policyOpts, policy.WithCache(a.cacheService))
	}

	a.policyService, err = policy.NewService(a.cfg.Policy, policyOpts...)
	if err != nil {
		return fmt.Errorf("failed to create policy service: %w", err)
	}
	if err := a.policyService.Start(ctx); err != nil {
		return fmt.Errorf("failed to start policy service: %w", err)
	}

	// Initialize HTTP server if enabled
	if a.cfg.Server.HTTP.Enabled {
		serverCfg := httpTransport.ServerConfig{
			HTTP:          a.cfg.Server.HTTP,
			Endpoints:     a.cfg.Endpoints,
			Proxy:         a.cfg.Proxy,
			Egress:        a.cfg.Egress,
			Env:           a.cfg.Env,
			TLSClientCert: a.cfg.TLSClientCert,
			RequestBody:   a.cfg.RequestBody,
		}

		serverOpts := []httpTransport.ServerOption{}
		if a.rateLimiter != nil {
			serverOpts = append(serverOpts, httpTransport.WithRateLimiter(a.rateLimiter))
		}
		if a.tracingProvider != nil {
			serverOpts = append(serverOpts, httpTransport.WithTracingProvider(a.tracingProvider))
		}

		a.httpServer, err = httpTransport.NewServer(
			serverCfg,
			a.jwtService,
			a.policyService,
			a.buildInfo.Version,
			serverOpts...,
		)
		if err != nil {
			return fmt.Errorf("failed to create HTTP server: %w", err)
		}
	}

	// Initialize management server if enabled
	if a.cfg.Management.Enabled {
		a.managementServer = httpTransport.NewManagementServer(
			a.cfg.Management,
			a.loader,
			a, // App implements AppInfo interface
			httpTransport.BuildInfo{
				Version:   a.buildInfo.Version,
				BuildTime: a.buildInfo.BuildTime,
				GitCommit: a.buildInfo.GitCommit,
			},
		)
		logger.Info("management server initialized",
			logger.String("admin_addr", a.cfg.Management.AdminAddr),
			logger.String("health_addr", a.cfg.Management.HealthAddr),
			logger.String("ready_addr", a.cfg.Management.ReadyAddr),
		)
	}

	// Initialize listener manager for dynamic listeners (proxy, egress)
	a.listenerManager = httpTransport.NewListenerManager(
		httpTransport.WithShutdownTimeout(30*time.Second),
		httpTransport.WithListenerLogger(logger.L().Named("listeners")),
	)
	logger.Info("listener manager initialized")

	// Connect listener manager to management server for admin API
	if a.managementServer != nil {
		a.managementServer.SetListenerManager(a.listenerManager)
	}

	// Initialize proxy listeners from services configuration
	if err := a.initProxyListeners(ctx); err != nil {
		return fmt.Errorf("failed to initialize proxy listeners: %w", err)
	}

	// Initialize egress listeners from services configuration
	if err := a.initEgressListeners(ctx); err != nil {
		return fmt.Errorf("failed to initialize egress listeners: %w", err)
	}

	logger.Info("application initialized",
		logger.String("version", a.buildInfo.Version),
		logger.String("commit", a.buildInfo.GitCommit),
	)

	return nil
}

// initProxyListeners initializes proxy listeners from the services configuration.
// Each listener is managed by the ListenerManager and can be dynamically updated.
func (a *App) initProxyListeners(ctx context.Context) error {
	// Check if proxy mode is enabled and there are listeners configured
	if !a.cfg.ProxyListeners.Enabled {
		logger.Debug("proxy listeners disabled, skipping initialization")
		return nil
	}

	if len(a.cfg.ProxyListeners.Listeners) == 0 {
		logger.Debug("no proxy listeners configured")
		return nil
	}

	logger.Info("initializing proxy listeners",
		logger.Int("count", len(a.cfg.ProxyListeners.Listeners)),
	)

	for _, listenerCfg := range a.cfg.ProxyListeners.Listeners {
		if err := a.addProxyListener(ctx, listenerCfg); err != nil {
			return fmt.Errorf("failed to add proxy listener %s: %w", listenerCfg.Name, err)
		}
	}

	return nil
}

// addProxyListener adds a single proxy listener to the ListenerManager.
func (a *App) addProxyListener(ctx context.Context, listenerCfg config.ProxyListenerConfig) error {
	// Apply defaults
	if listenerCfg.Bind == "" {
		listenerCfg.Bind = "0.0.0.0"
	}
	if listenerCfg.Timeout == 0 {
		listenerCfg.Timeout = a.cfg.ProxyListeners.Defaults.Timeout
	}

	// Routes are defined directly in listener config
	// Authorization rule_sets are defined in rules.yaml and applied during request processing

	// Create reverse proxy handler for this listener
	proxy, err := httpTransport.NewReverseProxyFromListener(
		listenerCfg,
		a.cfg.Env,
		a.cfg.TLSClientCert,
		a.cfg.RequestBody,
		a.jwtService,
		a.policyService,
	)
	if err != nil {
		return fmt.Errorf("failed to create reverse proxy: %w", err)
	}

	// Determine address
	address := fmt.Sprintf("%s:%d", listenerCfg.Bind, listenerCfg.Port)

	// Wrap handler with metrics middleware
	handler := metrics.WrapWithListenerMetrics(proxy, listenerCfg.Name, "proxy")

	// Add listener to manager
	err = a.listenerManager.AddListener(ctx, httpTransport.ListenerConfig{
		Name:         listenerCfg.Name,
		Type:         httpTransport.ListenerTypeProxy,
		Address:      address,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: listenerCfg.Timeout,
		IdleTimeout:  120 * time.Second,
		Metadata: map[string]string{
			"mode":         listenerCfg.Mode,
			"require_auth": fmt.Sprintf("%t", listenerCfg.RequireAuth),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to add listener to manager: %w", err)
	}

	logger.Info("proxy listener added",
		logger.String("name", listenerCfg.Name),
		logger.String("address", address),
		logger.String("mode", listenerCfg.Mode),
	)

	return nil
}

// initEgressListeners initializes egress listeners from the services configuration.
// Each egress listener handles outgoing requests to external APIs with credential injection.
func (a *App) initEgressListeners(ctx context.Context) error {
	// Check if egress mode is enabled and there are listeners configured
	if !a.cfg.EgressListeners.Enabled {
		logger.Debug("egress listeners disabled, skipping initialization")
		return nil
	}

	if len(a.cfg.EgressListeners.Listeners) == 0 {
		logger.Debug("no egress listeners configured")
		return nil
	}

	logger.Info("initializing egress listeners",
		logger.Int("count", len(a.cfg.EgressListeners.Listeners)),
	)

	for _, listenerCfg := range a.cfg.EgressListeners.Listeners {
		if err := a.addEgressListener(ctx, listenerCfg); err != nil {
			return fmt.Errorf("failed to add egress listener %s: %w", listenerCfg.Name, err)
		}
	}

	return nil
}

// addEgressListener adds a single egress listener to the ListenerManager.
func (a *App) addEgressListener(ctx context.Context, listenerCfg config.EgressListenerConfig) error {
	// Apply defaults
	if listenerCfg.Bind == "" {
		listenerCfg.Bind = "0.0.0.0"
	}

	// Create egress service for this listener
	egressSvc, err := egress.NewServiceFromListener(
		listenerCfg,
		a.cfg.EgressListeners.Defaults,
		a.cfg.EgressListeners.TokenStore,
		logger.L(),
	)
	if err != nil {
		return fmt.Errorf("failed to create egress service: %w", err)
	}

	// Start the egress service
	if err := egressSvc.Start(ctx); err != nil {
		return fmt.Errorf("failed to start egress service: %w", err)
	}

	// Determine address
	address := fmt.Sprintf("%s:%d", listenerCfg.Bind, listenerCfg.Port)

	// Wrap handler with metrics middleware
	handler := metrics.WrapWithListenerMetrics(http.HandlerFunc(egressSvc.ProxyRequest), listenerCfg.Name, "egress")

	// Add listener to manager
	err = a.listenerManager.AddListener(ctx, httpTransport.ListenerConfig{
		Name:         listenerCfg.Name,
		Type:         httpTransport.ListenerTypeEgress,
		Address:      address,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
		Metadata: map[string]string{
			"targets": fmt.Sprintf("%d", len(listenerCfg.Targets)),
			"routes":  fmt.Sprintf("%d", len(listenerCfg.Routes)),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to add listener to manager: %w", err)
	}

	logger.Info("egress listener added",
		logger.String("name", listenerCfg.Name),
		logger.String("address", address),
		logger.Int("targets", len(listenerCfg.Targets)),
	)

	return nil
}

// Start starts all application services.
func (a *App) Start() error {
	// Start HTTP server in goroutine
	if a.httpServer != nil {
		go func() {
			if err := a.httpServer.Start(); err != nil {
				logger.Error("HTTP server error", logger.Err(err))
			}
		}()
	}

	// Start management server in goroutine
	if a.managementServer != nil {
		go func() {
			if err := a.managementServer.Start(); err != nil {
				logger.Error("management server error", logger.Err(err))
			}
		}()
	}

	logger.Info("application started",
		logger.String("http_addr", a.cfg.Server.HTTP.Addr),
	)
	return nil
}

// Shutdown gracefully shuts down all application services.
func (a *App) Shutdown(ctx context.Context) error {
	logger.Info("shutting down application")

	// Shutdown dynamic listeners first (drain active connections)
	if a.listenerManager != nil {
		if err := a.listenerManager.Shutdown(ctx); err != nil {
			logger.Error("failed to shutdown listener manager", logger.Err(err))
		}
	}

	// Shutdown management server (to stop health probes)
	if a.managementServer != nil {
		if err := a.managementServer.Shutdown(ctx); err != nil {
			logger.Error("failed to shutdown management server", logger.Err(err))
		}
	}

	// Shutdown HTTP server
	if a.httpServer != nil {
		if err := a.httpServer.Shutdown(ctx); err != nil {
			logger.Error("failed to shutdown HTTP server", logger.Err(err))
		}
	}

	// Stop JWT service
	if a.jwtService != nil {
		a.jwtService.Stop()
	}

	// Stop policy service
	if a.policyService != nil {
		if err := a.policyService.Stop(); err != nil {
			logger.Error("failed to stop policy service", logger.Err(err))
		}
	}

	// Stop cache service
	if a.cacheService != nil {
		if err := a.cacheService.Stop(); err != nil {
			logger.Error("failed to stop cache service", logger.Err(err))
		}
	}

	// Stop audit service
	if a.auditService != nil {
		if err := a.auditService.Stop(); err != nil {
			logger.Error("failed to stop audit service", logger.Err(err))
		}
	}

	// Shutdown tracing provider (last to capture all spans)
	if a.tracingProvider != nil {
		if err := a.tracingProvider.Shutdown(ctx); err != nil {
			logger.Error("failed to shutdown tracing provider", logger.Err(err))
		}
	}

	logger.Info("application shutdown complete")
	return nil
}

// Healthy returns true if all critical services are healthy.
func (a *App) Healthy(ctx context.Context) bool {
	if a.policyService != nil && !a.policyService.Healthy(ctx) {
		return false
	}
	if a.cacheService != nil && a.cacheService.Enabled() && !a.cacheService.Healthy(ctx) {
		return false
	}
	return true
}

// RateLimiter returns the rate limiter instance.
func (a *App) RateLimiter() *ratelimit.Limiter {
	return a.rateLimiter
}

// CircuitBreaker returns the circuit breaker manager.
func (a *App) CircuitBreaker() *circuitbreaker.Manager {
	return a.circuitBreaker
}

// logSecurityWarnings logs warnings for insecure configurations.
func (a *App) logSecurityWarnings() {
	// Check proxy upstream TLS
	if a.cfg.Proxy.Enabled && a.cfg.Proxy.Upstream.TLS.InsecureSkipVerify {
		logger.Warn("SECURITY WARNING: proxy upstream TLS certificate verification is disabled",
			logger.String("upstream_url", a.cfg.Proxy.Upstream.URL),
			logger.String("setting", "proxy.upstream.tls.insecure_skip_verify"),
		)
	}

	// Check named upstreams TLS
	for name, upstream := range a.cfg.Proxy.Upstreams {
		if upstream.TLS.InsecureSkipVerify {
			logger.Warn("SECURITY WARNING: upstream TLS certificate verification is disabled",
				logger.String("upstream_name", name),
				logger.String("upstream_url", upstream.URL),
				logger.String("setting", fmt.Sprintf("proxy.upstreams.%s.tls.insecure_skip_verify", name)),
			)
		}
	}

	// Check egress targets TLS
	for name, target := range a.cfg.Egress.Targets {
		if target.TLS.InsecureSkipVerify {
			logger.Warn("SECURITY WARNING: egress target TLS certificate verification is disabled",
				logger.String("target_name", name),
				logger.String("target_url", target.URL),
				logger.String("setting", fmt.Sprintf("egress.targets.%s.tls.insecure_skip_verify", name)),
			)
		}
	}
}

// =============================================================================
// AppInfo interface implementation for ManagementServer
// =============================================================================

// GetServices returns health status of all services.
func (a *App) GetServices() []httpTransport.ServiceHealth {
	ctx := context.Background()
	services := []httpTransport.ServiceHealth{}

	// Policy service
	if a.policyService != nil {
		status := "healthy"
		msg := ""
		if !a.policyService.Healthy(ctx) {
			status = "unhealthy"
			msg = "policy engine not ready"
		}
		services = append(services, httpTransport.ServiceHealth{
			Name:    "policy",
			Status:  status,
			Message: msg,
		})
	}

	// Cache service
	if a.cacheService != nil && a.cacheService.Enabled() {
		status := "healthy"
		msg := ""
		if !a.cacheService.Healthy(ctx) {
			status = "unhealthy"
			msg = "cache not available"
		}
		services = append(services, httpTransport.ServiceHealth{
			Name:    "cache",
			Status:  status,
			Message: msg,
		})
	}

	// JWT service
	if a.jwtService != nil {
		services = append(services, httpTransport.ServiceHealth{
			Name:   "jwt",
			Status: "healthy",
		})
	}

	return services
}

// GetListeners returns information about active listeners.
func (a *App) GetListeners() []httpTransport.ListenerInfo {
	listeners := []httpTransport.ListenerInfo{}

	// HTTP server
	if a.httpServer != nil && a.cfg.Server.HTTP.Enabled {
		listeners = append(listeners, httpTransport.ListenerInfo{
			Name:    "http",
			Type:    "http",
			Address: a.cfg.Server.HTTP.Addr,
			Status:  "running",
		})
	}

	// Management servers
	if a.managementServer != nil && a.cfg.Management.Enabled {
		listeners = append(listeners, httpTransport.ListenerInfo{
			Name:    "admin",
			Type:    "management",
			Address: a.cfg.Management.AdminAddr,
			Status:  "running",
		})
		listeners = append(listeners, httpTransport.ListenerInfo{
			Name:    "health",
			Type:    "management",
			Address: a.cfg.Management.HealthAddr,
			Status:  "running",
		})
		listeners = append(listeners, httpTransport.ListenerInfo{
			Name:    "ready",
			Type:    "management",
			Address: a.cfg.Management.ReadyAddr,
			Status:  "running",
		})
	}

	// Dynamic listeners from ListenerManager (proxy, egress)
	if a.listenerManager != nil {
		listeners = append(listeners, a.listenerManager.GetListeners()...)
	}

	return listeners
}

// IsHealthy returns true if the application is healthy.
func (a *App) IsHealthy() bool {
	ctx := context.Background()
	return a.Healthy(ctx)
}

// IsReady returns true if the application is ready to serve traffic.
func (a *App) IsReady() bool {
	ctx := context.Background()

	// Check policy service
	if a.policyService != nil && !a.policyService.Healthy(ctx) {
		return false
	}

	return true
}
