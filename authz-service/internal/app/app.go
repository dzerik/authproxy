// Package app provides application lifecycle management and dependency injection.
package app

import (
	"context"
	"fmt"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/internal/service/audit"
	"github.com/your-org/authz-service/internal/service/cache"
	"github.com/your-org/authz-service/internal/service/jwt"
	"github.com/your-org/authz-service/internal/service/policy"
	httpTransport "github.com/your-org/authz-service/internal/transport/http"
	"github.com/your-org/authz-service/pkg/logger"
	"github.com/your-org/authz-service/pkg/resilience/circuitbreaker"
	"github.com/your-org/authz-service/pkg/resilience/ratelimit"
)

// BuildInfo holds application build information.
type BuildInfo struct {
	Version   string
	BuildTime string
	GitCommit string
}

// App represents the application with all its services and dependencies.
type App struct {
	cfg *config.Config

	// Services
	httpServer    *httpTransport.Server
	jwtService    *jwt.Service
	policyService *policy.Service
	cacheService  *cache.Service
	auditService  *audit.Service

	// Resilience components
	rateLimiter    *ratelimit.Limiter
	circuitBreaker *circuitbreaker.Manager

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

	logger.Info("application initialized",
		logger.String("version", a.buildInfo.Version),
		logger.String("commit", a.buildInfo.GitCommit),
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

	logger.Info("application started",
		logger.String("http_addr", a.cfg.Server.HTTP.Addr),
	)
	return nil
}

// Shutdown gracefully shuts down all application services.
func (a *App) Shutdown(ctx context.Context) error {
	logger.Info("shutting down application")

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
