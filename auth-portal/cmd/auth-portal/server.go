package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/handler"
	"github.com/dzerik/auth-portal/internal/service/idp"
	"github.com/dzerik/auth-portal/internal/service/metrics"
	"github.com/dzerik/auth-portal/internal/service/security"
	"github.com/dzerik/auth-portal/internal/service/session"
	"github.com/dzerik/auth-portal/internal/service/state"
	"github.com/dzerik/auth-portal/internal/ui"
	"github.com/dzerik/auth-portal/pkg/logger"
	"github.com/dzerik/auth-portal/pkg/tracing"
)

// NewServer creates a new HTTP server with chi router and all handlers.
func NewServer(cfg *config.Config, m *metrics.Metrics, tp *tracing.TracerProvider, securityWarnings []security.Warning) (*http.Server, *handler.HealthHandler, error) {
	// Create core dependencies
	deps, err := createDependencies(cfg, m, tp, securityWarnings)
	if err != nil {
		return nil, nil, err
	}

	// Setup router with all routes
	router := SetupRouter(deps)

	return &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.HTTPPort),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}, deps.HealthHandler, nil
}

// createDependencies initializes all server dependencies.
func createDependencies(cfg *config.Config, m *metrics.Metrics, tp *tracing.TracerProvider, securityWarnings []security.Warning) (*RouterDeps, error) {
	// Load templates
	templates, err := ui.LoadTemplates()
	if err != nil {
		return nil, fmt.Errorf("failed to load templates: %w", err)
	}

	// Create session manager
	sessionMgr, err := session.NewManager(&cfg.Session)
	if err != nil {
		return nil, fmt.Errorf("failed to create session manager: %w", err)
	}
	logger.Info("session manager created", zap.String("store", sessionMgr.StoreName()))

	// Create IdP manager
	idpMgr, err := createIDPManager(cfg)
	if err != nil {
		return nil, err
	}

	// Create state store (CRIT-02 security fix: supports Redis for HA)
	stateStore, err := createStateStore(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create state store: %w", err)
	}
	logger.Info("state store created", zap.String("type", stateStore.Name()))

	// Create handlers
	authHandler := handler.NewAuthHandler(idpMgr, sessionMgr, cfg, templates, stateStore)
	portalHandler := handler.NewPortalHandler(sessionMgr, cfg, templates,
		handler.WithSecurityWarnings(securityWarnings),
	)
	forwardAuthHandler := handler.NewForwardAuthHandler(sessionMgr, idpMgr, cfg)
	healthHandler := handler.NewHealthHandler(cfg, nil) // No nginx manager in Go process

	return &RouterDeps{
		Config:             cfg,
		Metrics:            m,
		TracerProvider:     tp,
		SessionMgr:         sessionMgr,
		AuthHandler:        authHandler,
		PortalHandler:      portalHandler,
		ForwardAuthHandler: forwardAuthHandler,
		HealthHandler:      healthHandler,
	}, nil
}

// createIDPManager creates an IdP manager based on config.
func createIDPManager(cfg *config.Config) (*idp.Manager, error) {
	var devCfg *config.DevModeConfig
	if cfg.DevMode.Enabled {
		devCfg = &cfg.DevMode
	}

	idpMgr, err := idp.NewManager(&cfg.Auth, cfg.DevMode.Enabled, devCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create IdP manager: %w", err)
	}
	logger.Info("IdP manager created", zap.String("provider", idpMgr.Provider().Name()))

	return idpMgr, nil
}

// createStateStore creates a state store based on configuration.
// CRIT-02 security fix: supports Redis for high-availability deployments.
func createStateStore(cfg *config.Config) (state.Store, error) {
	switch cfg.StateStore.Type {
	case "redis":
		redisCfg := state.Config{
			Type: "redis",
			TTL:  cfg.StateStore.TTL,
			Redis: state.RedisConfig{
				KeyPrefix: cfg.StateStore.Redis.KeyPrefix,
			},
		}

		// Use session Redis config if UseSessionRedis is true
		if cfg.StateStore.Redis.UseSessionRedis {
			redisCfg.Redis.Addresses = cfg.Session.Redis.Addresses
			redisCfg.Redis.Password = cfg.Session.Redis.Password
			redisCfg.Redis.DB = cfg.Session.Redis.DB
			redisCfg.Redis.MasterName = cfg.Session.Redis.MasterName
		}

		return state.NewRedisStore(redisCfg)

	case "memory", "":
		return state.NewMemoryStore(cfg.StateStore.TTL), nil

	default:
		return nil, fmt.Errorf("unknown state store type: %s", cfg.StateStore.Type)
	}
}

// initTracing initializes OpenTelemetry tracing if enabled.
func initTracing(cfg *config.Config) *tracing.TracerProvider {
	if !cfg.Observability.Tracing.Enabled {
		return nil
	}

	tracingCfg := tracing.Config{
		Enabled:        true,
		ServiceName:    "auth-portal",
		ServiceVersion: Version,
		Environment:    getEnvironment(cfg),
		Endpoint:       cfg.Observability.Tracing.Endpoint,
		Protocol:       cfg.Observability.Tracing.Protocol,
		Insecure:       cfg.Observability.Tracing.Insecure,
		SamplingRatio:  cfg.Observability.Tracing.SamplingRatio,
		Headers:        cfg.Observability.Tracing.Headers,
	}

	tp, err := tracing.Init(context.Background(), tracingCfg)
	if err != nil {
		logger.Error("failed to initialize tracing", zap.Error(err))
		return nil
	}

	logger.Info("tracing initialized",
		zap.String("endpoint", tracingCfg.Endpoint),
		zap.String("protocol", tracingCfg.Protocol),
	)

	return tp
}

// startHTTPServer starts HTTP server and handles errors.
func startHTTPServer(srv *http.Server, port int) {
	logger.Info("starting HTTP server", zap.Int("port", port))
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server error", zap.Error(err))
		os.Exit(1)
	}
}

// waitForShutdown waits for shutdown signal and performs graceful shutdown.
func waitForShutdown(srv *http.Server, healthHandler interface{ SetReady(bool) }, tp *tracing.TracerProvider) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down server...")

	// Mark as not ready
	healthHandler.SetReady(false)

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("server shutdown error", zap.Error(err))
	}

	// Shutdown tracing
	if tp != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := tp.Shutdown(shutdownCtx); err != nil {
			logger.Error("tracing shutdown error", zap.Error(err))
		}
	}

	logger.Info("server stopped")
}
