package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/internal/service/audit"
	"github.com/your-org/authz-service/internal/service/cache"
	"github.com/your-org/authz-service/internal/service/jwt"
	"github.com/your-org/authz-service/internal/service/policy"
	httpTransport "github.com/your-org/authz-service/internal/transport/http"
	"github.com/your-org/authz-service/pkg/logger"
)

var (
	// Version is set during build
	Version = "dev"
	// BuildTime is set during build
	BuildTime = "unknown"
	// GitCommit is set during build
	GitCommit = "unknown"
)

func main() {
	// Parse flags
	configPath := flag.String("config", "", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Show version information")
	flag.Parse()

	if *showVersion {
		fmt.Printf("authz-service %s\n", Version)
		fmt.Printf("Build time: %s\n", BuildTime)
		fmt.Printf("Git commit: %s\n", GitCommit)
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	if err := logger.Init(cfg.Logging); err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("starting authz-service",
		logger.String("version", Version),
		logger.String("commit", GitCommit),
	)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize services
	app, err := initializeApp(ctx, cfg)
	if err != nil {
		logger.Fatal("failed to initialize application", logger.Err(err))
	}

	// Start the application
	if err := app.Start(); err != nil {
		logger.Fatal("failed to start application", logger.Err(err))
	}

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	logger.Info("received shutdown signal", logger.String("signal", sig.String()))

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := app.Shutdown(shutdownCtx); err != nil {
		logger.Error("error during shutdown", logger.Err(err))
	}

	logger.Info("authz-service stopped")
}

// App represents the application.
type App struct {
	httpServer    *httpTransport.Server
	jwtService    *jwt.Service
	policyService *policy.Service
	cacheService  *cache.Service
	auditService  *audit.Service
}

// initializeApp creates and initializes all application components.
func initializeApp(ctx context.Context, cfg *config.Config) (*App, error) {
	// Initialize cache service
	cacheService := cache.NewService(cfg.Cache)
	if err := cacheService.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start cache service: %w", err)
	}

	// Initialize audit service
	auditService := audit.NewService(cfg.Audit)
	if err := auditService.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start audit service: %w", err)
	}

	// Initialize JWT service
	jwtService := jwt.NewService(cfg.JWT)
	if err := jwtService.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start JWT service: %w", err)
	}

	// Initialize policy service with cache
	policyOpts := []policy.ServiceOption{}
	if cacheService.Enabled() {
		policyOpts = append(policyOpts, policy.WithCache(cacheService))
	}

	policyService, err := policy.NewService(cfg.Policy, policyOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy service: %w", err)
	}
	if err := policyService.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start policy service: %w", err)
	}

	// Initialize HTTP server
	var httpServer *httpTransport.Server
	if cfg.Server.HTTP.Enabled {
		serverCfg := httpTransport.ServerConfig{
			HTTP:      cfg.Server.HTTP,
			Endpoints: cfg.Endpoints,
			Proxy:     cfg.Proxy,
		}
		httpServer, err = httpTransport.NewServer(
			serverCfg,
			jwtService,
			policyService,
			Version,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP server: %w", err)
		}
	}

	return &App{
		httpServer:    httpServer,
		jwtService:    jwtService,
		policyService: policyService,
		cacheService:  cacheService,
		auditService:  auditService,
	}, nil
}

// Start starts all application components.
func (a *App) Start() error {
	// Start HTTP server in goroutine
	if a.httpServer != nil {
		go func() {
			if err := a.httpServer.Start(); err != nil {
				logger.Error("HTTP server error", logger.Err(err))
			}
		}()
	}

	logger.Info("application started")
	return nil
}

// Shutdown gracefully shuts down all application components.
func (a *App) Shutdown(ctx context.Context) error {
	// Shutdown HTTP server
	if a.httpServer != nil {
		if err := a.httpServer.Shutdown(ctx); err != nil {
			logger.Error("failed to shutdown HTTP server", logger.Err(err))
		}
	}

	// Stop JWT service
	a.jwtService.Stop()

	// Stop policy service
	if err := a.policyService.Stop(); err != nil {
		logger.Error("failed to stop policy service", logger.Err(err))
	}

	// Stop cache service
	if err := a.cacheService.Stop(); err != nil {
		logger.Error("failed to stop cache service", logger.Err(err))
	}

	// Stop audit service
	if err := a.auditService.Stop(); err != nil {
		logger.Error("failed to stop audit service", logger.Err(err))
	}

	return nil
}
