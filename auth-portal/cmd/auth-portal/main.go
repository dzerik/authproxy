package main

import (
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/nginx"
	"github.com/dzerik/auth-portal/internal/service/metrics"
	"github.com/dzerik/auth-portal/internal/service/security"
	"github.com/dzerik/auth-portal/pkg/logger"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// run is the main application entry point with proper error handling.
func run() error {
	// Parse CLI flags
	opts := parseFlags()

	// Handle informational commands (version, help, schema)
	if handled := handleInfoCommands(opts); handled {
		return nil
	}

	// Initialize logger
	if err := initLogger(opts.devMode); err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer logger.Sync()

	logger.Info("starting auth-portal",
		zap.String("version", Version),
		zap.Bool("dev_mode", opts.devMode),
	)

	// Load and validate configuration
	cfg, err := loadAndValidateConfig(opts.configPath, opts.devMode)
	if err != nil {
		return err
	}

	// Check security configuration
	securityWarnings := checkSecurity(cfg)

	// Handle nginx config generation
	if opts.generateNginx {
		return generateNginxConfig(cfg, opts.nginxOutput)
	}

	// Run the server
	return runServer(cfg, securityWarnings)
}

// initLogger initializes the logger with appropriate settings.
func initLogger(devMode bool) error {
	logCfg := logger.DefaultConfig()
	if devMode || os.Getenv("DEV_MODE") == "true" {
		logCfg.Level = "debug"
		logCfg.Development = true
	}
	return logger.Init(logCfg)
}

// loadAndValidateConfig loads and validates configuration.
func loadAndValidateConfig(configPath string, devMode bool) (*config.Config, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Error("failed to load configuration",
			zap.Error(err),
			zap.String("path", configPath),
		)
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	// Override dev mode from flag
	if devMode {
		cfg.DevMode.Enabled = true
	}

	// Reinitialize logger with config settings
	if cfg.Log.Level != "" || cfg.Log.Development {
		logger.SetLevel(cfg.Log.Level)
	}

	logger.Info("configuration loaded",
		zap.String("path", configPath),
		zap.String("mode", cfg.Mode),
		zap.Bool("dev_mode", cfg.DevMode.Enabled),
	)

	// Validate configuration
	if err := config.Validate(cfg); err != nil {
		logger.Error("configuration validation failed", zap.Error(err))
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}

// checkSecurity checks for security issues and logs warnings.
func checkSecurity(cfg *config.Config) []security.Warning {
	checker := security.NewChecker(cfg)
	warnings := checker.Check()

	if len(warnings) > 0 {
		logger.Warn("security issues detected in configuration",
			zap.Int("total_warnings", len(warnings)),
			zap.String("summary", security.FormatSummary(warnings)),
		)
		for _, w := range warnings {
			logFunc := logger.Warn
			if w.Severity == security.SeverityCritical {
				logFunc = logger.Error
			}
			logFunc("security warning",
				zap.String("code", w.Code),
				zap.String("severity", string(w.Severity)),
				zap.String("title", w.Title),
				zap.String("service", w.Service),
				zap.String("recommendation", w.Recommendation),
			)
		}
	} else {
		logger.Info("security check passed - no issues found")
	}

	return warnings
}

// generateNginxConfig generates nginx configuration file.
func generateNginxConfig(cfg *config.Config, outputPath string) error {
	generator, err := nginx.NewGenerator(cfg, "")
	if err != nil {
		logger.Error("failed to create nginx generator", zap.Error(err))
		return fmt.Errorf("failed to create nginx generator: %w", err)
	}

	if err := generator.GenerateToFile(outputPath); err != nil {
		logger.Error("failed to generate nginx config", zap.Error(err))
		return err
	}

	logger.Info("nginx config generated successfully", zap.String("output", outputPath))
	return nil
}

// runServer starts the HTTP server and handles graceful shutdown.
func runServer(cfg *config.Config, securityWarnings []security.Warning) error {
	// Create metrics
	m := metrics.New()

	// Initialize tracing
	tp := initTracing(cfg)

	// Create server
	srv, healthHandler, err := NewServer(cfg, m, tp, securityWarnings)
	if err != nil {
		logger.Error("failed to create server", zap.Error(err))
		return fmt.Errorf("failed to create server: %w", err)
	}

	// Start server in goroutine
	go startHTTPServer(srv, cfg.Server.HTTPPort)

	// Mark as ready after startup delay
	time.AfterFunc(1*time.Second, func() {
		healthHandler.SetReady(true)
		logger.Info("service is ready")
	})

	// Wait for shutdown signal
	waitForShutdown(srv, healthHandler, tp)

	return nil
}
