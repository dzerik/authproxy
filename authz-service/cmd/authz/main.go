package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/your-org/authz-service/internal/app"
	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/internal/help"
	"github.com/your-org/authz-service/internal/schema"
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

const (
	appName        = "authz-service"
	appDescription = "Authorization service with JWT validation, policy evaluation, and proxy capabilities"
	envVarPrefix   = "AUTHZ"
	docsURL        = "https://github.com/your-org/authz-service"
)

// helpGenerator is initialized at startup for generating help text.
var helpGenerator *help.Generator

func main() {
	// Initialize help generator
	helpGenerator = help.NewGenerator(help.AppInfo{
		Name:        appName,
		Description: appDescription,
		Version:     Version,
		BuildTime:   BuildTime,
		GitCommit:   GitCommit,
		DocsURL:     docsURL,
	}, envVarPrefix)

	// Extract env vars from config structure for help generation
	helpGenerator.ExtractEnvVars(config.Config{})

	// Define flags
	configPath := flag.String("config", "", "Path to configuration file (YAML)")
	showVersion := flag.Bool("version", false, "Show version information")
	showHelp := flag.Bool("help", false, "Show detailed help")
	showHelpShort := flag.Bool("h", false, "Show detailed help")
	showHelpEnv := flag.Bool("help-env", false, "Show all environment variables")
	generateSchema := flag.String("schema", "", "Generate JSON Schema (config, rules)")
	schemaOutput := flag.String("schema-output", "", "Output file for schema (default: stdout)")
	validateConfig := flag.Bool("validate", false, "Validate configuration and exit")
	dryRun := flag.Bool("dry-run", false, "Validate configuration, test connections, and exit")

	// Custom usage function
	flag.Usage = printUsage

	flag.Parse()

	// Handle help-env (show only environment variables)
	if *showHelpEnv {
		fmt.Print(helpGenerator.PrintEnvVars())
		os.Exit(0)
	}

	// Handle help
	if *showHelp || *showHelpShort {
		fmt.Print(helpGenerator.PrintExtendedHelp())
		os.Exit(0)
	}

	// Handle version
	if *showVersion {
		fmt.Print(helpGenerator.PrintVersion())
		os.Exit(0)
	}

	// Handle schema generation
	if *generateSchema != "" {
		if err := handleSchemaGeneration(*generateSchema, *schemaOutput); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to load configuration: %v\n", err)
		fmt.Fprintf(os.Stderr, "\nUse --help for configuration options\n")
		os.Exit(1)
	}

	// Handle validate-only mode
	if *validateConfig {
		fmt.Println("Configuration is valid")
		os.Exit(0)
	}

	// Initialize logger
	if err := logger.Init(cfg.Logging); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	// Initialize sensitive data masker
	logger.InitMasker(logger.SensitiveDataConfig{
		Enabled:   cfg.SensitiveData.Enabled,
		MaskValue: cfg.SensitiveData.MaskValue,
		Fields:    cfg.SensitiveData.Fields,
		Headers:   cfg.SensitiveData.Headers,
		MaskJWT:   cfg.SensitiveData.MaskJWT,
		PartialMask: logger.PartialMaskConfig{
			Enabled:   cfg.SensitiveData.PartialMask.Enabled,
			ShowFirst: cfg.SensitiveData.PartialMask.ShowFirst,
			ShowLast:  cfg.SensitiveData.PartialMask.ShowLast,
			MinLength: cfg.SensitiveData.PartialMask.MinLength,
		},
	})

	logger.Info("starting "+appName,
		logger.String("version", Version),
		logger.String("commit", GitCommit),
	)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create application with build info
	buildInfo := app.BuildInfo{
		Version:   Version,
		BuildTime: BuildTime,
		GitCommit: GitCommit,
	}

	application, err := app.New(cfg, app.WithBuildInfo(buildInfo))
	if err != nil {
		logger.Fatal("failed to create application", logger.Err(err))
	}

	// Initialize application services
	if err := application.Initialize(ctx); err != nil {
		logger.Fatal("failed to initialize application", logger.Err(err))
	}

	// Handle dry-run mode
	if *dryRun {
		logger.Info("dry-run mode: configuration and services validated successfully")
		if err := application.Shutdown(ctx); err != nil {
			logger.Warn("error during dry-run shutdown", logger.Err(err))
		}
		os.Exit(0)
	}

	// Start the application
	if err := application.Start(); err != nil {
		logger.Fatal("failed to start application", logger.Err(err))
	}

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	logger.Info("received shutdown signal", logger.String("signal", sig.String()))

	// Graceful shutdown with configurable timeout
	shutdownTimeout := cfg.Server.HTTP.ShutdownTimeout
	if shutdownTimeout == 0 {
		shutdownTimeout = 30 * time.Second
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()

	if err := application.Shutdown(shutdownCtx); err != nil {
		logger.Error("error during shutdown", logger.Err(err))
	}

	logger.Info(appName + " stopped")
}

// printUsage prints basic usage.
func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", appName)
	fmt.Fprintf(os.Stderr, "%s\n\n", appDescription)
	fmt.Fprintf(os.Stderr, "Options:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nUse --help for detailed configuration documentation\n")
}

// handleSchemaGeneration generates and outputs the requested schema.
func handleSchemaGeneration(schemaType, outputPath string) error {
	st, ok := schema.ParseSchemaType(schemaType)
	if !ok {
		available := make([]string, 0)
		for _, s := range schema.GetAvailableSchemas() {
			available = append(available, string(s))
		}
		return fmt.Errorf("unknown schema type: %q. Available: %s", schemaType, strings.Join(available, ", "))
	}

	gen := schema.NewGenerator()
	data, err := gen.Generate(st)
	if err != nil {
		return fmt.Errorf("failed to generate schema: %w", err)
	}

	// Output to file or stdout
	if outputPath != "" {
		if err := os.WriteFile(outputPath, data, 0644); err != nil {
			return fmt.Errorf("failed to write schema to %s: %w", outputPath, err)
		}
		fmt.Fprintf(os.Stderr, "Schema written to: %s\n", outputPath)
	} else {
		fmt.Println(string(data))
	}

	return nil
}
