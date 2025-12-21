package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"go.uber.org/zap"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/handler"
	"github.com/dzerik/auth-portal/internal/help"
	"github.com/dzerik/auth-portal/internal/nginx"
	"github.com/dzerik/auth-portal/internal/schema"
	"github.com/dzerik/auth-portal/internal/service/idp"
	"github.com/dzerik/auth-portal/internal/service/metrics"
	"github.com/dzerik/auth-portal/internal/service/session"
	"github.com/dzerik/auth-portal/internal/ui"
	"github.com/dzerik/auth-portal/pkg/logger"
	"github.com/dzerik/auth-portal/pkg/resilience/ratelimit"
	"github.com/dzerik/auth-portal/pkg/tracing"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
)

func main() {
	// Parse flags
	configPath := flag.String("config", getEnv("AUTH_PORTAL_CONFIG", "/etc/auth-portal/config.yaml"), "Path to configuration file")
	generateNginx := flag.Bool("generate-nginx", false, "Generate nginx config and exit")
	nginxOutput := flag.String("output", getEnv("AUTH_PORTAL_NGINX_CONFIG", "/etc/nginx/nginx.conf"), "Output path for nginx config")
	devMode := flag.Bool("dev", false, "Enable development mode")
	showVersion := flag.Bool("version", false, "Show version and exit")
	showHelp := flag.Bool("help", false, "Show extended help")
	generateSchema := flag.Bool("schema", false, "Generate JSON schema and exit")
	schemaOutput := flag.String("schema-output", "", "Output file for schema (default: stdout)")
	flag.Parse()

	// Create help generator
	helpGen := help.NewGenerator(help.AppInfo{
		Name:        "auth-portal",
		Description: "Authentication portal with Keycloak OIDC integration",
		Version:     Version,
		BuildTime:   BuildTime,
		DocsURL:     "https://github.com/dzerik/auth-portal",
	}, "AUTH_PORTAL")

	// Show version
	if *showVersion {
		fmt.Print(helpGen.PrintVersion())
		os.Exit(0)
	}

	// Show extended help
	if *showHelp {
		fmt.Print(helpGen.PrintExtendedHelp())
		os.Exit(0)
	}

	// Generate JSON schema
	if *generateSchema {
		gen := schema.NewGenerator()
		data, err := gen.Generate()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to generate schema: %v\n", err)
			os.Exit(1)
		}

		if *schemaOutput != "" {
			if err := os.WriteFile(*schemaOutput, data, 0644); err != nil {
				fmt.Fprintf(os.Stderr, "failed to write schema: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Schema written to %s\n", *schemaOutput)
		} else {
			fmt.Println(string(data))
		}
		os.Exit(0)
	}

	// Initialize logger early with minimal config
	logCfg := logger.DefaultConfig()
	if *devMode || os.Getenv("DEV_MODE") == "true" {
		logCfg.Level = "debug"
		logCfg.Development = true
	}
	if err := logger.Init(logCfg); err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("starting auth-portal",
		zap.String("version", Version),
		zap.Bool("dev_mode", *devMode),
	)

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load configuration",
			zap.Error(err),
			zap.String("path", *configPath),
		)
		os.Exit(1)
	}

	// Override dev mode from flag
	if *devMode {
		cfg.DevMode.Enabled = true
	}

	// Reinitialize logger with config settings
	if cfg.Log.Level != "" || cfg.Log.Development {
		logCfg.Level = cfg.Log.Level
		logCfg.Development = cfg.Log.Development || cfg.DevMode.Enabled
		logger.SetLevel(logCfg.Level)
	}

	logger.Info("configuration loaded",
		zap.String("path", *configPath),
		zap.String("mode", cfg.Mode),
		zap.Bool("dev_mode", cfg.DevMode.Enabled),
	)

	// Validate configuration
	if err := config.Validate(cfg); err != nil {
		logger.Error("configuration validation failed", zap.Error(err))
		os.Exit(1)
	}

	// Generate nginx config if requested
	if *generateNginx {
		if err := generateNginxConfig(cfg, *nginxOutput); err != nil {
			logger.Error("failed to generate nginx config", zap.Error(err))
			os.Exit(1)
		}
		logger.Info("nginx config generated successfully", zap.String("output", *nginxOutput))
		os.Exit(0)
	}

	// Create metrics
	m := metrics.New()

	// Initialize tracing
	var tp *tracing.TracerProvider
	if cfg.Observability.Tracing.Enabled {
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

		var err error
		tp, err = tracing.Init(context.Background(), tracingCfg)
		if err != nil {
			logger.Error("failed to initialize tracing", zap.Error(err))
			// Continue without tracing
		} else {
			logger.Info("tracing initialized",
				zap.String("endpoint", tracingCfg.Endpoint),
				zap.String("protocol", tracingCfg.Protocol),
			)
		}
	}

	// Create and start server
	srv, healthHandler, err := NewServer(cfg, m, tp)
	if err != nil {
		logger.Error("failed to create server", zap.Error(err))
		os.Exit(1)
	}

	// Start server in goroutine
	go func() {
		addr := fmt.Sprintf(":%d", cfg.Server.HTTPPort)
		logger.Info("starting HTTP server", zap.String("addr", addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", zap.Error(err))
			os.Exit(1)
		}
	}()

	// Mark as ready after startup
	time.AfterFunc(1*time.Second, func() {
		healthHandler.SetReady(true)
		logger.Info("service is ready")
	})

	// Wait for interrupt signal
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
		os.Exit(1)
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

// getEnvironment returns the environment name based on config.
func getEnvironment(cfg *config.Config) string {
	if cfg.DevMode.Enabled {
		return "development"
	}
	return "production"
}

// NewServer creates a new HTTP server with chi router and all handlers.
func NewServer(cfg *config.Config, m *metrics.Metrics, tp *tracing.TracerProvider) (*http.Server, *handler.HealthHandler, error) {
	// Load templates
	templates, err := ui.LoadTemplates()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load templates: %w", err)
	}

	// Create session manager
	sessionMgr, err := session.NewManager(&cfg.Session)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create session manager: %w", err)
	}
	logger.Info("session manager created", zap.String("store", sessionMgr.StoreName()))

	// Create IdP manager
	var devCfg *config.DevModeConfig
	if cfg.DevMode.Enabled {
		devCfg = &cfg.DevMode
	}
	idpMgr, err := idp.NewManager(&cfg.Auth, cfg.DevMode.Enabled, devCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create IdP manager: %w", err)
	}
	logger.Info("IdP manager created", zap.String("provider", idpMgr.Provider().Name()))

	// Create handlers
	authHandler := handler.NewAuthHandler(idpMgr, sessionMgr, cfg, templates)
	portalHandler := handler.NewPortalHandler(sessionMgr, cfg, templates)
	forwardAuthHandler := handler.NewForwardAuthHandler(sessionMgr, idpMgr, cfg)
	healthHandler := handler.NewHealthHandler(cfg, nil) // No nginx manager in Go process

	// Setup chi router
	r := chi.NewRouter()

	// Global middleware stack
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)

	// Add tracing middleware if enabled
	if tp != nil {
		r.Use(tracing.Middleware)
	}

	r.Use(logger.RequestLogger)  // Zap-based request logging
	r.Use(logger.RecoveryLogger) // Zap-based panic recovery
	r.Use(chimw.CleanPath)
	r.Use(chimw.Timeout(60 * time.Second))
	r.Use(m.Middleware) // Prometheus metrics

	// Add rate limiting if enabled
	if cfg.Resilience.RateLimit.Enabled {
		rateLimitCfg := ratelimit.Config{
			Enabled:           cfg.Resilience.RateLimit.Enabled,
			Rate:              cfg.Resilience.RateLimit.Rate,
			TrustForwardedFor: cfg.Resilience.RateLimit.TrustForwardedFor,
			ExcludePaths:      cfg.Resilience.RateLimit.ExcludePaths,
			ByEndpoint:        cfg.Resilience.RateLimit.ByEndpoint,
			EndpointRates:     cfg.Resilience.RateLimit.EndpointRates,
			Headers: ratelimit.HeadersConfig{
				Enabled:         cfg.Resilience.RateLimit.Headers.Enabled,
				LimitHeader:     cfg.Resilience.RateLimit.Headers.LimitHeader,
				RemainingHeader: cfg.Resilience.RateLimit.Headers.RemainingHeader,
				ResetHeader:     cfg.Resilience.RateLimit.Headers.ResetHeader,
			},
			FailClose: cfg.Resilience.RateLimit.FailClose,
		}
		limiter, err := ratelimit.NewLimiter(rateLimitCfg)
		if err != nil {
			logger.Error("failed to create rate limiter", zap.Error(err))
		} else {
			r.Use(limiter.Middleware())
			logger.Info("rate limiting enabled", zap.String("rate", cfg.Resilience.RateLimit.Rate))
		}
	}

	// CORS configuration
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Request-ID"},
		ExposedHeaders:   []string{"Link", "X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Static files
	r.Handle("/static/*", ui.StaticFileHandler())

	// Auth routes (public)
	r.Group(func(r chi.Router) {
		r.Get("/", authHandler.HandleRoot)
		r.Get("/login", authHandler.HandleLogin)
		r.Get("/login/keycloak", authHandler.HandleLoginKeycloak)
		r.Get("/login/social/{provider}", authHandler.HandleLoginSocial)
		r.Get("/login/dev/{profile}", authHandler.HandleLoginDevProfile)
		r.Get("/callback", authHandler.HandleCallback)
		r.Get("/logout", authHandler.HandleLogout)
		r.Post("/logout", authHandler.HandleLogout)
	})

	// User info (requires session but not full auth)
	r.Group(func(r chi.Router) {
		r.Use(sessionMgr.Middleware)
		r.Get("/userinfo", authHandler.HandleUserInfo)
		r.Get("/session", authHandler.HandleSessionInfo)
	})

	// Portal routes (requires auth)
	r.Group(func(r chi.Router) {
		r.Use(sessionMgr.Middleware)
		r.Use(authHandler.RequireAuthMiddleware)
		r.Get("/portal", portalHandler.HandlePortal)
		r.Get("/service/{service}", portalHandler.HandleServiceRedirect)
	})

	// API routes (requires auth, returns JSON errors)
	r.Route("/api", func(r chi.Router) {
		r.Use(sessionMgr.Middleware)
		r.Use(authHandler.RequireAuthJSONMiddleware)
		r.Get("/services", portalHandler.HandleServices)
	})

	// Forward auth endpoints
	r.Route("/auth", func(r chi.Router) {
		r.Use(sessionMgr.Middleware)
		r.Get("/", forwardAuthHandler.HandleAuth)
		r.Get("/redirect", forwardAuthHandler.HandleAuthWithRedirect)
		r.Get("/verify", forwardAuthHandler.HandleVerify)
		r.Post("/introspect", forwardAuthHandler.HandleIntrospect)
	})

	// Health endpoints (no auth required)
	r.Get("/health", healthHandler.HandleHealth)
	r.Get("/ready", healthHandler.HandleReady)

	// Metrics endpoint
	if cfg.Observability.Metrics.Enabled {
		metricsPath := cfg.Observability.Metrics.Path
		if metricsPath == "" {
			metricsPath = "/metrics"
		}
		r.Handle(metricsPath, m.Handler())
	}

	// Admin endpoints
	r.Route("/admin", func(r chi.Router) {
		// Schema endpoint (always available)
		r.Get("/schema", func(w http.ResponseWriter, req *http.Request) {
			gen := schema.NewGenerator()
			data, err := gen.Generate()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(data)
		})

		// Config dump (dev mode only)
		if cfg.DevMode.Enabled {
			r.Handle("/log/level", logger.LevelHandler())

			r.Get("/config", func(w http.ResponseWriter, req *http.Request) {
				// Return sanitized config (no secrets)
				sanitized := struct {
					Mode        string `json:"mode"`
					DevMode     bool   `json:"dev_mode"`
					HTTPPort    int    `json:"http_port"`
					SessionType string `json:"session_type"`
					Services    int    `json:"services_count"`
				}{
					Mode:        cfg.Mode,
					DevMode:     cfg.DevMode.Enabled,
					HTTPPort:    cfg.Server.HTTPPort,
					SessionType: cfg.Session.Store,
					Services:    len(cfg.Services),
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(sanitized)
			})

			r.Get("/info", func(w http.ResponseWriter, req *http.Request) {
				info := map[string]interface{}{
					"version":    Version,
					"build_time": BuildTime,
					"mode":       cfg.Mode,
					"dev_mode":   cfg.DevMode.Enabled,
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(info)
			})
		}
	})

	return &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.HTTPPort),
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}, healthHandler, nil
}

// generateNginxConfig generates nginx configuration from YAML.
func generateNginxConfig(cfg *config.Config, outputPath string) error {
	generator, err := nginx.NewGenerator(cfg, "")
	if err != nil {
		return fmt.Errorf("failed to create nginx generator: %w", err)
	}

	return generator.GenerateToFile(outputPath)
}

// getEnv returns environment variable value or default.
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
