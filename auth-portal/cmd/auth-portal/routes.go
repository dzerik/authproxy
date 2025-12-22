package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"go.uber.org/zap"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/handler"
	"github.com/dzerik/auth-portal/internal/schema"
	"github.com/dzerik/auth-portal/internal/service/metrics"
	"github.com/dzerik/auth-portal/internal/service/session"
	"github.com/dzerik/auth-portal/internal/ui"
	"github.com/dzerik/auth-portal/pkg/logger"
	"github.com/dzerik/auth-portal/pkg/resilience/ratelimit"
	"github.com/dzerik/auth-portal/pkg/tracing"
)

// RouterDeps contains dependencies for router setup.
type RouterDeps struct {
	Config             *config.Config
	Metrics            *metrics.Metrics
	TracerProvider     *tracing.TracerProvider
	SessionMgr         *session.Manager
	AuthHandler        *handler.AuthHandler
	PortalHandler      *handler.PortalHandler
	ForwardAuthHandler *handler.ForwardAuthHandler
	HealthHandler      *handler.HealthHandler
}

// SetupRouter creates and configures chi router with all middleware and routes.
func SetupRouter(deps *RouterDeps) chi.Router {
	r := chi.NewRouter()

	// Apply global middleware
	applyGlobalMiddleware(r, deps)

	// Register routes
	registerStaticRoutes(r)
	registerAuthRoutes(r, deps)
	registerUserRoutes(r, deps)
	registerPortalRoutes(r, deps)
	registerAPIRoutes(r, deps)
	registerForwardAuthRoutes(r, deps)
	registerHealthRoutes(r, deps)
	registerMetricsRoutes(r, deps)
	registerAdminRoutes(r, deps)

	return r
}

// applyGlobalMiddleware applies middleware stack to router.
func applyGlobalMiddleware(r chi.Router, deps *RouterDeps) {
	cfg := deps.Config

	// Core middleware
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)

	// Tracing middleware
	if deps.TracerProvider != nil {
		r.Use(tracing.Middleware)
	}

	// Logging middleware
	r.Use(logger.RequestLogger)
	r.Use(logger.RecoveryLogger)
	r.Use(chimw.CleanPath)
	r.Use(chimw.Timeout(60 * time.Second))
	r.Use(deps.Metrics.Middleware)

	// Rate limiting
	if cfg.Resilience.RateLimit.Enabled {
		limiter := createRateLimiter(cfg)
		if limiter != nil {
			r.Use(limiter.Middleware())
			logger.Info("rate limiting enabled", zap.String("rate", cfg.Resilience.RateLimit.Rate))
		}
	}

	// CORS
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Request-ID"},
		ExposedHeaders:   []string{"Link", "X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           300,
	}))
}

// createRateLimiter creates rate limiter from config.
func createRateLimiter(cfg *config.Config) *ratelimit.Limiter {
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
		return nil
	}
	return limiter
}

// registerStaticRoutes registers static file handlers.
func registerStaticRoutes(r chi.Router) {
	r.Handle("/static/*", ui.StaticFileHandler())
}

// registerAuthRoutes registers authentication routes (public).
func registerAuthRoutes(r chi.Router, deps *RouterDeps) {
	r.Group(func(r chi.Router) {
		r.Get("/", deps.AuthHandler.HandleRoot)
		r.Get("/login", deps.AuthHandler.HandleLogin)
		r.Get("/login/keycloak", deps.AuthHandler.HandleLoginKeycloak)
		r.Get("/login/social/{provider}", deps.AuthHandler.HandleLoginSocial)
		r.Get("/login/dev/{profile}", deps.AuthHandler.HandleLoginDevProfile)
		r.Get("/callback", deps.AuthHandler.HandleCallback)
		r.Get("/logout", deps.AuthHandler.HandleLogout)
		r.Post("/logout", deps.AuthHandler.HandleLogout)
	})
}

// registerUserRoutes registers user info routes (session required).
func registerUserRoutes(r chi.Router, deps *RouterDeps) {
	r.Group(func(r chi.Router) {
		r.Use(deps.SessionMgr.Middleware)
		r.Get("/userinfo", deps.AuthHandler.HandleUserInfo)
		r.Get("/session", deps.AuthHandler.HandleSessionInfo)
	})
}

// registerPortalRoutes registers portal routes (auth required).
func registerPortalRoutes(r chi.Router, deps *RouterDeps) {
	r.Group(func(r chi.Router) {
		r.Use(deps.SessionMgr.Middleware)
		r.Use(deps.AuthHandler.RequireAuthMiddleware)
		r.Get("/portal", deps.PortalHandler.HandlePortal)
		r.Get("/service/{service}", deps.PortalHandler.HandleServiceRedirect)
	})
}

// registerAPIRoutes registers API routes (auth required, JSON errors).
func registerAPIRoutes(r chi.Router, deps *RouterDeps) {
	r.Route("/api", func(r chi.Router) {
		r.Use(deps.SessionMgr.Middleware)
		r.Use(deps.AuthHandler.RequireAuthJSONMiddleware)
		r.Get("/services", deps.PortalHandler.HandleServices)
	})
}

// registerForwardAuthRoutes registers forward auth endpoints.
func registerForwardAuthRoutes(r chi.Router, deps *RouterDeps) {
	r.Route("/auth", func(r chi.Router) {
		r.Use(deps.SessionMgr.Middleware)
		r.Get("/", deps.ForwardAuthHandler.HandleAuth)
		r.Get("/redirect", deps.ForwardAuthHandler.HandleAuthWithRedirect)
		r.Get("/verify", deps.ForwardAuthHandler.HandleVerify)
		r.Post("/introspect", deps.ForwardAuthHandler.HandleIntrospect)
	})
}

// registerHealthRoutes registers health check endpoints (no auth).
func registerHealthRoutes(r chi.Router, deps *RouterDeps) {
	r.Get("/health", deps.HealthHandler.HandleHealth)
	r.Get("/ready", deps.HealthHandler.HandleReady)
}

// registerMetricsRoutes registers metrics endpoint if enabled.
func registerMetricsRoutes(r chi.Router, deps *RouterDeps) {
	if deps.Config.Observability.Metrics.Enabled {
		metricsPath := deps.Config.Observability.Metrics.Path
		if metricsPath == "" {
			metricsPath = "/metrics"
		}
		r.Handle(metricsPath, deps.Metrics.Handler())
	}
}

// registerAdminRoutes registers admin endpoints.
func registerAdminRoutes(r chi.Router, deps *RouterDeps) {
	cfg := deps.Config

	r.Route("/admin", func(r chi.Router) {
		// Schema endpoint (always available)
		r.Get("/schema", handleSchema)

		// Dev mode only endpoints
		if cfg.DevMode.Enabled {
			r.Handle("/log/level", logger.LevelHandler())
			r.Get("/config", makeConfigHandler(cfg))
			r.Get("/info", makeInfoHandler(cfg))
		}
	})
}

// handleSchema returns JSON schema for config.
func handleSchema(w http.ResponseWriter, _ *http.Request) {
	gen := schema.NewGenerator()
	data, err := gen.Generate()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// makeConfigHandler creates a handler that returns sanitized config.
func makeConfigHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
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
	}
}

// makeInfoHandler creates a handler that returns app info.
func makeInfoHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		info := map[string]interface{}{
			"version":    Version,
			"build_time": BuildTime,
			"mode":       cfg.Mode,
			"dev_mode":   cfg.DevMode.Enabled,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(info)
	}
}
