package http

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/internal/service/egress"
	"github.com/your-org/authz-service/internal/service/jwt"
	"github.com/your-org/authz-service/internal/service/policy"
	"github.com/your-org/authz-service/pkg/logger"
	"github.com/your-org/authz-service/pkg/resilience/ratelimit"
)

// Server represents the HTTP server.
type Server struct {
	httpServer    *http.Server
	handler       *Handler
	reverseProxy  *ReverseProxy
	egressService *egress.Service
	rateLimiter   *ratelimit.Limiter
	cfg           config.HTTPServerConfig
	endpoints     config.EndpointsConfig
	proxyEnabled  bool
	egressEnabled bool
}

// ServerOption is a functional option for configuring the Server.
type ServerOption func(*Server)

// WithRateLimiter sets the rate limiter for the server.
func WithRateLimiter(limiter *ratelimit.Limiter) ServerOption {
	return func(s *Server) {
		s.rateLimiter = limiter
	}
}

// ServerConfig holds all configuration needed for the HTTP server.
type ServerConfig struct {
	HTTP      config.HTTPServerConfig
	Endpoints config.EndpointsConfig
	Proxy     config.ProxyConfig
	Egress    config.EgressConfig
}

// NewServer creates a new HTTP server.
func NewServer(
	cfg ServerConfig,
	jwtService *jwt.Service,
	policyService *policy.Service,
	version string,
	opts ...ServerOption,
) (*Server, error) {
	handler := NewHandler(jwtService, policyService, version)

	server := &Server{
		handler:       handler,
		cfg:           cfg.HTTP,
		endpoints:     cfg.Endpoints,
		proxyEnabled:  cfg.Proxy.Enabled && cfg.Proxy.Mode == "reverse_proxy",
		egressEnabled: cfg.Egress.Enabled,
	}

	// Apply functional options
	for _, opt := range opts {
		opt(server)
	}

	// Create reverse proxy if enabled
	if server.proxyEnabled {
		proxy, err := NewReverseProxy(cfg.Proxy, jwtService, policyService)
		if err != nil {
			return nil, err
		}
		server.reverseProxy = proxy
	}

	// Create egress proxy service if enabled
	if server.egressEnabled {
		egressSvc, err := egress.NewService(cfg.Egress, logger.L())
		if err != nil {
			return nil, err
		}
		server.egressService = egressSvc
	}

	router := chi.NewRouter()

	// Middleware stack (order matters)
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Recoverer)

	// Rate limiter middleware (early in the chain to reject requests fast)
	if server.rateLimiter != nil {
		router.Use(server.rateLimiter.Middleware())
		logger.Info("rate limiter middleware enabled")
	}

	router.Use(requestLogger)
	router.Use(middleware.Timeout(cfg.HTTP.WriteTimeout))

	// Register routes with configurable endpoints
	server.registerRoutes(router, handler)

	httpServer := &http.Server{
		Addr:           cfg.HTTP.Addr,
		Handler:        router,
		ReadTimeout:    cfg.HTTP.ReadTimeout,
		WriteTimeout:   cfg.HTTP.WriteTimeout,
		IdleTimeout:    cfg.HTTP.IdleTimeout,
		MaxHeaderBytes: cfg.HTTP.MaxHeaderBytes,
	}

	server.httpServer = httpServer

	return server, nil
}

// registerRoutes registers all HTTP routes with configurable endpoints.
func (s *Server) registerRoutes(r chi.Router, h *Handler) {
	ep := s.endpoints

	// API authorization endpoints
	if ep.Authorize != "" {
		r.Post(ep.Authorize, h.Authorize)
	}
	if ep.AuthorizeBatch != "" {
		r.Post(ep.AuthorizeBatch, h.AuthorizeBatch)
	}

	// Token endpoints
	if ep.TokenValidate != "" {
		r.Get(ep.TokenValidate, h.ValidateToken)
		r.Post(ep.TokenValidate, h.ValidateToken)
	}
	if ep.TokenExchange != "" {
		r.Post(ep.TokenExchange, h.TokenExchange)
	}

	// Health endpoints
	if ep.Health != "" {
		r.Get(ep.Health, h.Health)
		// Also support common variants
		r.Get(ep.Health+"z", h.Health)
	}
	if ep.Ready != "" {
		r.Get(ep.Ready, h.Ready)
		r.Get(ep.Ready+"z", h.Ready)
	}
	if ep.Live != "" {
		r.Get(ep.Live, h.Live)
		r.Get(ep.Live+"z", h.Live)
	}

	// Metrics endpoint
	if ep.Metrics != "" {
		r.Handle(ep.Metrics, promhttp.Handler())
	}

	// Admin endpoints (optional)
	if ep.CacheInvalidate != "" {
		r.Post(ep.CacheInvalidate, h.CacheInvalidate)
	}
	if ep.PolicyReload != "" {
		r.Post(ep.PolicyReload, h.PolicyReload)
	}

	// Reverse proxy catch-all (if enabled)
	if s.proxyEnabled && s.reverseProxy != nil {
		r.HandleFunc("/*", s.reverseProxy.ServeHTTP)
	}

	// Egress proxy endpoint (if enabled)
	if s.egressEnabled && s.egressService != nil && ep.Egress != "" {
		r.HandleFunc(ep.Egress+"/*", s.egressService.ProxyRequest)
	}
}

// Start starts the HTTP server.
func (s *Server) Start() error {
	logger.Info("starting HTTP server",
		logger.String("addr", s.cfg.Addr),
	)

	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Shutdown gracefully shuts down the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	logger.Info("shutting down HTTP server")

	// Stop egress service if enabled
	if s.egressService != nil {
		if err := s.egressService.Stop(); err != nil {
			logger.Warn("failed to stop egress service", logger.Err(err))
		}
	}

	return s.httpServer.Shutdown(ctx)
}

// requestLogger is a middleware that logs HTTP requests.
func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		next.ServeHTTP(ww, r)

		// Log the request
		logger.Info("http request",
			logger.String("method", r.Method),
			logger.String("path", r.URL.Path),
			logger.Int("status", ww.Status()),
			logger.Int("bytes", ww.BytesWritten()),
			logger.Duration("duration", time.Since(start)),
			logger.String("remote_addr", r.RemoteAddr),
			logger.String("request_id", middleware.GetReqID(r.Context())),
		)
	})
}
