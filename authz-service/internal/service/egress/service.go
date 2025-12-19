package egress

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/pkg/logger"
)

// Service handles egress proxy requests.
type Service struct {
	cfg         config.EgressConfig
	credManager *CredentialManager
	tokenStore  TokenStore
	router      *Router
	httpClients map[string]*http.Client
	log         logger.Logger
}

// NewService creates a new egress service.
func NewService(cfg config.EgressConfig, log logger.Logger) (*Service, error) {
	// Create token store
	tokenStore, err := NewTokenStore(cfg.TokenStore, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create token store: %w", err)
	}

	// Create credential manager
	credManager, err := NewCredentialManager(cfg, tokenStore, log)
	if err != nil {
		tokenStore.Close()
		return nil, fmt.Errorf("failed to create credential manager: %w", err)
	}

	// Create router
	router := NewRouter(cfg.Routes, log)

	// Create HTTP clients for each target
	httpClients := make(map[string]*http.Client)
	for name, targetCfg := range cfg.Targets {
		client, err := createHTTPClient(targetCfg, cfg.Defaults)
		if err != nil {
			tokenStore.Close()
			return nil, fmt.Errorf("failed to create HTTP client for %s: %w", name, err)
		}
		httpClients[name] = client
	}

	return &Service{
		cfg:         cfg,
		credManager: credManager,
		tokenStore:  tokenStore,
		router:      router,
		httpClients: httpClients,
		log:         log,
	}, nil
}

// NewServiceFromListener creates an egress service from a listener configuration.
// This is used for multi-listener egress architecture where each listener has its own config.
func NewServiceFromListener(
	listenerCfg config.EgressListenerConfig,
	defaults config.EgressDefaultsConfig,
	tokenStoreCfg config.EgressTokenStoreConfig,
	log logger.Logger,
) (*Service, error) {
	// Convert EgressListenerConfig to EgressConfig
	egressCfg := config.EgressConfig{
		Enabled:    true,
		Targets:    listenerCfg.Targets,
		Routes:     listenerCfg.Routes,
		Defaults:   defaults,
		TokenStore: tokenStoreCfg,
	}

	return NewService(egressCfg, log)
}

// Start starts the egress service.
func (s *Service) Start(ctx context.Context) error {
	s.log.Info("Egress proxy service started",
		logger.Int("targets", len(s.cfg.Targets)),
		logger.Int("routes", len(s.cfg.Routes)),
	)
	return nil
}

// Stop stops the egress service.
func (s *Service) Stop() error {
	if s.tokenStore != nil {
		return s.tokenStore.Close()
	}
	return nil
}

// Proxy proxies a request to the appropriate target.
func (s *Service) Proxy(ctx context.Context, req *http.Request) (*http.Response, error) {
	// Match route
	route := s.router.Match(req.URL.Path, req.Method)
	if route == nil {
		return nil, fmt.Errorf("no matching route for path: %s", req.URL.Path)
	}

	// Get target config
	targetCfg, ok := s.cfg.Targets[route.Target]
	if !ok {
		return nil, fmt.Errorf("target not found: %s", route.Target)
	}

	// Get credentials
	creds, err := s.credManager.GetCredentials(ctx, route.Target)
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}

	// Build target URL
	targetURL, err := s.buildTargetURL(targetCfg.URL, req.URL.Path, route)
	if err != nil {
		return nil, fmt.Errorf("failed to build target URL: %w", err)
	}

	// Create proxied request
	proxyReq, err := http.NewRequestWithContext(ctx, req.Method, targetURL, req.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to create proxy request: %w", err)
	}

	// Copy headers from original request
	s.copyHeaders(proxyReq, req)

	// Inject credentials
	s.injectCredentials(proxyReq, creds)

	// Get HTTP client for target
	client := s.httpClients[route.Target]
	if client == nil {
		return nil, fmt.Errorf("no HTTP client for target: %s", route.Target)
	}

	// Execute request
	start := time.Now()
	resp, err := client.Do(proxyReq)
	duration := time.Since(start)

	// Log request
	s.log.Info("Egress request",
		logger.String("target", route.Target),
		logger.String("method", req.Method),
		logger.String("path", req.URL.Path),
		logger.String("target_url", targetURL),
		logger.Duration("duration", duration),
		logger.Int("status", func() int {
			if resp != nil {
				return resp.StatusCode
			}
			return 0
		}()),
		logger.Err(err),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to execute proxy request: %w", err)
	}

	return resp, nil
}

// ProxyRequest is a convenience method that handles the full request/response cycle.
func (s *Service) ProxyRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	resp, err := s.Proxy(ctx, r)
	if err != nil {
		s.log.Error("Egress proxy error", logger.Err(err))
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Write status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	_, _ = io.Copy(w, resp.Body)
}

// Health checks if the service is healthy.
func (s *Service) Health(ctx context.Context) error {
	return s.credManager.Health(ctx)
}

// Enabled returns whether egress proxy is enabled.
func (s *Service) Enabled() bool {
	return s.cfg.Enabled
}

// buildTargetURL builds the target URL with path rewriting.
func (s *Service) buildTargetURL(baseURL, path string, route *config.EgressRouteConfig) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}

	// Apply path transformations
	newPath := path

	// Strip prefix
	if route.StripPrefix != "" {
		newPath = strings.TrimPrefix(newPath, route.StripPrefix)
	}

	// Rewrite prefix
	if route.RewritePrefix != "" {
		newPath = route.RewritePrefix + newPath
	}

	// Ensure path starts with /
	if !strings.HasPrefix(newPath, "/") {
		newPath = "/" + newPath
	}

	u.Path = newPath

	return u.String(), nil
}

// copyHeaders copies headers from original request to proxy request.
func (s *Service) copyHeaders(dst, src *http.Request) {
	// Headers to skip
	skipHeaders := map[string]bool{
		"Host":              true,
		"Content-Length":    true,
		"Transfer-Encoding": true,
		"Connection":        true,
	}

	for key, values := range src.Header {
		if skipHeaders[key] {
			continue
		}
		for _, value := range values {
			dst.Header.Add(key, value)
		}
	}
}

// injectCredentials injects credentials into the request.
func (s *Service) injectCredentials(req *http.Request, creds *Credentials) {
	if creds == nil {
		return
	}

	// Add credential headers
	for key, value := range creds.Headers {
		req.Header.Set(key, value)
	}
}

// createHTTPClient creates an HTTP client for a target.
func createHTTPClient(targetCfg config.EgressTargetConfig, defaults config.EgressDefaultsConfig) (*http.Client, error) {
	timeout := targetCfg.Timeout
	if timeout == 0 {
		timeout = defaults.Timeout
	}
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	transport := &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		DisableKeepAlives:   false,
		MaxIdleConnsPerHost: 10,
	}

	// Configure TLS if enabled
	if targetCfg.TLS.Enabled {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: targetCfg.TLS.InsecureSkipVerify,
		}

		// Load client certificate for mTLS
		if targetCfg.TLS.ClientCert != "" && targetCfg.TLS.ClientKey != "" {
			cert, err := tls.LoadX509KeyPair(targetCfg.TLS.ClientCert, targetCfg.TLS.ClientKey)
			if err != nil {
				return nil, fmt.Errorf("failed to load client certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}

		transport.TLSClientConfig = tlsConfig
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}, nil
}

// =============================================================================
// Router
// =============================================================================

// Router matches incoming requests to egress routes.
type Router struct {
	routes []config.EgressRouteConfig
	log    logger.Logger
}

// NewRouter creates a new router.
func NewRouter(routes []config.EgressRouteConfig, log logger.Logger) *Router {
	return &Router{
		routes: routes,
		log:    log,
	}
}

// Match finds a matching route for the given path and method.
func (r *Router) Match(path, method string) *config.EgressRouteConfig {
	for i := range r.routes {
		route := &r.routes[i]

		// Check path prefix
		if route.PathPrefix != "" && !strings.HasPrefix(path, route.PathPrefix) {
			continue
		}

		// Check method
		if len(route.Methods) > 0 {
			methodMatched := false
			for _, m := range route.Methods {
				if strings.EqualFold(m, method) {
					methodMatched = true
					break
				}
			}
			if !methodMatched {
				continue
			}
		}

		return route
	}

	return nil
}
