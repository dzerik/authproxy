package http

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/internal/domain"
	bodyExtractor "github.com/your-org/authz-service/internal/service/body"
	"github.com/your-org/authz-service/internal/service/jwt"
	"github.com/your-org/authz-service/internal/service/policy"
	tlsExtractor "github.com/your-org/authz-service/internal/service/tls"
	errResponse "github.com/your-org/authz-service/pkg/httputil"
	"github.com/your-org/authz-service/pkg/logger"
)

// ReverseProxy handles reverse proxying of authorized requests.
type ReverseProxy struct {
	cfg           config.ProxyConfig
	envCfg        config.EnvConfig
	tlsCfg        config.TLSClientCertConfig
	bodyCfg       config.RequestBodyConfig
	jwtService    *jwt.Service
	policyService *policy.Service
	tlsExtractor  *tlsExtractor.Extractor
	bodyExtractor *bodyExtractor.Extractor
	proxies       map[string]*httputil.ReverseProxy
	routes        []*compiledRoute
	defaultProxy  *httputil.ReverseProxy
	errorWriter   *errResponse.ErrorResponseWriter
}

// compiledRoute is a pre-compiled route for faster matching.
type compiledRoute struct {
	config     config.RouteConfig
	pathRegex  *regexp.Regexp
	upstream   string
}

// NewReverseProxy creates a new reverse proxy handler.
func NewReverseProxy(
	cfg config.ProxyConfig,
	envCfg config.EnvConfig,
	tlsCfg config.TLSClientCertConfig,
	bodyCfg config.RequestBodyConfig,
	errCfg config.ErrorResponseConfig,
	jwtService *jwt.Service,
	policyService *policy.Service,
) (*ReverseProxy, error) {
	rp := &ReverseProxy{
		cfg:           cfg,
		envCfg:        envCfg,
		tlsCfg:        tlsCfg,
		bodyCfg:       bodyCfg,
		jwtService:    jwtService,
		policyService: policyService,
		proxies:       make(map[string]*httputil.ReverseProxy),
		errorWriter:   errResponse.NewErrorResponseWriter(errCfg),
	}

	// Create TLS extractor if enabled
	if tlsCfg.Enabled {
		extractor, err := tlsExtractor.NewExtractor(tlsCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS extractor: %w", err)
		}
		rp.tlsExtractor = extractor
		logger.Info("TLS client certificate extraction enabled",
			logger.Bool("xfcc", tlsCfg.Sources.XFCC.Enabled),
			logger.Bool("headers", tlsCfg.Sources.Headers.Enabled),
		)
	}

	// Create body extractor if enabled
	// WARNING: Request body access has security and performance implications
	if bodyCfg.Enabled {
		rp.bodyExtractor = bodyExtractor.NewExtractor(bodyCfg)
		logger.Warn("⚠️  REQUEST BODY ACCESS ENABLED - This feature buffers request bodies in memory "+
			"and may have security implications. Ensure proper validation is configured.",
			logger.Int64("max_size", bodyCfg.MaxSize),
			logger.Bool("schema_validation", bodyCfg.Schema.Enabled),
			logger.Strings("methods", bodyCfg.Methods),
		)
	}

	// Create default proxy
	if cfg.Upstream.URL != "" {
		proxy, err := rp.createProxy(cfg.Upstream)
		if err != nil {
			return nil, fmt.Errorf("failed to create default upstream proxy: %w", err)
		}
		rp.defaultProxy = proxy
		rp.proxies["default"] = proxy
	}

	// Create named upstream proxies
	for name, upstream := range cfg.Upstreams {
		proxy, err := rp.createProxy(upstream)
		if err != nil {
			return nil, fmt.Errorf("failed to create upstream proxy %s: %w", name, err)
		}
		rp.proxies[name] = proxy
	}

	// Compile routes
	for _, route := range cfg.Routes {
		compiled := &compiledRoute{
			config:   route,
			upstream: route.Upstream,
		}

		// Compile path regex if specified
		if route.PathRegex != "" {
			regex, err := regexp.Compile(route.PathRegex)
			if err != nil {
				return nil, fmt.Errorf("invalid route regex %s: %w", route.PathRegex, err)
			}
			compiled.pathRegex = regex
		}

		rp.routes = append(rp.routes, compiled)
	}

	return rp, nil
}

// NewReverseProxyFromListener creates a reverse proxy from a listener configuration.
// This is used for multi-listener proxy architecture where each listener has its own config.
func NewReverseProxyFromListener(
	listenerCfg config.ProxyListenerConfig,
	envCfg config.EnvConfig,
	tlsCfg config.TLSClientCertConfig,
	bodyCfg config.RequestBodyConfig,
	jwtService *jwt.Service,
	policyService *policy.Service,
) (*ReverseProxy, error) {
	// Convert ProxyListenerConfig to ProxyConfig
	proxyCfg := config.ProxyConfig{
		Enabled:   true,
		Mode:      listenerCfg.Mode,
		Upstreams: listenerCfg.Upstreams,
		Routes:    listenerCfg.Routes,
		Headers:   listenerCfg.Headers,
		Timeout:   listenerCfg.Timeout,
		Retry:     listenerCfg.Retry,
	}

	return NewReverseProxy(proxyCfg, envCfg, tlsCfg, bodyCfg, listenerCfg.ErrorResponse, jwtService, policyService)
}

// createProxy creates an httputil.ReverseProxy for an upstream.
func (rp *ReverseProxy) createProxy(upstream config.UpstreamConfig) (*httputil.ReverseProxy, error) {
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL %s: %w", upstream.URL, err)
	}

	// Create transport
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       rp.cfg.IdleConnTimeout,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Configure TLS if enabled
	if upstream.TLS.Enabled {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: upstream.TLS.InsecureSkipVerify,
		}

		// Load CA certificate
		if upstream.TLS.CACert != "" {
			caCert, err := os.ReadFile(upstream.TLS.CACert)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA cert: %w", err)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig.RootCAs = caCertPool
		}

		// Load client certificate for mTLS
		if upstream.TLS.ClientCert != "" && upstream.TLS.ClientKey != "" {
			cert, err := tls.LoadX509KeyPair(upstream.TLS.ClientCert, upstream.TLS.ClientKey)
			if err != nil {
				return nil, fmt.Errorf("failed to load client cert: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}

		transport.TLSClientConfig = tlsConfig
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Transport = transport

	// Custom error handler
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("proxy error",
			logger.String("upstream", upstream.URL),
			logger.String("path", r.URL.Path),
			logger.Err(err),
		)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	// Modify response
	proxy.ModifyResponse = func(resp *http.Response) error {
		// Add request ID to response
		if reqID := resp.Request.Context().Value(requestIDKey); reqID != nil {
			resp.Header.Set("X-Request-ID", reqID.(string))
		}
		return nil
	}

	return proxy, nil
}

// ServeHTTP handles incoming requests with authorization and proxying.
func (rp *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := getRequestID(r)
	start := time.Now()

	// Add request ID to context
	ctx = context.WithValue(ctx, requestIDKey, requestID)
	r = r.WithContext(ctx)

	// Build policy input from request
	input := rp.buildPolicyInput(r)

	// Extract and validate JWT token
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		authHeader = r.Header.Get("X-Forwarded-Authorization")
	}

	var tokenInfo *domain.TokenInfo
	if authHeader != "" {
		var err error
		tokenInfo, err = rp.jwtService.ValidateFromHeader(ctx, authHeader)
		if err != nil {
			logger.Warn("JWT validation failed",
				logger.String("request_id", requestID),
				logger.Err(err),
			)
			rp.errorWriter.WriteError(w, r, http.StatusUnauthorized, "Unauthorized", err.Error())
			return
		}
		input.Token = tokenInfo
	}

	// Set context info
	input.Context.RequestID = requestID
	input.Context.Timestamp = time.Now().Unix()

	// Evaluate policy
	decision, err := rp.policyService.Evaluate(ctx, input)
	if err != nil {
		logger.Error("policy evaluation failed",
			logger.String("request_id", requestID),
			logger.Err(err),
		)
		rp.errorWriter.WriteError(w, r, http.StatusInternalServerError, "Internal Server Error", "policy evaluation failed")
		return
	}

	// Log the decision
	logger.Info("proxy authorization decision",
		logger.String("request_id", requestID),
		logger.Bool("allowed", decision.Allowed),
		logger.String("method", r.Method),
		logger.String("path", r.URL.Path),
		logger.Duration("auth_duration", time.Since(start)),
	)

	// If denied, return 403
	if !decision.Allowed {
		reason := "Access denied"
		if len(decision.Reasons) > 0 {
			reason = decision.Reasons[0]
		}
		rp.errorWriter.WriteError(w, r, http.StatusForbidden, "Forbidden", reason)
		return
	}

	// Apply headers from decision
	for key, value := range decision.HeadersToAdd {
		r.Header.Set(key, value)
	}
	for _, key := range decision.HeadersToRemove {
		r.Header.Del(key)
	}

	// Apply configured headers
	rp.applyHeaders(r, tokenInfo)

	// Select upstream based on routing rules
	proxy := rp.selectUpstream(r)
	if proxy == nil {
		logger.Error("no upstream configured",
			logger.String("request_id", requestID),
			logger.String("path", r.URL.Path),
		)
		rp.errorWriter.WriteError(w, r, http.StatusBadGateway, "Bad Gateway", "no upstream configured")
		return
	}

	// Apply path rewriting if configured
	rp.rewritePath(r)

	// Proxy the request
	proxy.ServeHTTP(w, r)
}

// buildPolicyInput creates a PolicyInput from an HTTP request.
func (rp *ReverseProxy) buildPolicyInput(r *http.Request) *domain.PolicyInput {
	// Build headers map
	headers := make(map[string]string)
	for key, values := range r.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	// Build query params
	query := make(map[string]string)
	for key, values := range r.URL.Query() {
		if len(values) > 0 {
			query[key] = values[0]
		}
	}

	input := &domain.PolicyInput{
		Request: domain.RequestInfo{
			Method:   r.Method,
			Path:     r.URL.Path,
			Host:     r.Host,
			Headers:  headers,
			Query:    query,
			Protocol: r.Proto,
		},
		Source: domain.SourceInfo{
			Address: getClientIP(r),
		},
		Destination: domain.DestinationInfo{
			Address: r.Host,
		},
		Env: domain.EnvInfo{
			Name:     rp.envCfg.Name,
			Region:   rp.envCfg.Region,
			Cluster:  rp.envCfg.Cluster,
			Version:  rp.envCfg.Version,
			Features: rp.envCfg.Features,
			Custom:   rp.envCfg.Custom,
		},
	}

	// Extract TLS client certificate info if extractor is enabled
	if rp.tlsExtractor != nil {
		tlsInfo := rp.tlsExtractor.Extract(r)
		if tlsInfo != nil {
			input.TLS = tlsInfo
			// Also populate source info from SPIFFE if available
			if tlsInfo.SPIFFE != nil {
				input.Source.Principal = tlsInfo.SPIFFE.URI
				input.Source.Namespace = tlsInfo.SPIFFE.Namespace
				input.Source.ServiceAccount = tlsInfo.SPIFFE.ServiceAccount
			}
		}
	}

	// Extract request body if extractor is enabled
	// WARNING: This buffers the request body in memory
	if rp.bodyExtractor != nil {
		body, err := rp.bodyExtractor.Extract(r)
		if err != nil {
			logger.Warn("failed to extract request body for authorization",
				logger.String("path", r.URL.Path),
				logger.String("method", r.Method),
				logger.Err(err),
			)
			// Don't fail the request, just skip body access
		} else if body != nil {
			input.Body = body
		}
	}

	return input
}

// applyHeaders applies configured headers to the request.
func (rp *ReverseProxy) applyHeaders(r *http.Request, tokenInfo *domain.TokenInfo) {
	// Add configured headers
	for key, value := range rp.cfg.Headers.Add {
		r.Header.Set(key, value)
	}

	// Remove configured headers
	for _, key := range rp.cfg.Headers.Remove {
		r.Header.Del(key)
	}

	// Add user info headers if enabled
	if rp.cfg.Headers.AddUserInfo && tokenInfo != nil {
		if rp.cfg.Headers.UserIDHeader != "" {
			r.Header.Set(rp.cfg.Headers.UserIDHeader, tokenInfo.Subject)
		}
		if rp.cfg.Headers.UserRolesHeader != "" && len(tokenInfo.Roles) > 0 {
			r.Header.Set(rp.cfg.Headers.UserRolesHeader, strings.Join(tokenInfo.Roles, ","))
		}
	}

	// Set standard proxy headers
	if r.Header.Get("X-Forwarded-For") == "" {
		r.Header.Set("X-Forwarded-For", getClientIP(r))
	}
	if r.Header.Get("X-Forwarded-Proto") == "" {
		proto := "http"
		if r.TLS != nil {
			proto = "https"
		}
		r.Header.Set("X-Forwarded-Proto", proto)
	}
	if r.Header.Get("X-Forwarded-Host") == "" {
		r.Header.Set("X-Forwarded-Host", r.Host)
	}
}

// selectUpstream selects the appropriate upstream proxy based on routing rules.
func (rp *ReverseProxy) selectUpstream(r *http.Request) *httputil.ReverseProxy {
	// Check routing rules
	for _, route := range rp.routes {
		if rp.matchRoute(r, route) {
			if proxy, ok := rp.proxies[route.upstream]; ok {
				return proxy
			}
		}
	}

	// Return default proxy
	return rp.defaultProxy
}

// matchRoute checks if a request matches a route.
func (rp *ReverseProxy) matchRoute(r *http.Request, route *compiledRoute) bool {
	cfg := route.config

	// Check method
	if len(cfg.Methods) > 0 {
		matched := false
		for _, m := range cfg.Methods {
			if strings.EqualFold(m, r.Method) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check path exact match
	if cfg.PathExact != "" && r.URL.Path != cfg.PathExact {
		return false
	}

	// Check path prefix
	if cfg.PathPrefix != "" && !strings.HasPrefix(r.URL.Path, cfg.PathPrefix) {
		return false
	}

	// Check path regex
	if route.pathRegex != nil && !route.pathRegex.MatchString(r.URL.Path) {
		return false
	}

	// Check headers
	for key, value := range cfg.Headers {
		if r.Header.Get(key) != value {
			return false
		}
	}

	return true
}

// rewritePath applies path rewriting rules.
func (rp *ReverseProxy) rewritePath(r *http.Request) {
	// Find matching route with rewrite rules
	for _, route := range rp.routes {
		if rp.matchRoute(r, route) {
			cfg := route.config

			// Strip prefix
			if cfg.StripPrefix != "" {
				r.URL.Path = strings.TrimPrefix(r.URL.Path, cfg.StripPrefix)
				if r.URL.Path == "" {
					r.URL.Path = "/"
				}
			}

			// Rewrite prefix
			if cfg.RewritePrefix != "" {
				if cfg.StripPrefix != "" {
					r.URL.Path = cfg.RewritePrefix + r.URL.Path
				} else if cfg.PathPrefix != "" {
					r.URL.Path = strings.Replace(r.URL.Path, cfg.PathPrefix, cfg.RewritePrefix, 1)
				}
			}

			break
		}
	}
}

// Context key type for request ID
type contextKey string

const requestIDKey contextKey = "request_id"
