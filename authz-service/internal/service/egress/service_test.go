package egress

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/your-org/authz-service/internal/config"
)

func TestRouter_Match(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	routes := []config.EgressRouteConfig{
		{
			PathPrefix: "/api/v1",
			Target:     "backend-api",
			Methods:    []string{"GET", "POST"},
		},
		{
			PathPrefix: "/api/v2",
			Target:     "backend-api-v2",
			Methods:    []string{"GET"},
		},
		{
			PathPrefix: "/internal",
			Target:     "internal-service",
			Methods:    nil, // All methods
		},
	}

	router := NewRouter(routes, logger)

	tests := []struct {
		name           string
		path           string
		method         string
		expectedTarget string
		shouldMatch    bool
	}{
		{
			name:           "match api v1 GET",
			path:           "/api/v1/users",
			method:         "GET",
			expectedTarget: "backend-api",
			shouldMatch:    true,
		},
		{
			name:           "match api v1 POST",
			path:           "/api/v1/users",
			method:         "POST",
			expectedTarget: "backend-api",
			shouldMatch:    true,
		},
		{
			name:           "no match api v1 DELETE",
			path:           "/api/v1/users",
			method:         "DELETE",
			expectedTarget: "",
			shouldMatch:    false,
		},
		{
			name:           "match api v2 GET",
			path:           "/api/v2/products",
			method:         "GET",
			expectedTarget: "backend-api-v2",
			shouldMatch:    true,
		},
		{
			name:           "no match api v2 POST",
			path:           "/api/v2/products",
			method:         "POST",
			expectedTarget: "",
			shouldMatch:    false,
		},
		{
			name:           "match internal any method GET",
			path:           "/internal/config",
			method:         "GET",
			expectedTarget: "internal-service",
			shouldMatch:    true,
		},
		{
			name:           "match internal any method DELETE",
			path:           "/internal/config",
			method:         "DELETE",
			expectedTarget: "internal-service",
			shouldMatch:    true,
		},
		{
			name:           "no match unknown path",
			path:           "/unknown/path",
			method:         "GET",
			expectedTarget: "",
			shouldMatch:    false,
		},
		{
			name:           "case insensitive method match",
			path:           "/api/v1/users",
			method:         "get",
			expectedTarget: "backend-api",
			shouldMatch:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := router.Match(tt.path, tt.method)
			if tt.shouldMatch {
				require.NotNil(t, route)
				assert.Equal(t, tt.expectedTarget, route.Target)
			} else {
				assert.Nil(t, route)
			}
		})
	}
}

func TestRouter_MatchPriority(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// Routes are matched in order
	routes := []config.EgressRouteConfig{
		{
			PathPrefix: "/api/v1/specific",
			Target:     "specific-target",
		},
		{
			PathPrefix: "/api/v1",
			Target:     "general-target",
		},
	}

	router := NewRouter(routes, logger)

	// More specific route should match first
	route := router.Match("/api/v1/specific/endpoint", "GET")
	require.NotNil(t, route)
	assert.Equal(t, "specific-target", route.Target)

	// General route should match for non-specific paths
	route = router.Match("/api/v1/other", "GET")
	require.NotNil(t, route)
	assert.Equal(t, "general-target", route.Target)
}

func TestService_BuildTargetURL(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	cfg := config.EgressConfig{
		Targets: map[string]config.EgressTargetConfig{
			"test": {URL: "https://api.example.com"},
		},
	}

	svc := &Service{
		cfg: cfg,
		log: logger,
	}

	tests := []struct {
		name           string
		baseURL        string
		path           string
		route          *config.EgressRouteConfig
		expectedResult string
	}{
		{
			name:    "simple path",
			baseURL: "https://api.example.com",
			path:    "/users",
			route:   &config.EgressRouteConfig{},
			expectedResult: "https://api.example.com/users",
		},
		{
			name:    "strip prefix",
			baseURL: "https://api.example.com",
			path:    "/egress/v1/users",
			route: &config.EgressRouteConfig{
				StripPrefix: "/egress/v1",
			},
			expectedResult: "https://api.example.com/users",
		},
		{
			name:    "rewrite prefix",
			baseURL: "https://api.example.com",
			path:    "/users",
			route: &config.EgressRouteConfig{
				RewritePrefix: "/api/v2",
			},
			expectedResult: "https://api.example.com/api/v2/users",
		},
		{
			name:    "strip and rewrite prefix",
			baseURL: "https://api.example.com",
			path:    "/egress/users",
			route: &config.EgressRouteConfig{
				StripPrefix:   "/egress",
				RewritePrefix: "/api/v1",
			},
			expectedResult: "https://api.example.com/api/v1/users",
		},
		{
			name:    "path without leading slash",
			baseURL: "https://api.example.com",
			path:    "users",
			route:   &config.EgressRouteConfig{},
			expectedResult: "https://api.example.com/users",
		},
		{
			name:    "base URL with path",
			baseURL: "https://api.example.com/v1",
			path:    "/users",
			route:   &config.EgressRouteConfig{},
			expectedResult: "https://api.example.com/users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := svc.buildTargetURL(tt.baseURL, tt.path, tt.route)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestService_CopyHeaders(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	svc := &Service{log: logger}

	// Create source request with headers
	src, _ := http.NewRequest("GET", "http://example.com", nil)
	src.Header.Set("Content-Type", "application/json")
	src.Header.Set("X-Custom-Header", "custom-value")
	src.Header.Set("Accept", "application/json")
	src.Header.Set("Host", "should-be-skipped")
	src.Header.Set("Content-Length", "100")
	src.Header.Set("Transfer-Encoding", "chunked")
	src.Header.Set("Connection", "keep-alive")

	// Create destination request
	dst, _ := http.NewRequest("GET", "http://target.com", nil)

	// Copy headers
	svc.copyHeaders(dst, src)

	// Check copied headers
	assert.Equal(t, "application/json", dst.Header.Get("Content-Type"))
	assert.Equal(t, "custom-value", dst.Header.Get("X-Custom-Header"))
	assert.Equal(t, "application/json", dst.Header.Get("Accept"))

	// Check skipped headers
	assert.Empty(t, dst.Header.Get("Host"))
	assert.Empty(t, dst.Header.Get("Content-Length"))
	assert.Empty(t, dst.Header.Get("Transfer-Encoding"))
	assert.Empty(t, dst.Header.Get("Connection"))
}

func TestService_InjectCredentials(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	svc := &Service{log: logger}

	tests := []struct {
		name     string
		creds    *Credentials
		expected map[string]string
	}{
		{
			name:     "nil credentials",
			creds:    nil,
			expected: map[string]string{},
		},
		{
			name: "with headers",
			creds: &Credentials{
				Headers: map[string]string{
					"Authorization": "Bearer token",
					"X-API-Key":     "key123",
				},
			},
			expected: map[string]string{
				"Authorization": "Bearer token",
				"X-API-Key":     "key123",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://example.com", nil)
			svc.injectCredentials(req, tt.creds)

			for key, value := range tt.expected {
				assert.Equal(t, value, req.Header.Get(key))
			}
		})
	}
}

func TestService_Proxy(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// Create a mock backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify credentials were injected
		assert.Equal(t, "secret-key", r.Header.Get("X-API-Key"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Check path transformation
		assert.Equal(t, "/v2/users", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer backend.Close()

	cfg := config.EgressConfig{
		Enabled: true,
		Targets: map[string]config.EgressTargetConfig{
			"backend": {
				URL: backend.URL,
				Auth: config.EgressAuthConfig{
					Type:   "api_key",
					Header: "X-API-Key",
					Key:    "secret-key",
				},
			},
		},
		Routes: []config.EgressRouteConfig{
			{
				PathPrefix:    "/api/v1",
				Target:        "backend",
				StripPrefix:   "/api/v1",
				RewritePrefix: "/v2",
			},
		},
	}

	svc, err := NewService(cfg, logger)
	require.NoError(t, err)
	defer svc.Stop()

	// Create incoming request
	req := httptest.NewRequest("GET", "/api/v1/users", nil)
	req.Header.Set("Content-Type", "application/json")

	// Proxy the request
	resp, err := svc.Proxy(context.Background(), req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, `{"status": "ok"}`, string(body))
}

func TestService_ProxyRequest(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// Create a mock backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Response-Header", "response-value")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id": 123}`))
	}))
	defer backend.Close()

	cfg := config.EgressConfig{
		Enabled: true,
		Targets: map[string]config.EgressTargetConfig{
			"backend": {
				URL: backend.URL,
				Auth: config.EgressAuthConfig{
					Type: "none",
				},
			},
		},
		Routes: []config.EgressRouteConfig{
			{
				PathPrefix: "/api",
				Target:     "backend",
			},
		},
	}

	svc, err := NewService(cfg, logger)
	require.NoError(t, err)
	defer svc.Stop()

	// Create request and response recorder
	req := httptest.NewRequest("POST", "/api/items", strings.NewReader(`{"name": "test"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Proxy the request
	svc.ProxyRequest(w, req)

	// Check response
	resp := w.Result()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Equal(t, "response-value", resp.Header.Get("X-Response-Header"))

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, `{"id": 123}`, string(body))
}

func TestService_Proxy_NoMatchingRoute(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	cfg := config.EgressConfig{
		Enabled: true,
		Targets: map[string]config.EgressTargetConfig{
			"backend": {
				URL: "http://backend.example.com",
				Auth: config.EgressAuthConfig{
					Type: "none",
				},
			},
		},
		Routes: []config.EgressRouteConfig{
			{
				PathPrefix: "/api",
				Target:     "backend",
			},
		},
	}

	svc, err := NewService(cfg, logger)
	require.NoError(t, err)
	defer svc.Stop()

	// Create request with non-matching path
	req := httptest.NewRequest("GET", "/unknown/path", nil)

	// Should return error
	_, err = svc.Proxy(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no matching route")
}

func TestService_Health(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	cfg := config.EgressConfig{
		Enabled: true,
		Targets: map[string]config.EgressTargetConfig{
			"backend": {
				URL: "http://backend.example.com",
				Auth: config.EgressAuthConfig{
					Type: "none",
				},
			},
		},
	}

	svc, err := NewService(cfg, logger)
	require.NoError(t, err)
	defer svc.Stop()

	// Health check should pass
	err = svc.Health(context.Background())
	assert.NoError(t, err)
}

func TestService_Enabled(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	tests := []struct {
		name     string
		enabled  bool
		expected bool
	}{
		{
			name:     "enabled",
			enabled:  true,
			expected: true,
		},
		{
			name:     "disabled",
			enabled:  false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.EgressConfig{
				Enabled: tt.enabled,
				Targets: map[string]config.EgressTargetConfig{
					"backend": {
						URL: "http://backend.example.com",
						Auth: config.EgressAuthConfig{
							Type: "none",
						},
					},
				},
			}

			svc, err := NewService(cfg, logger)
			require.NoError(t, err)
			defer svc.Stop()

			assert.Equal(t, tt.expected, svc.Enabled())
		})
	}
}

func TestCreateHTTPClient(t *testing.T) {
	tests := []struct {
		name        string
		targetCfg   config.EgressTargetConfig
		defaults    config.EgressDefaultsConfig
		expectError bool
	}{
		{
			name: "default timeout",
			targetCfg: config.EgressTargetConfig{
				Timeout: 0,
			},
			defaults: config.EgressDefaultsConfig{
				Timeout: 0,
			},
			expectError: false,
		},
		{
			name: "custom timeout from target",
			targetCfg: config.EgressTargetConfig{
				Timeout: 10 * 1000 * 1000 * 1000, // 10s in nanoseconds
			},
			defaults:    config.EgressDefaultsConfig{},
			expectError: false,
		},
		{
			name: "TLS enabled",
			targetCfg: config.EgressTargetConfig{
				TLS: config.EgressTLSConfig{
					Enabled: true,
				},
			},
			defaults:    config.EgressDefaultsConfig{},
			expectError: false,
		},
		{
			name: "TLS with insecure skip verify",
			targetCfg: config.EgressTargetConfig{
				TLS: config.EgressTLSConfig{
					Enabled:            true,
					InsecureSkipVerify: true,
				},
			},
			defaults:    config.EgressDefaultsConfig{},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := createHTTPClient(tt.targetCfg, tt.defaults)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, client)
			}
		})
	}
}
