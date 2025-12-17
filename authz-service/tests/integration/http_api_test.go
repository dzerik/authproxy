package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/internal/domain"
	"github.com/your-org/authz-service/internal/service/jwt"
	"github.com/your-org/authz-service/internal/service/policy"
	httpTransport "github.com/your-org/authz-service/internal/transport/http"
)

// mockPolicyEngine is a mock implementation of policy.Engine for testing.
type mockPolicyEngine struct {
	evaluateFunc func(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error)
}

func (m *mockPolicyEngine) Name() string {
	return "mock"
}

func (m *mockPolicyEngine) Start(ctx context.Context) error {
	return nil
}

func (m *mockPolicyEngine) Stop() error {
	return nil
}

func (m *mockPolicyEngine) Evaluate(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
	if m.evaluateFunc != nil {
		return m.evaluateFunc(ctx, input)
	}
	return domain.Allow("mock allow"), nil
}

func (m *mockPolicyEngine) Healthy(ctx context.Context) bool {
	return true
}

func TestHTTPHandler_Authorize_Success(t *testing.T) {
	// Create mock services
	jwtCfg := config.JWTConfig{
		Issuers: []config.IssuerConfig{
			{
				Name:      "test",
				IssuerURL: "http://localhost:8180/realms/test",
			},
		},
	}
	jwtService := jwt.NewService(jwtCfg)

	policyCfg := config.PolicyConfig{
		Engine: "builtin",
		Builtin: config.BuiltinPolicyConfig{
			RulesPath: "",
		},
	}
	policyService, err := policy.NewService(policyCfg)
	require.NoError(t, err)

	// Create handler
	handler := httpTransport.NewHandler(jwtService, policyService, "test")

	// Setup router
	router := chi.NewRouter()
	handler.RegisterRoutes(router)

	// Create request
	reqBody := httpTransport.AuthzRequest{
		Request: httpTransport.RequestDTO{
			Path:   "/health",
			Method: "GET",
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/authorize", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp httpTransport.AuthzResponse
	err = json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	// Policy should evaluate (allowed depends on actual policy rules)
	assert.NotNil(t, resp.EvaluatedAt)
}

func TestHTTPHandler_Authorize_InvalidJSON(t *testing.T) {
	jwtCfg := config.JWTConfig{}
	jwtService := jwt.NewService(jwtCfg)

	policyCfg := config.PolicyConfig{Engine: "builtin"}
	policyService, _ := policy.NewService(policyCfg)

	handler := httpTransport.NewHandler(jwtService, policyService, "test")
	router := chi.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/authorize", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHTTPHandler_Health(t *testing.T) {
	jwtCfg := config.JWTConfig{}
	jwtService := jwt.NewService(jwtCfg)

	policyCfg := config.PolicyConfig{Engine: "builtin"}
	policyService, _ := policy.NewService(policyCfg)

	handler := httpTransport.NewHandler(jwtService, policyService, "test")
	router := chi.NewRouter()
	handler.RegisterRoutes(router)

	testCases := []struct {
		name     string
		endpoint string
	}{
		{"health", "/health"},
		{"healthz", "/healthz"},
		{"ready", "/ready"},
		{"readyz", "/readyz"},
		{"live", "/live"},
		{"livez", "/livez"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.endpoint, nil)
			rec := httptest.NewRecorder()

			router.ServeHTTP(rec, req)

			// Should return OK or ServiceUnavailable depending on service health
			assert.True(t, rec.Code == http.StatusOK || rec.Code == http.StatusServiceUnavailable)
		})
	}
}

func TestHTTPHandler_ValidateToken_NoHeader(t *testing.T) {
	jwtCfg := config.JWTConfig{}
	jwtService := jwt.NewService(jwtCfg)

	policyCfg := config.PolicyConfig{Engine: "builtin"}
	policyService, _ := policy.NewService(policyCfg)

	handler := httpTransport.NewHandler(jwtService, policyService, "test")
	router := chi.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/token/validate", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHTTPHandler_ContentType_JSON(t *testing.T) {
	jwtCfg := config.JWTConfig{}
	jwtService := jwt.NewService(jwtCfg)

	policyCfg := config.PolicyConfig{Engine: "builtin"}
	policyService, _ := policy.NewService(policyCfg)

	handler := httpTransport.NewHandler(jwtService, policyService, "test")
	router := chi.NewRouter()
	handler.RegisterRoutes(router)

	reqBody := httpTransport.AuthzRequest{
		Request: httpTransport.RequestDTO{Path: "/api/data", Method: "GET"},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/authorize", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")
}

func TestHTTPHandler_ResponseTime(t *testing.T) {
	jwtCfg := config.JWTConfig{}
	jwtService := jwt.NewService(jwtCfg)

	policyCfg := config.PolicyConfig{Engine: "builtin"}
	policyService, _ := policy.NewService(policyCfg)

	handler := httpTransport.NewHandler(jwtService, policyService, "test")
	router := chi.NewRouter()
	handler.RegisterRoutes(router)

	reqBody := httpTransport.AuthzRequest{
		Request: httpTransport.RequestDTO{Path: "/api/data", Method: "GET"},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/authorize", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	start := time.Now()
	router.ServeHTTP(rec, req)
	duration := time.Since(start)

	assert.Equal(t, http.StatusOK, rec.Code)
	// Should be fast - under 100ms for simple request
	assert.Less(t, duration, 100*time.Millisecond)
}

// Benchmark tests

func BenchmarkHTTPHandler_Authorize(b *testing.B) {
	jwtCfg := config.JWTConfig{}
	jwtService := jwt.NewService(jwtCfg)

	policyCfg := config.PolicyConfig{Engine: "builtin"}
	policyService, _ := policy.NewService(policyCfg)

	handler := httpTransport.NewHandler(jwtService, policyService, "test")
	router := chi.NewRouter()
	handler.RegisterRoutes(router)

	reqBody := httpTransport.AuthzRequest{
		Request: httpTransport.RequestDTO{Path: "/api/data", Method: "GET"},
	}
	body, _ := json.Marshal(reqBody)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/authorize", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
	}
}
