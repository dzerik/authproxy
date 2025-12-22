package http

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

	"github.com/your-org/authz-service/internal/domain"
	"github.com/your-org/authz-service/pkg/errors"
)

// =============================================================================
// Mock Services
// =============================================================================

type mockJWTService struct {
	validateFunc func(ctx context.Context, token string) (*domain.TokenInfo, error)
}

func (m *mockJWTService) ValidateFromHeader(ctx context.Context, authHeader string) (*domain.TokenInfo, error) {
	if m.validateFunc != nil {
		// Extract token from "Bearer <token>"
		token := authHeader
		if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
			token = authHeader[7:]
		}
		return m.validateFunc(ctx, token)
	}
	return nil, nil
}

func (m *mockJWTService) ValidateToken(ctx context.Context, token string) (*domain.TokenInfo, error) {
	if m.validateFunc != nil {
		return m.validateFunc(ctx, token)
	}
	return nil, nil
}

type mockPolicyService struct {
	evaluateFunc func(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error)
	healthyFunc  func(ctx context.Context) bool
	reloadFunc   func(ctx context.Context) error
}

func (m *mockPolicyService) Evaluate(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
	if m.evaluateFunc != nil {
		return m.evaluateFunc(ctx, input)
	}
	return domain.Allow(), nil
}

func (m *mockPolicyService) Healthy(ctx context.Context) bool {
	if m.healthyFunc != nil {
		return m.healthyFunc(ctx)
	}
	return true
}

func (m *mockPolicyService) Reload(ctx context.Context) error {
	if m.reloadFunc != nil {
		return m.reloadFunc(ctx)
	}
	return nil
}

type mockCacheService struct {
	clearFunc   func(ctx context.Context)
	statsFunc   func() map[string]any
	enabledFunc func() bool
}

func (m *mockCacheService) Clear(ctx context.Context) {
	if m.clearFunc != nil {
		m.clearFunc(ctx)
	}
}

func (m *mockCacheService) Stats() map[string]any {
	if m.statsFunc != nil {
		return m.statsFunc()
	}
	return map[string]any{
		"l1": map[string]any{"size": 0, "hits": 0, "misses": 0},
		"l2": map[string]any{"size": 0, "hits": 0, "misses": 0},
	}
}

func (m *mockCacheService) Enabled() bool {
	if m.enabledFunc != nil {
		return m.enabledFunc()
	}
	return true
}

// =============================================================================
// Handler Tests
// =============================================================================

func TestNewHandler(t *testing.T) {
	h := NewHandler(nil, nil, "1.0.0")

	require.NotNil(t, h)
	assert.Equal(t, "1.0.0", h.version)
}

func TestHandler_Health(t *testing.T) {
	policyMock := &mockPolicyService{
		healthyFunc: func(ctx context.Context) bool { return true },
	}
	h := NewHandler(nil, policyMock, "1.0.0")

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	h.Health(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp HealthResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "healthy", resp.Status)
	assert.Equal(t, "1.0.0", resp.Version)
}

func TestHandler_Health_Unhealthy(t *testing.T) {
	policyMock := &mockPolicyService{
		healthyFunc: func(ctx context.Context) bool { return false },
	}
	h := NewHandler(nil, policyMock, "1.0.0")

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	h.Health(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	var resp HealthResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "unhealthy", resp.Status)
}

func TestHandler_Ready(t *testing.T) {
	policyMock := &mockPolicyService{
		healthyFunc: func(ctx context.Context) bool { return true },
	}
	h := NewHandler(nil, policyMock, "1.0.0")

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()

	h.Ready(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandler_Ready_NotReady(t *testing.T) {
	policyMock := &mockPolicyService{
		healthyFunc: func(ctx context.Context) bool { return false },
	}
	h := NewHandler(nil, policyMock, "1.0.0")

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()

	h.Ready(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestHandler_Live(t *testing.T) {
	h := NewHandler(nil, nil, "1.0.0")

	req := httptest.NewRequest(http.MethodGet, "/live", nil)
	w := httptest.NewRecorder()

	h.Live(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandler_Authorize_Success(t *testing.T) {
	jwtMock := &mockJWTService{
		validateFunc: func(ctx context.Context, token string) (*domain.TokenInfo, error) {
			return &domain.TokenInfo{
				Subject: "user123",
				Roles:   []string{"admin"},
				Valid:   true,
			}, nil
		},
	}
	policyMock := &mockPolicyService{
		evaluateFunc: func(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
			return domain.Allow("policy matched"), nil
		},
	}
	h := NewHandler(jwtMock, policyMock, "1.0.0")

	body := AuthzRequest{
		Request: RequestDTO{
			Method: "GET",
			Path:   "/api/users",
		},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/authorize", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	h.Authorize(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp AuthzResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Allowed)
}

func TestHandler_Authorize_Denied(t *testing.T) {
	jwtMock := &mockJWTService{
		validateFunc: func(ctx context.Context, token string) (*domain.TokenInfo, error) {
			return &domain.TokenInfo{
				Subject: "user123",
				Valid:   true,
			}, nil
		},
	}
	policyMock := &mockPolicyService{
		evaluateFunc: func(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
			return domain.Deny("access denied"), nil
		},
	}
	h := NewHandler(jwtMock, policyMock, "1.0.0")

	body := AuthzRequest{
		Request: RequestDTO{
			Method: "DELETE",
			Path:   "/api/admin/users",
		},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/authorize", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	h.Authorize(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp AuthzResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.False(t, resp.Allowed)
	assert.Contains(t, resp.Reasons, "access denied")
}

func TestHandler_Authorize_InvalidRequest(t *testing.T) {
	h := NewHandler(nil, nil, "1.0.0")

	req := httptest.NewRequest(http.MethodPost, "/v1/authorize", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Authorize(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "INVALID_REQUEST", resp.Code)
}

func TestHandler_Authorize_InvalidToken(t *testing.T) {
	jwtMock := &mockJWTService{
		validateFunc: func(ctx context.Context, token string) (*domain.TokenInfo, error) {
			return nil, errors.NewAuthzError(errors.CodeTokenInvalid, "token expired", nil)
		},
	}
	h := NewHandler(jwtMock, nil, "1.0.0")

	body := AuthzRequest{
		Request: RequestDTO{
			Method: "GET",
			Path:   "/api/users",
		},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/authorize", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer expired-token")
	w := httptest.NewRecorder()

	h.Authorize(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, errors.CodeTokenInvalid, resp.Code)
}

func TestHandler_Authorize_NoToken(t *testing.T) {
	policyMock := &mockPolicyService{
		evaluateFunc: func(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
			// Anonymous access allowed for public endpoints
			return domain.Allow("public endpoint"), nil
		},
	}
	h := NewHandler(nil, policyMock, "1.0.0")

	body := AuthzRequest{
		Request: RequestDTO{
			Method: "GET",
			Path:   "/public/docs",
		},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/authorize", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Authorize(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp AuthzResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Allowed)
}

func TestHandler_Authorize_PolicyError(t *testing.T) {
	policyMock := &mockPolicyService{
		evaluateFunc: func(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
			return nil, assert.AnError
		},
	}
	h := NewHandler(nil, policyMock, "1.0.0")

	body := AuthzRequest{
		Request: RequestDTO{
			Method: "GET",
			Path:   "/api/users",
		},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/authorize", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Authorize(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, errors.CodePolicyError, resp.Code)
}

func TestHandler_ValidateToken_Success(t *testing.T) {
	jwtMock := &mockJWTService{
		validateFunc: func(ctx context.Context, token string) (*domain.TokenInfo, error) {
			exp := time.Now().Add(time.Hour)
			iat := time.Now()
			return &domain.TokenInfo{
				Subject:   "user123",
				Issuer:    "https://auth.example.com",
				Audience:  []string{"api.example.com"},
				ExpiresAt: exp,
				IssuedAt:  iat,
				Roles:     []string{"admin", "user"},
				Scopes:    []string{"openid", "profile"},
				ClientID:  "web-app",
				Valid:     true,
			}, nil
		},
	}
	h := NewHandler(jwtMock, nil, "1.0.0")

	req := httptest.NewRequest(http.MethodGet, "/v1/token/validate", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	h.ValidateToken(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp TokenInfoResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Valid)
	assert.Equal(t, "user123", resp.Subject)
	assert.Equal(t, "https://auth.example.com", resp.Issuer)
	assert.Contains(t, resp.Roles, "admin")
	assert.Contains(t, resp.Scopes, "openid")
}

func TestHandler_ValidateToken_MissingHeader(t *testing.T) {
	h := NewHandler(nil, nil, "1.0.0")

	req := httptest.NewRequest(http.MethodGet, "/v1/token/validate", nil)
	// No Authorization header
	w := httptest.NewRecorder()

	h.ValidateToken(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, errors.CodeTokenMissing, resp.Code)
}

func TestHandler_ValidateToken_InvalidToken(t *testing.T) {
	jwtMock := &mockJWTService{
		validateFunc: func(ctx context.Context, token string) (*domain.TokenInfo, error) {
			return nil, errors.NewAuthzError(errors.CodeTokenExpired, "token has expired", nil)
		},
	}
	h := NewHandler(jwtMock, nil, "1.0.0")

	req := httptest.NewRequest(http.MethodGet, "/v1/token/validate", nil)
	req.Header.Set("Authorization", "Bearer expired-token")
	w := httptest.NewRecorder()

	h.ValidateToken(w, req)

	assert.Equal(t, http.StatusOK, w.Code) // Returns 200 with valid=false

	var resp TokenInfoResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.False(t, resp.Valid)
	assert.Equal(t, errors.CodeTokenExpired, resp.ErrorCode)
	assert.Contains(t, resp.Error, "expired")
}

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestGetRequestID(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		expectUUID bool
	}{
		{
			name:       "from X-Request-ID header",
			headers:    map[string]string{"X-Request-ID": "custom-req-id"},
			expectUUID: false,
		},
		{
			name:       "from X-Correlation-ID header",
			headers:    map[string]string{"X-Correlation-ID": "correlation-123"},
			expectUUID: false,
		},
		{
			name:       "generate new UUID",
			headers:    map[string]string{},
			expectUUID: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			requestID := getRequestID(req)

			if tt.expectUUID {
				// Should be a valid UUID format
				assert.Len(t, requestID, 36) // UUID format: 8-4-4-4-12
			} else {
				// Should match header value
				for _, v := range tt.headers {
					assert.Equal(t, v, requestID)
					break
				}
			}
		})
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		remoteIP string
		expected string
	}{
		{
			name:     "from X-Forwarded-For",
			headers:  map[string]string{"X-Forwarded-For": "192.168.1.100, 10.0.0.1"},
			remoteIP: "127.0.0.1:8080",
			expected: "192.168.1.100, 10.0.0.1", // Returns full header
		},
		{
			name:     "from X-Forwarded-For single IP",
			headers:  map[string]string{"X-Forwarded-For": "192.168.1.100"},
			remoteIP: "127.0.0.1:8080",
			expected: "192.168.1.100",
		},
		{
			name:     "from X-Real-IP",
			headers:  map[string]string{"X-Real-IP": "192.168.1.100"},
			remoteIP: "127.0.0.1:8080",
			expected: "192.168.1.100",
		},
		{
			name:     "from RemoteAddr",
			headers:  map[string]string{},
			remoteIP: "192.168.1.100:12345",
			expected: "192.168.1.100:12345", // Returns full RemoteAddr
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteIP
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			clientIP := getClientIP(req)
			assert.Equal(t, tt.expected, clientIP)
		})
	}
}

// =============================================================================
// DTO Tests
// =============================================================================

func TestAuthzRequest_ToPolicyInput(t *testing.T) {
	req := AuthzRequest{
		Request: RequestDTO{
			Method:   "POST",
			Path:     "/api/users",
			Host:     "api.example.com",
			Headers:  map[string]string{"Content-Type": "application/json"},
			Query:    map[string]string{"page": "1"},
			Protocol: "HTTP/1.1",
		},
		Context: map[string]any{
			"custom_field": "value",
		},
	}

	input := req.ToPolicyInput()

	assert.Equal(t, "POST", input.Request.Method)
	assert.Equal(t, "/api/users", input.Request.Path)
	assert.Equal(t, "api.example.com", input.Request.Host)
	assert.Equal(t, "application/json", input.Request.Headers["Content-Type"])
	assert.Equal(t, "1", input.Request.Query["page"])
	assert.Equal(t, "HTTP/1.1", input.Request.Protocol)
	assert.Equal(t, "value", input.Context.Custom["custom_field"])
}

func TestFromDecision(t *testing.T) {
	decision := &domain.Decision{
		Allowed:       true,
		Reasons:       []string{"policy matched"},
		PolicyVersion: "v1.0",
		Cached:        true,
		EvaluatedAt:   time.Now(),
		Metadata:      map[string]any{"rule": "allow-all"},
	}

	resp := FromDecision(decision)

	assert.True(t, resp.Allowed)
	assert.Equal(t, []string{"policy matched"}, resp.Reasons)
	assert.Equal(t, "v1.0", resp.PolicyVersion)
	assert.True(t, resp.Cached)
	assert.Equal(t, "allow-all", resp.Metadata["rule"])
}

func TestFromTokenInfo(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	iat := time.Now()
	token := &domain.TokenInfo{
		Valid:       true,
		Subject:     "user123",
		Issuer:      "https://auth.example.com",
		Audience:    []string{"api.example.com"},
		ExpiresAt:   exp,
		IssuedAt:    iat,
		Roles:       []string{"admin"},
		Scopes:      []string{"openid"},
		ClientID:    "web-app",
		ExtraClaims: map[string]any{"custom": "value"},
	}

	resp := FromTokenInfo(token)

	assert.True(t, resp.Valid)
	assert.Equal(t, "user123", resp.Subject)
	assert.Equal(t, "https://auth.example.com", resp.Issuer)
	assert.Contains(t, resp.Audience, "api.example.com")
	assert.NotNil(t, resp.ExpiresAt)
	assert.NotNil(t, resp.IssuedAt)
	assert.Contains(t, resp.Roles, "admin")
	assert.Contains(t, resp.Scopes, "openid")
	assert.Equal(t, "web-app", resp.ClientID)
	assert.Equal(t, "value", resp.ExtraClaims["custom"])
}

func TestFromTokenInfo_ZeroTimes(t *testing.T) {
	token := &domain.TokenInfo{
		Valid:   true,
		Subject: "user123",
		// ExpiresAt and IssuedAt are zero values
	}

	resp := FromTokenInfo(token)

	assert.Nil(t, resp.ExpiresAt)
	assert.Nil(t, resp.IssuedAt)
}

// =============================================================================
// AuthorizeBatch Tests
// =============================================================================

func TestHandler_AuthorizeBatch_Success(t *testing.T) {
	jwtMock := &mockJWTService{
		validateFunc: func(ctx context.Context, token string) (*domain.TokenInfo, error) {
			return &domain.TokenInfo{
				Subject: "user123",
				Roles:   []string{"admin"},
				Valid:   true,
			}, nil
		},
	}
	policyMock := &mockPolicyService{
		evaluateFunc: func(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
			if input.Request.Path == "/api/admin" {
				return domain.Deny("admin access denied"), nil
			}
			return domain.Allow("allowed"), nil
		},
	}
	h := NewHandler(jwtMock, policyMock, "1.0.0")

	body := BatchAuthzRequest{
		Token: "valid-token",
		Requests: []AuthzRequest{
			{Request: RequestDTO{Method: "GET", Path: "/api/users"}},
			{Request: RequestDTO{Method: "DELETE", Path: "/api/admin"}},
		},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/authorize/batch", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.AuthorizeBatch(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp BatchAuthzResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Len(t, resp.Responses, 2)
	assert.True(t, resp.Responses[0].Allowed)
	assert.False(t, resp.Responses[1].Allowed)
}

func TestHandler_AuthorizeBatch_InvalidJSON(t *testing.T) {
	h := NewHandler(nil, nil, "1.0.0")

	req := httptest.NewRequest(http.MethodPost, "/v1/authorize/batch", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.AuthorizeBatch(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "INVALID_REQUEST", resp.Code)
}

func TestHandler_AuthorizeBatch_EmptyRequests(t *testing.T) {
	h := NewHandler(nil, nil, "1.0.0")

	body := BatchAuthzRequest{
		Requests: []AuthzRequest{},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/authorize/batch", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.AuthorizeBatch(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp.Error, "empty")
}

func TestHandler_AuthorizeBatch_PolicyError(t *testing.T) {
	policyMock := &mockPolicyService{
		evaluateFunc: func(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
			return nil, assert.AnError
		},
	}
	h := NewHandler(nil, policyMock, "1.0.0")

	body := BatchAuthzRequest{
		Requests: []AuthzRequest{
			{Request: RequestDTO{Method: "GET", Path: "/api/users"}},
		},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/authorize/batch", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.AuthorizeBatch(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp BatchAuthzResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Len(t, resp.Responses, 1)
	assert.False(t, resp.Responses[0].Allowed)
	assert.Contains(t, resp.Responses[0].Reasons, "policy evaluation failed")
}

func TestHandler_AuthorizeBatch_NoSharedToken(t *testing.T) {
	policyMock := &mockPolicyService{
		evaluateFunc: func(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
			// Verify no token is set
			if input.Token != nil {
				return domain.Deny("unexpected token"), nil
			}
			return domain.Allow("anonymous allowed"), nil
		},
	}
	h := NewHandler(nil, policyMock, "1.0.0")

	body := BatchAuthzRequest{
		// No token
		Requests: []AuthzRequest{
			{Request: RequestDTO{Method: "GET", Path: "/public/docs"}},
		},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/authorize/batch", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.AuthorizeBatch(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp BatchAuthzResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Len(t, resp.Responses, 1)
	assert.True(t, resp.Responses[0].Allowed)
}

// =============================================================================
// TokenExchange Tests
// =============================================================================

func TestHandler_TokenExchange_JSONRequest(t *testing.T) {
	jwtMock := &mockJWTService{
		validateFunc: func(ctx context.Context, token string) (*domain.TokenInfo, error) {
			return &domain.TokenInfo{Subject: "user123", Valid: true}, nil
		},
	}
	h := NewHandler(jwtMock, nil, "1.0.0")

	body := TokenExchangeRequest{
		SubjectToken:     "valid-subject-token",
		SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
		Audience:         "target-api",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/token/exchange", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.TokenExchange(w, req)

	// Currently returns NOT_IMPLEMENTED
	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestHandler_TokenExchange_FormRequest(t *testing.T) {
	jwtMock := &mockJWTService{
		validateFunc: func(ctx context.Context, token string) (*domain.TokenInfo, error) {
			return &domain.TokenInfo{Subject: "user123", Valid: true}, nil
		},
	}
	h := NewHandler(jwtMock, nil, "1.0.0")

	form := "subject_token=valid-token&subject_token_type=access_token&audience=target-api"
	req := httptest.NewRequest(http.MethodPost, "/v1/token/exchange", bytes.NewReader([]byte(form)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.TokenExchange(w, req)

	// Currently returns NOT_IMPLEMENTED
	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestHandler_TokenExchange_InvalidJSON(t *testing.T) {
	h := NewHandler(nil, nil, "1.0.0")

	req := httptest.NewRequest(http.MethodPost, "/v1/token/exchange", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.TokenExchange(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "INVALID_REQUEST", resp.Code)
}

func TestHandler_TokenExchange_MissingSubjectToken(t *testing.T) {
	h := NewHandler(nil, nil, "1.0.0")

	body := TokenExchangeRequest{
		// No SubjectToken
		Audience: "target-api",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/token/exchange", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.TokenExchange(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp.Error, "subject_token")
}

func TestHandler_TokenExchange_InvalidSubjectToken(t *testing.T) {
	jwtMock := &mockJWTService{
		validateFunc: func(ctx context.Context, token string) (*domain.TokenInfo, error) {
			return nil, errors.NewAuthzError(errors.CodeTokenInvalid, "invalid token", nil)
		},
	}
	h := NewHandler(jwtMock, nil, "1.0.0")

	body := TokenExchangeRequest{
		SubjectToken: "invalid-token",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/token/exchange", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.TokenExchange(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, errors.CodeTokenInvalid, resp.Code)
}

// =============================================================================
// CacheInvalidate Tests
// =============================================================================

func TestHandler_CacheInvalidate_WithPattern(t *testing.T) {
	clearCalled := false
	cacheMock := &mockCacheService{
		clearFunc: func(ctx context.Context) {
			clearCalled = true
		},
	}
	h := NewHandler(nil, nil, "1.0.0", WithCacheService(cacheMock))

	body := CacheInvalidateRequest{
		Pattern: "user:*",
		Type:    "authorization",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/cache/invalidate", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.CacheInvalidate(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, clearCalled, "Clear should be called")

	var resp CacheInvalidateResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.NotNil(t, resp.Stats)
}

func TestHandler_CacheInvalidate_NoBody(t *testing.T) {
	cacheMock := &mockCacheService{}
	h := NewHandler(nil, nil, "1.0.0", WithCacheService(cacheMock))

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/cache/invalidate", nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.CacheInvalidate(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp CacheInvalidateResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestHandler_CacheInvalidate_WithKeys(t *testing.T) {
	cacheMock := &mockCacheService{}
	h := NewHandler(nil, nil, "1.0.0", WithCacheService(cacheMock))

	body := CacheInvalidateRequest{
		Keys: []string{"key1", "key2", "key3"},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/cache/invalidate", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.CacheInvalidate(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp CacheInvalidateResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestHandler_CacheInvalidate_NoCacheService(t *testing.T) {
	h := NewHandler(nil, nil, "1.0.0") // No cache service

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/cache/invalidate", nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.CacheInvalidate(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	var resp ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "CACHE_NOT_AVAILABLE", resp.Code)
}

// =============================================================================
// PolicyReload Tests
// =============================================================================

func TestHandler_PolicyReload_Success(t *testing.T) {
	policyMock := &mockPolicyService{
		reloadFunc: func(ctx context.Context) error {
			return nil
		},
	}
	h := NewHandler(nil, policyMock, "1.0.0")

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/policy/reload", nil)
	w := httptest.NewRecorder()

	h.PolicyReload(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, true, resp["success"])
	assert.Contains(t, resp["message"], "reloaded")
}

func TestHandler_PolicyReload_Error(t *testing.T) {
	policyMock := &mockPolicyService{
		reloadFunc: func(ctx context.Context) error {
			return assert.AnError
		},
	}
	h := NewHandler(nil, policyMock, "1.0.0")

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/policy/reload", nil)
	w := httptest.NewRecorder()

	h.PolicyReload(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "RELOAD_FAILED", resp.Code)
}

// =============================================================================
// RegisterRoutes Tests
// =============================================================================

func TestHandler_RegisterRoutes(t *testing.T) {
	h := NewHandler(nil, nil, "1.0.0")
	r := chi.NewRouter()

	// Should not panic
	require.NotPanics(t, func() {
		h.RegisterRoutes(r)
	})
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkHandler_Authorize(b *testing.B) {
	jwtMock := &mockJWTService{
		validateFunc: func(ctx context.Context, token string) (*domain.TokenInfo, error) {
			return &domain.TokenInfo{Subject: "user123", Valid: true}, nil
		},
	}
	policyMock := &mockPolicyService{
		evaluateFunc: func(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
			return domain.Allow(), nil
		},
	}
	h := NewHandler(jwtMock, policyMock, "1.0.0")

	body := AuthzRequest{
		Request: RequestDTO{
			Method: "GET",
			Path:   "/api/users",
		},
	}
	bodyBytes, _ := json.Marshal(body)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/authorize", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()
		h.Authorize(w, req)
	}
}

func BenchmarkHandler_ValidateToken(b *testing.B) {
	jwtMock := &mockJWTService{
		validateFunc: func(ctx context.Context, token string) (*domain.TokenInfo, error) {
			return &domain.TokenInfo{Subject: "user123", Valid: true}, nil
		},
	}
	h := NewHandler(jwtMock, nil, "1.0.0")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/v1/token/validate", nil)
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()
		h.ValidateToken(w, req)
	}
}

func BenchmarkHandler_Health(b *testing.B) {
	policyMock := &mockPolicyService{
		healthyFunc: func(ctx context.Context) bool { return true },
	}
	h := NewHandler(nil, policyMock, "1.0.0")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()
		h.Health(w, req)
	}
}

func BenchmarkFromDecision(b *testing.B) {
	decision := &domain.Decision{
		Allowed:       true,
		Reasons:       []string{"allowed"},
		PolicyVersion: "v1",
		EvaluatedAt:   time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FromDecision(decision)
	}
}

func BenchmarkAuthzRequest_ToPolicyInput(b *testing.B) {
	req := AuthzRequest{
		Request: RequestDTO{
			Method:  "GET",
			Path:    "/api/users",
			Headers: map[string]string{"Authorization": "Bearer token"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.ToPolicyInput()
	}
}
