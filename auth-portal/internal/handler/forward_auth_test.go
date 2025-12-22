package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestForwardAuthHandler_buildOriginalURL(t *testing.T) {
	h := &ForwardAuthHandler{}

	tests := []struct {
		name     string
		setup    func(*http.Request)
		expected string
	}{
		{
			name: "basic http request",
			setup: func(r *http.Request) {
				r.Host = "example.com"
			},
			expected: "http://example.com/test",
		},
		{
			name: "with X-Forwarded-Proto https",
			setup: func(r *http.Request) {
				r.Host = "example.com"
				r.Header.Set("X-Forwarded-Proto", "https")
			},
			expected: "https://example.com/test",
		},
		{
			name: "with X-Forwarded-Scheme https",
			setup: func(r *http.Request) {
				r.Host = "example.com"
				r.Header.Set("X-Forwarded-Scheme", "https")
			},
			expected: "https://example.com/test",
		},
		{
			name: "with X-Forwarded-Host",
			setup: func(r *http.Request) {
				r.Host = "internal-host"
				r.Header.Set("X-Forwarded-Host", "external.example.com")
			},
			expected: "http://external.example.com/test",
		},
		{
			name: "with X-Forwarded-Uri",
			setup: func(r *http.Request) {
				r.Host = "example.com"
				r.Header.Set("X-Forwarded-Uri", "/original/path?param=value")
			},
			expected: "http://example.com/original/path?param=value",
		},
		{
			name: "all forwarded headers",
			setup: func(r *http.Request) {
				r.Host = "internal-host"
				r.Header.Set("X-Forwarded-Proto", "https")
				r.Header.Set("X-Forwarded-Host", "api.example.com")
				r.Header.Set("X-Forwarded-Uri", "/api/v1/resource")
			},
			expected: "https://api.example.com/api/v1/resource",
		},
		{
			name: "with port in host",
			setup: func(r *http.Request) {
				r.Host = "example.com:8080"
			},
			expected: "http://example.com:8080/test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://localhost/test", nil)
			tt.setup(req)

			result := h.buildOriginalURL(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestForwardAuthHandler_renderJSONError(t *testing.T) {
	h := &ForwardAuthHandler{}

	tests := []struct {
		name           string
		message        string
		status         int
		expectedStatus int
	}{
		{"bad request", "Invalid request", http.StatusBadRequest, http.StatusBadRequest},
		{"unauthorized", "Authentication required", http.StatusUnauthorized, http.StatusUnauthorized},
		{"internal error", "Something went wrong", http.StatusInternalServerError, http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()

			h.renderJSONError(rr, tt.message, tt.status)

			assert.Equal(t, tt.expectedStatus, rr.Code)
			assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
		})
	}
}

func TestForwardAuthHandler_handleUnauthenticated(t *testing.T) {
	h := &ForwardAuthHandler{}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth", nil)

	h.handleUnauthenticated(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	wwwAuth := rr.Header().Get("WWW-Authenticate")
	assert.NotEmpty(t, wwwAuth, "WWW-Authenticate header should be set")
	assert.Equal(t, `Bearer realm="auth-portal"`, wwwAuth)
}

func TestNewForwardAuthHandler(t *testing.T) {
	// Test that constructor works with nil values (for basic testing)
	h := NewForwardAuthHandler(nil, nil, nil)
	require.NotNil(t, h)
}
