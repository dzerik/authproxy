package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
			if result != tt.expected {
				t.Errorf("buildOriginalURL() = %s, want %s", result, tt.expected)
			}
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

			if rr.Code != tt.expectedStatus {
				t.Errorf("status = %d, want %d", rr.Code, tt.expectedStatus)
			}

			if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %s, want application/json", ct)
			}
		})
	}
}

func TestForwardAuthHandler_handleUnauthenticated(t *testing.T) {
	h := &ForwardAuthHandler{}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth", nil)

	h.handleUnauthenticated(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}

	wwwAuth := rr.Header().Get("WWW-Authenticate")
	if wwwAuth == "" {
		t.Error("WWW-Authenticate header should be set")
	}
	if wwwAuth != `Bearer realm="auth-portal"` {
		t.Errorf("WWW-Authenticate = %s, want Bearer realm=\"auth-portal\"", wwwAuth)
	}
}

func TestNewForwardAuthHandler(t *testing.T) {
	// Test that constructor works with nil values (for basic testing)
	h := NewForwardAuthHandler(nil, nil, nil)
	if h == nil {
		t.Fatal("NewForwardAuthHandler returned nil")
	}
}
