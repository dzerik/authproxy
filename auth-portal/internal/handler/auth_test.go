package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dzerik/auth-portal/internal/service/state"
)

// Tests for state store have been moved to internal/service/state package
// These tests now use the state package directly

func TestMemoryStateStore_SetAndGet(t *testing.T) {
	store := state.NewMemoryStore(10 * time.Minute)
	defer store.Close()

	s := &state.OAuthState{
		State:       "test-state-token",
		Nonce:       "test-nonce",
		RedirectURL: "https://example.com/callback",
		Provider:    "keycloak",
		CreatedAt:   time.Now(),
	}

	// Set state
	err := store.Set(s)
	require.NoError(t, err, "Set failed")

	// Get state (should succeed and remove it)
	retrieved, ok := store.Get("test-state-token")
	assert.True(t, ok, "Get should return true for existing state")
	require.NotNil(t, retrieved, "Get should return state")
	assert.Equal(t, "test-state-token", retrieved.State)
	assert.Equal(t, "test-nonce", retrieved.Nonce)
	assert.Equal(t, "https://example.com/callback", retrieved.RedirectURL)
	assert.Equal(t, "keycloak", retrieved.Provider)

	// Get again (should fail - state was removed)
	_, ok = store.Get("test-state-token")
	assert.False(t, ok, "Get should return false after state was consumed")
}

func TestMemoryStateStore_Get_NotExists(t *testing.T) {
	store := state.NewMemoryStore(10 * time.Minute)
	defer store.Close()

	_, ok := store.Get("nonexistent")
	assert.False(t, ok, "Get should return false for non-existing state")
}

func TestMemoryStateStore_Validate(t *testing.T) {
	store := state.NewMemoryStore(10 * time.Minute)
	defer store.Close()

	s := &state.OAuthState{
		State:     "test-state",
		CreatedAt: time.Now(),
	}

	// Set state
	store.Set(s)

	// Validate should return true
	assert.True(t, store.Validate("test-state"), "Validate should return true for existing state")

	// Validate again (state should still exist - Validate doesn't remove)
	assert.True(t, store.Validate("test-state"), "Validate should return true - state should still exist")

	// Non-existing state
	assert.False(t, store.Validate("nonexistent"), "Validate should return false for non-existing state")
}

func TestMemoryStateStore_Concurrency(t *testing.T) {
	store := state.NewMemoryStore(10 * time.Minute)
	defer store.Close()
	done := make(chan bool)

	// Concurrent writes
	for i := 0; i < 10; i++ {
		go func(i int) {
			s := &state.OAuthState{
				State:     "state-" + string(rune('0'+i)),
				CreatedAt: time.Now(),
			}
			store.Set(s)
			done <- true
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func(i int) {
			store.Validate("state-" + string(rune('0'+i)))
			done <- true
		}(i)
	}

	for i := 0; i < 20; i++ {
		<-done
	}
}

func TestOAuthState_Struct(t *testing.T) {
	now := time.Now()
	s := &state.OAuthState{
		State:       "state-123",
		Nonce:       "nonce-456",
		RedirectURL: "https://example.com",
		Provider:    "google",
		CreatedAt:   now,
	}

	assert.Equal(t, "state-123", s.State)
	assert.Equal(t, "nonce-456", s.Nonce)
	assert.Equal(t, "https://example.com", s.RedirectURL)
	assert.Equal(t, "google", s.Provider)
	assert.True(t, s.CreatedAt.Equal(now), "CreatedAt should equal now")
}

func TestLoginPageData_Struct(t *testing.T) {
	data := LoginPageData{
		Title:       "Login",
		RedirectURL: "/portal",
		DevMode:     true,
		DevProfiles: []string{"developer", "admin"},
		Error:       "",
	}

	assert.Equal(t, "Login", data.Title)
	assert.Equal(t, "/portal", data.RedirectURL)
	assert.True(t, data.DevMode, "DevMode should be true")
	assert.Len(t, data.DevProfiles, 2)
}

func TestErrorPageData_Struct(t *testing.T) {
	data := ErrorPageData{
		Title:   "Error",
		Message: "Something went wrong",
		Status:  500,
	}

	assert.Equal(t, "Error", data.Title)
	assert.Equal(t, "Something went wrong", data.Message)
	assert.Equal(t, 500, data.Status)
}

func TestExtractPathParam(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		prefix   string
		expected string
	}{
		{"extract provider", "/login/social/google", "/login/social/", "google"},
		{"extract dev profile", "/login/dev/admin", "/login/dev/", "admin"},
		{"extract service", "/service/grafana", "/service/", "grafana"},
		{"path equals prefix", "/login/social/", "/login/social/", ""},
		{"path shorter than prefix", "/login", "/login/social/", ""},
		{"empty path", "", "/prefix/", ""},
		{"path with extra parts", "/login/social/google/extra", "/login/social/", "google/extra"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractPathParam(tt.path, tt.prefix)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAuthHandler_buildAbsoluteURL(t *testing.T) {
	// Create a minimal auth handler for testing
	h := &AuthHandler{}

	t.Run("http request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
		req.Host = "example.com"

		url := h.buildAbsoluteURL(req, "/login")
		expected := "http://example.com/login"
		assert.Equal(t, expected, url)
	})

	t.Run("https from header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
		req.Host = "example.com"
		req.Header.Set("X-Forwarded-Proto", "https")

		url := h.buildAbsoluteURL(req, "/callback")
		expected := "https://example.com/callback"
		assert.Equal(t, expected, url)
	})

	t.Run("with port", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com:8080/test", nil)
		req.Host = "example.com:8080"

		url := h.buildAbsoluteURL(req, "/portal")
		expected := "http://example.com:8080/portal"
		assert.Equal(t, expected, url)
	})
}

func BenchmarkMemoryStateStore_SetGet(b *testing.B) {
	store := state.NewMemoryStore(10 * time.Minute)
	defer store.Close()
	s := &state.OAuthState{
		State:       "benchmark-state",
		Nonce:       "benchmark-nonce",
		RedirectURL: "https://example.com",
		Provider:    "keycloak",
		CreatedAt:   time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Set(s)
		store.Get("benchmark-state")
	}
}

func BenchmarkMemoryStateStore_Validate(b *testing.B) {
	store := state.NewMemoryStore(10 * time.Minute)
	defer store.Close()
	s := &state.OAuthState{
		State:     "benchmark-state",
		CreatedAt: time.Now(),
	}
	store.Set(s)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Validate("benchmark-state")
	}
}

// Tests for security fixes

func TestAuthHandler_validateRedirectURL(t *testing.T) {
	h := &AuthHandler{}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// Valid relative URLs
		{"valid relative path", "/portal", "/portal"},
		{"valid path with query", "/portal?foo=bar", "/portal?foo=bar"},
		{"valid nested path", "/service/grafana", "/service/grafana"},

		// Empty URL
		{"empty string", "", "/portal"},

		// Absolute URLs (Open Redirect prevention)
		{"http absolute URL", "http://evil.com", "/portal"},
		{"https absolute URL", "https://evil.com", "/portal"},
		{"ftp absolute URL", "ftp://evil.com", "/portal"},

		// Protocol-relative URLs (Open Redirect prevention)
		{"double slash prefix", "//evil.com", "/portal"},
		{"triple slash prefix", "///evil.com", "/portal"},

		// Path traversal attempts
		{"path traversal with dots", "/portal/../etc/passwd", "/portal"},
		{"path traversal in middle", "/service/../../../etc/passwd", "/portal"},
		{"encoded path traversal", "/portal/%2e%2e/etc/passwd", "/portal"},
		{"mixed case encoded", "/portal/%2E%2E/etc/passwd", "/portal"},

		// Valid edge cases
		{"single slash", "/", "/"},
		{"path with trailing slash", "/portal/", "/portal/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := h.validateRedirectURL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewAuthHandler(t *testing.T) {
	t.Run("creates handler with all dependencies", func(t *testing.T) {
		store := state.NewMemoryStore(10 * time.Minute)
		defer store.Close()

		handler := NewAuthHandler(nil, nil, nil, nil, store)

		require.NotNil(t, handler)
		assert.Nil(t, handler.idpManager)
		assert.Nil(t, handler.sessionManager)
		assert.Nil(t, handler.config)
		assert.Nil(t, handler.templates)
		assert.Equal(t, store, handler.stateStore)
	})
}

func TestAuthHandler_renderJSONError(t *testing.T) {
	h := &AuthHandler{}

	tests := []struct {
		name       string
		message    string
		status     int
		wantStatus int
	}{
		{"bad request", "Invalid input", http.StatusBadRequest, http.StatusBadRequest},
		{"unauthorized", "Not authenticated", http.StatusUnauthorized, http.StatusUnauthorized},
		{"internal error", "Server error", http.StatusInternalServerError, http.StatusInternalServerError},
		{"forbidden", "Access denied", http.StatusForbidden, http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.renderJSONError(w, tt.message, tt.status)

			assert.Equal(t, tt.wantStatus, w.Code)
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
			assert.Contains(t, w.Body.String(), tt.message)
			assert.Contains(t, w.Body.String(), `"status"`)
		})
	}
}

func TestAuthHandler_renderError_noTemplates(t *testing.T) {
	// When templates are nil, renderError should fall back to JSON
	h := &AuthHandler{templates: nil}

	w := httptest.NewRecorder()
	h.renderError(w, "Test error", http.StatusBadRequest)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Body.String(), "Test error")
}

func TestAuthHandler_extractNonceFromIDToken(t *testing.T) {
	h := &AuthHandler{}

	t.Run("valid token with nonce", func(t *testing.T) {
		// Create a mock JWT: header.payload.signature
		// Payload: {"nonce": "test-nonce-123"}
		// Base64URL: eyJub25jZSI6ICJ0ZXN0LW5vbmNlLTEyMyJ9
		token := "eyJhbGciOiJSUzI1NiJ9.eyJub25jZSI6InRlc3Qtbm9uY2UtMTIzIn0.signature"

		nonce, err := h.extractNonceFromIDToken(token)
		assert.NoError(t, err, "unexpected error")
		assert.Equal(t, "test-nonce-123", nonce)
	})

	t.Run("token without nonce", func(t *testing.T) {
		// Payload: {"sub": "user123"}
		// Base64URL: eyJzdWIiOiJ1c2VyMTIzIn0
		token := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature"

		nonce, err := h.extractNonceFromIDToken(token)
		assert.NoError(t, err, "unexpected error")
		assert.Empty(t, nonce, "nonce should be empty")
	})

	t.Run("invalid token format - too few parts", func(t *testing.T) {
		token := "not.a.valid"

		nonce, err := h.extractNonceFromIDToken(token)
		assert.NoError(t, err, "unexpected error")
		// Should return empty on invalid format, not error
		assert.Empty(t, nonce, "nonce should be empty for invalid token")
	})

	t.Run("invalid base64 payload", func(t *testing.T) {
		token := "header.!!!invalid-base64!!!.signature"

		nonce, err := h.extractNonceFromIDToken(token)
		assert.NoError(t, err, "unexpected error")
		// Should return empty on decode error, not error
		assert.Empty(t, nonce, "nonce should be empty for invalid base64")
	})

	t.Run("empty token", func(t *testing.T) {
		nonce, err := h.extractNonceFromIDToken("")

		assert.NoError(t, err, "unexpected error")
		assert.Empty(t, nonce, "nonce should be empty for empty token")
	})
}
