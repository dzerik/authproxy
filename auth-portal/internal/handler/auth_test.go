package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewStateStore(t *testing.T) {
	store := NewStateStore()
	if store == nil {
		t.Fatal("NewStateStore returned nil")
	}
	if store.states == nil {
		t.Error("states map should be initialized")
	}
}

func TestStateStore_SetAndGet(t *testing.T) {
	store := NewStateStore()

	state := &OAuthState{
		State:       "test-state-token",
		Nonce:       "test-nonce",
		RedirectURL: "https://example.com/callback",
		Provider:    "keycloak",
		CreatedAt:   time.Now(),
	}

	// Set state
	store.Set(state)

	// Get state (should succeed and remove it)
	retrieved, ok := store.Get("test-state-token")
	if !ok {
		t.Error("Get should return true for existing state")
	}
	if retrieved == nil {
		t.Fatal("Get should return state")
	}
	if retrieved.State != "test-state-token" {
		t.Errorf("State = %s, want test-state-token", retrieved.State)
	}
	if retrieved.Nonce != "test-nonce" {
		t.Errorf("Nonce = %s, want test-nonce", retrieved.Nonce)
	}
	if retrieved.RedirectURL != "https://example.com/callback" {
		t.Errorf("RedirectURL = %s, want https://example.com/callback", retrieved.RedirectURL)
	}
	if retrieved.Provider != "keycloak" {
		t.Errorf("Provider = %s, want keycloak", retrieved.Provider)
	}

	// Get again (should fail - state was removed)
	_, ok = store.Get("test-state-token")
	if ok {
		t.Error("Get should return false after state was consumed")
	}
}

func TestStateStore_Get_NotExists(t *testing.T) {
	store := NewStateStore()

	_, ok := store.Get("nonexistent")
	if ok {
		t.Error("Get should return false for non-existing state")
	}
}

func TestStateStore_Validate(t *testing.T) {
	store := NewStateStore()

	state := &OAuthState{
		State:     "test-state",
		CreatedAt: time.Now(),
	}

	// Set state
	store.Set(state)

	// Validate should return true
	if !store.Validate("test-state") {
		t.Error("Validate should return true for existing state")
	}

	// Validate again (state should still exist - Validate doesn't remove)
	if !store.Validate("test-state") {
		t.Error("Validate should return true - state should still exist")
	}

	// Non-existing state
	if store.Validate("nonexistent") {
		t.Error("Validate should return false for non-existing state")
	}
}

func TestStateStore_Concurrency(t *testing.T) {
	store := NewStateStore()
	done := make(chan bool)

	// Concurrent writes
	for i := 0; i < 10; i++ {
		go func(i int) {
			state := &OAuthState{
				State:     "state-" + string(rune('0'+i)),
				CreatedAt: time.Now(),
			}
			store.Set(state)
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
	state := &OAuthState{
		State:       "state-123",
		Nonce:       "nonce-456",
		RedirectURL: "https://example.com",
		Provider:    "google",
		CreatedAt:   now,
	}

	if state.State != "state-123" {
		t.Errorf("State = %s, want state-123", state.State)
	}
	if state.Nonce != "nonce-456" {
		t.Errorf("Nonce = %s, want nonce-456", state.Nonce)
	}
	if state.RedirectURL != "https://example.com" {
		t.Errorf("RedirectURL = %s, want https://example.com", state.RedirectURL)
	}
	if state.Provider != "google" {
		t.Errorf("Provider = %s, want google", state.Provider)
	}
	if !state.CreatedAt.Equal(now) {
		t.Error("CreatedAt should equal now")
	}
}

func TestLoginPageData_Struct(t *testing.T) {
	data := LoginPageData{
		Title:       "Login",
		RedirectURL: "/portal",
		DevMode:     true,
		DevProfiles: []string{"developer", "admin"},
		Error:       "",
	}

	if data.Title != "Login" {
		t.Errorf("Title = %s, want Login", data.Title)
	}
	if data.RedirectURL != "/portal" {
		t.Errorf("RedirectURL = %s, want /portal", data.RedirectURL)
	}
	if !data.DevMode {
		t.Error("DevMode should be true")
	}
	if len(data.DevProfiles) != 2 {
		t.Errorf("DevProfiles length = %d, want 2", len(data.DevProfiles))
	}
}

func TestErrorPageData_Struct(t *testing.T) {
	data := ErrorPageData{
		Title:   "Error",
		Message: "Something went wrong",
		Status:  500,
	}

	if data.Title != "Error" {
		t.Errorf("Title = %s, want Error", data.Title)
	}
	if data.Message != "Something went wrong" {
		t.Errorf("Message = %s, want Something went wrong", data.Message)
	}
	if data.Status != 500 {
		t.Errorf("Status = %d, want 500", data.Status)
	}
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
			if result != tt.expected {
				t.Errorf("extractPathParam(%q, %q) = %q, want %q", tt.path, tt.prefix, result, tt.expected)
			}
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
		if url != expected {
			t.Errorf("buildAbsoluteURL = %s, want %s", url, expected)
		}
	})

	t.Run("https from header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
		req.Host = "example.com"
		req.Header.Set("X-Forwarded-Proto", "https")

		url := h.buildAbsoluteURL(req, "/callback")
		expected := "https://example.com/callback"
		if url != expected {
			t.Errorf("buildAbsoluteURL = %s, want %s", url, expected)
		}
	})

	t.Run("with port", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com:8080/test", nil)
		req.Host = "example.com:8080"

		url := h.buildAbsoluteURL(req, "/portal")
		expected := "http://example.com:8080/portal"
		if url != expected {
			t.Errorf("buildAbsoluteURL = %s, want %s", url, expected)
		}
	})
}

func BenchmarkStateStore_SetGet(b *testing.B) {
	store := NewStateStore()
	state := &OAuthState{
		State:       "benchmark-state",
		Nonce:       "benchmark-nonce",
		RedirectURL: "https://example.com",
		Provider:    "keycloak",
		CreatedAt:   time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Set(state)
		store.Get("benchmark-state")
	}
}

func BenchmarkStateStore_Validate(b *testing.B) {
	store := NewStateStore()
	state := &OAuthState{
		State:     "benchmark-state",
		CreatedAt: time.Now(),
	}
	store.Set(state)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Validate("benchmark-state")
	}
}
