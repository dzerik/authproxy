package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/model"
)

func TestNewManager_CookieStore(t *testing.T) {
	cfg := &config.SessionConfig{
		Store:      "cookie",
		CookieName: "_auth_session",
		TTL:        time.Hour,
		Encryption: config.EncryptionConfig{
			Enabled: true,
			Key:     "abcdefghijklmnopqrstuvwxyz!@#$%^", // 32 bytes
		},
	}

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.StoreName() != "cookie" {
		t.Errorf("StoreName = %s, want cookie", m.StoreName())
	}
}

func TestNewManager_JWTStore(t *testing.T) {
	cfg := &config.SessionConfig{
		Store:      "jwt",
		CookieName: "_auth_session",
		TTL:        time.Hour,
		JWT: config.JWTStoreConfig{
			Algorithm:  "HS256",
			SigningKey: "test-secret-key-for-testing-1234",
		},
	}

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.StoreName() != "jwt" {
		t.Errorf("StoreName = %s, want jwt", m.StoreName())
	}
}

func TestNewManager_DefaultStore(t *testing.T) {
	cfg := &config.SessionConfig{
		Store:      "", // empty - should default to cookie
		CookieName: "_auth_session",
		TTL:        time.Hour,
		Encryption: config.EncryptionConfig{
			Enabled: true,
			Key:     "abcdefghijklmnopqrstuvwxyz!@#$%^",
		},
	}

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	if m.StoreName() != "cookie" {
		t.Errorf("StoreName = %s, want cookie (default)", m.StoreName())
	}
}

func TestNewManager_InvalidConfig(t *testing.T) {
	cfg := &config.SessionConfig{
		Store:      "cookie",
		CookieName: "_auth_session",
		Encryption: config.EncryptionConfig{
			Enabled: false, // encryption required for cookie store
		},
	}

	_, err := NewManager(cfg)
	if err == nil {
		t.Error("NewManager should fail when encryption is disabled for cookie store")
	}
}

func TestManager_IsAuthenticated(t *testing.T) {
	cfg := &config.SessionConfig{
		Store:      "cookie",
		CookieName: "_auth_session",
		TTL:        time.Hour,
		Encryption: config.EncryptionConfig{
			Enabled: true,
			Key:     "abcdefghijklmnopqrstuvwxyz!@#$%^",
		},
	}

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Request without session cookie
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if m.IsAuthenticated(req) {
		t.Error("IsAuthenticated should return false for request without session")
	}
}

func TestManager_GetOrCreate(t *testing.T) {
	cfg := &config.SessionConfig{
		Store:      "cookie",
		CookieName: "_auth_session",
		TTL:        time.Hour,
		Encryption: config.EncryptionConfig{
			Enabled: true,
			Key:     "abcdefghijklmnopqrstuvwxyz!@#$%^",
		},
	}

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Request without session - should create new
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	session, created, err := m.GetOrCreate(req)
	if err != nil {
		t.Fatalf("GetOrCreate failed: %v", err)
	}
	if !created {
		t.Error("created should be true for new session")
	}
	if session == nil {
		t.Error("session should not be nil")
	}
}

func TestFromContext(t *testing.T) {
	session := &model.Session{
		ID: "test-session",
		User: &model.User{
			ID:    "user-1",
			Email: "test@example.com",
		},
	}

	// Context with session
	ctx := context.WithValue(context.Background(), sessionContextKey, session)
	retrieved := FromContext(ctx)
	if retrieved == nil {
		t.Fatal("FromContext should return session")
	}
	if retrieved.ID != "test-session" {
		t.Errorf("session.ID = %s, want test-session", retrieved.ID)
	}

	// Context without session
	ctx = context.Background()
	retrieved = FromContext(ctx)
	if retrieved != nil {
		t.Error("FromContext should return nil for context without session")
	}
}

func TestFromRequest(t *testing.T) {
	session := &model.Session{
		ID: "test-session",
		User: &model.User{
			ID:    "user-1",
			Email: "test@example.com",
		},
	}

	// Request with session in context
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := context.WithValue(req.Context(), sessionContextKey, session)
	req = req.WithContext(ctx)

	retrieved := FromRequest(req)
	if retrieved == nil {
		t.Fatal("FromRequest should return session")
	}
	if retrieved.ID != "test-session" {
		t.Errorf("session.ID = %s, want test-session", retrieved.ID)
	}

	// Request without session
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	retrieved = FromRequest(req)
	if retrieved != nil {
		t.Error("FromRequest should return nil for request without session")
	}
}

func TestManager_Middleware(t *testing.T) {
	cfg := &config.SessionConfig{
		Store:      "cookie",
		CookieName: "_auth_session",
		TTL:        time.Hour,
		Encryption: config.EncryptionConfig{
			Enabled: true,
			Key:     "abcdefghijklmnopqrstuvwxyz!@#$%^",
		},
	}

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Create a handler that checks for session in context
	var sessionInContext *model.Session
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionInContext = FromRequest(r)
		w.WriteHeader(http.StatusOK)
	})

	// Wrap with middleware
	middleware := m.Middleware(handler)

	// Request without session cookie
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	middleware.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Session should be nil (no cookie)
	if sessionInContext != nil {
		t.Error("session should be nil when no session cookie")
	}
}

func TestParseSameSite(t *testing.T) {
	tests := []struct {
		input    string
		expected http.SameSite
	}{
		{"strict", http.SameSiteStrictMode},
		{"lax", http.SameSiteLaxMode},
		{"none", http.SameSiteNoneMode},
		{"", http.SameSiteLaxMode},       // default
		{"invalid", http.SameSiteLaxMode}, // default for unknown
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseSameSite(tt.input)
			if result != tt.expected {
				t.Errorf("parseSameSite(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestErrors(t *testing.T) {
	t.Run("ErrSessionNotFound", func(t *testing.T) {
		if ErrSessionNotFound.Error() == "" {
			t.Error("ErrSessionNotFound should have message")
		}
	})

	t.Run("ErrSessionExpired", func(t *testing.T) {
		if ErrSessionExpired.Error() == "" {
			t.Error("ErrSessionExpired should have message")
		}
	})

	t.Run("ErrSessionInvalid", func(t *testing.T) {
		if ErrSessionInvalid.Error() == "" {
			t.Error("ErrSessionInvalid should have message")
		}
	})

	t.Run("ErrStoreFull", func(t *testing.T) {
		if ErrStoreFull.Error() == "" {
			t.Error("ErrStoreFull should have message")
		}
	})
}
