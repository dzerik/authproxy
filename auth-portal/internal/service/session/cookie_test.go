package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/model"
)

func TestNewCookieStore(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		cfg := &config.SessionConfig{
			CookieName: "_auth_session",
			TTL:        time.Hour,
			Secure:     true,
			SameSite:   "strict",
			Encryption: config.EncryptionConfig{
				Enabled: true,
				Key:     "abcdefghijklmnopqrstuvwxyz!@#$%^",
			},
		}

		store, err := NewCookieStore(cfg)
		if err != nil {
			t.Fatalf("NewCookieStore failed: %v", err)
		}
		if store == nil {
			t.Fatal("NewCookieStore returned nil")
		}
		if store.cookieName != "_auth_session" {
			t.Errorf("cookieName = %s, want _auth_session", store.cookieName)
		}
		if !store.secure {
			t.Error("secure should be true")
		}
		if store.sameSite != http.SameSiteStrictMode {
			t.Errorf("sameSite = %v, want SameSiteStrictMode", store.sameSite)
		}
	})

	t.Run("encryption disabled", func(t *testing.T) {
		cfg := &config.SessionConfig{
			Encryption: config.EncryptionConfig{
				Enabled: false,
			},
		}

		_, err := NewCookieStore(cfg)
		if err == nil {
			t.Error("NewCookieStore should fail when encryption is disabled")
		}
	})

	t.Run("invalid encryption key", func(t *testing.T) {
		cfg := &config.SessionConfig{
			Encryption: config.EncryptionConfig{
				Enabled: true,
				Key:     "short-key",
			},
		}

		_, err := NewCookieStore(cfg)
		if err == nil {
			t.Error("NewCookieStore should fail with invalid encryption key")
		}
	})

	t.Run("default max size", func(t *testing.T) {
		cfg := &config.SessionConfig{
			Encryption: config.EncryptionConfig{
				Enabled: true,
				Key:     "abcdefghijklmnopqrstuvwxyz!@#$%^",
			},
			Cookie: config.CookieStoreConfig{
				MaxSize: 0, // should default to 4096
			},
		}

		store, err := NewCookieStore(cfg)
		if err != nil {
			t.Fatalf("NewCookieStore failed: %v", err)
		}
		if store.maxSize != 4096 {
			t.Errorf("maxSize = %d, want 4096", store.maxSize)
		}
	})
}

func TestCookieStore_Name(t *testing.T) {
	cfg := &config.SessionConfig{
		Encryption: config.EncryptionConfig{
			Enabled: true,
			Key:     "abcdefghijklmnopqrstuvwxyz!@#$%^",
		},
	}

	store, err := NewCookieStore(cfg)
	if err != nil {
		t.Fatalf("NewCookieStore failed: %v", err)
	}

	if store.Name() != "cookie" {
		t.Errorf("Name() = %s, want cookie", store.Name())
	}
}

func TestCookieStore_Get_NoCookie(t *testing.T) {
	cfg := &config.SessionConfig{
		CookieName: "_auth_session",
		Encryption: config.EncryptionConfig{
			Enabled: true,
			Key:     "abcdefghijklmnopqrstuvwxyz!@#$%^",
		},
	}

	store, err := NewCookieStore(cfg)
	if err != nil {
		t.Fatalf("NewCookieStore failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err = store.Get(req)
	if err != ErrSessionNotFound {
		t.Errorf("Get should return ErrSessionNotFound, got %v", err)
	}
}

func TestCookieStore_Get_EmptyCookie(t *testing.T) {
	cfg := &config.SessionConfig{
		CookieName: "_auth_session",
		Encryption: config.EncryptionConfig{
			Enabled: true,
			Key:     "abcdefghijklmnopqrstuvwxyz!@#$%^",
		},
	}

	store, err := NewCookieStore(cfg)
	if err != nil {
		t.Fatalf("NewCookieStore failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "_auth_session",
		Value: "",
	})

	_, err = store.Get(req)
	if err != ErrSessionNotFound {
		t.Errorf("Get should return ErrSessionNotFound for empty cookie, got %v", err)
	}
}

func TestCookieStore_Get_InvalidCookie(t *testing.T) {
	cfg := &config.SessionConfig{
		CookieName: "_auth_session",
		Encryption: config.EncryptionConfig{
			Enabled: true,
			Key:     "abcdefghijklmnopqrstuvwxyz!@#$%^",
		},
	}

	store, err := NewCookieStore(cfg)
	if err != nil {
		t.Fatalf("NewCookieStore failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "_auth_session",
		Value: "not-valid-encrypted-data",
	})

	_, err = store.Get(req)
	if err != ErrSessionInvalid {
		t.Errorf("Get should return ErrSessionInvalid for invalid cookie, got %v", err)
	}
}

func TestCookieStore_SaveAndGet(t *testing.T) {
	cfg := &config.SessionConfig{
		CookieName: "_auth_session",
		TTL:        time.Hour,
		Encryption: config.EncryptionConfig{
			Enabled: true,
			Key:     "abcdefghijklmnopqrstuvwxyz!@#$%^",
		},
	}

	store, err := NewCookieStore(cfg)
	if err != nil {
		t.Fatalf("NewCookieStore failed: %v", err)
	}

	// Create session
	session := &model.Session{
		ID: "session-123",
		User: &model.User{
			ID:    "user-456",
			Email: "test@example.com",
			Name:  "Test User",
			Roles: []string{"admin"},
		},
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		CreatedAt:    time.Now(),
	}

	// Save session
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	err = store.Save(rr, req, session)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Check cookie was set
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != "_auth_session" {
		t.Errorf("cookie name = %s, want _auth_session", cookie.Name)
	}
	if cookie.Value == "" {
		t.Error("cookie value should not be empty")
	}
	if !cookie.HttpOnly {
		t.Error("cookie should be HttpOnly")
	}

	// Get session back
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.AddCookie(cookie)

	retrieved, err := store.Get(req2)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if retrieved.ID != "session-123" {
		t.Errorf("session.ID = %s, want session-123", retrieved.ID)
	}
	if retrieved.User == nil {
		t.Fatal("session.User should not be nil")
	}
	if retrieved.User.ID != "user-456" {
		t.Errorf("session.User.ID = %s, want user-456", retrieved.User.ID)
	}
	if retrieved.User.Email != "test@example.com" {
		t.Errorf("session.User.Email = %s, want test@example.com", retrieved.User.Email)
	}
}

func TestCookieStore_Save_NoUser(t *testing.T) {
	cfg := &config.SessionConfig{
		CookieName: "_auth_session",
		Encryption: config.EncryptionConfig{
			Enabled: true,
			Key:     "abcdefghijklmnopqrstuvwxyz!@#$%^",
		},
	}

	store, err := NewCookieStore(cfg)
	if err != nil {
		t.Fatalf("NewCookieStore failed: %v", err)
	}

	session := &model.Session{
		ID:   "session-123",
		User: nil, // no user
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	err = store.Save(rr, req, session)
	if err == nil {
		t.Error("Save should fail when session has no user")
	}
}

func TestCookieStore_Delete(t *testing.T) {
	cfg := &config.SessionConfig{
		CookieName: "_auth_session",
		Secure:     true,
		SameSite:   "strict",
		Encryption: config.EncryptionConfig{
			Enabled: true,
			Key:     "abcdefghijklmnopqrstuvwxyz!@#$%^",
		},
	}

	store, err := NewCookieStore(cfg)
	if err != nil {
		t.Fatalf("NewCookieStore failed: %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	err = store.Delete(rr, req)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Check cookie was cleared
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != "_auth_session" {
		t.Errorf("cookie name = %s, want _auth_session", cookie.Name)
	}
	if cookie.Value != "" {
		t.Error("cookie value should be empty")
	}
	if cookie.MaxAge != -1 {
		t.Errorf("cookie MaxAge = %d, want -1", cookie.MaxAge)
	}
}

func TestCookieStore_ExpiredSession(t *testing.T) {
	cfg := &config.SessionConfig{
		CookieName: "_auth_session",
		TTL:        -time.Hour, // Already expired
		Encryption: config.EncryptionConfig{
			Enabled: true,
			Key:     "abcdefghijklmnopqrstuvwxyz!@#$%^",
		},
	}

	store, err := NewCookieStore(cfg)
	if err != nil {
		t.Fatalf("NewCookieStore failed: %v", err)
	}

	// Create session with expired time
	session := &model.Session{
		ID: "session-123",
		User: &model.User{
			ID:    "user-456",
			Email: "test@example.com",
		},
		ExpiresAt: time.Now().Add(-time.Hour), // Expired
	}

	// Save session
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	err = store.Save(rr, req, session)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Get session - should be expired
	cookie := rr.Result().Cookies()[0]
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.AddCookie(cookie)

	_, err = store.Get(req2)
	if err != ErrSessionExpired {
		t.Errorf("Get should return ErrSessionExpired, got %v", err)
	}
}

func BenchmarkCookieStore_SaveAndGet(b *testing.B) {
	cfg := &config.SessionConfig{
		CookieName: "_auth_session",
		TTL:        time.Hour,
		Encryption: config.EncryptionConfig{
			Enabled: true,
			Key:     "abcdefghijklmnopqrstuvwxyz!@#$%^",
		},
	}

	store, _ := NewCookieStore(cfg)
	session := &model.Session{
		ID: "session-123",
		User: &model.User{
			ID:    "user-456",
			Email: "test@example.com",
			Roles: []string{"admin", "user"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		_ = store.Save(rr, req, session)

		cookie := rr.Result().Cookies()[0]
		req2 := httptest.NewRequest(http.MethodGet, "/", nil)
		req2.AddCookie(cookie)
		_, _ = store.Get(req2)
	}
}
