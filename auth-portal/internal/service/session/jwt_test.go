package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/model"
)

func TestNewJWTStore(t *testing.T) {
	t.Run("valid config HS256", func(t *testing.T) {
		cfg := &config.SessionConfig{
			CookieName: "_auth_session",
			TTL:        time.Hour,
			Secure:     true,
			SameSite:   "lax",
			JWT: config.JWTStoreConfig{
				Algorithm:  "HS256",
				SigningKey: "test-secret-key-for-testing-1234",
			},
		}

		store, err := NewJWTStore(cfg)
		if err != nil {
			t.Fatalf("NewJWTStore failed: %v", err)
		}
		if store == nil {
			t.Fatal("NewJWTStore returned nil")
		}
		if store.cookieName != "_auth_session" {
			t.Errorf("cookieName = %s, want _auth_session", store.cookieName)
		}
		if !store.secure {
			t.Error("secure should be true")
		}
		if store.sameSite != http.SameSiteLaxMode {
			t.Errorf("sameSite = %v, want SameSiteLaxMode", store.sameSite)
		}
	})

	t.Run("missing signing key", func(t *testing.T) {
		cfg := &config.SessionConfig{
			JWT: config.JWTStoreConfig{
				Algorithm:  "HS256",
				SigningKey: "",
			},
		}

		_, err := NewJWTStore(cfg)
		if err == nil {
			t.Error("NewJWTStore should fail when signing key is missing")
		}
	})
}

func TestJWTStore_Name(t *testing.T) {
	cfg := &config.SessionConfig{
		JWT: config.JWTStoreConfig{
			Algorithm:  "HS256",
			SigningKey: "test-secret-key-for-testing-1234",
		},
	}

	store, err := NewJWTStore(cfg)
	if err != nil {
		t.Fatalf("NewJWTStore failed: %v", err)
	}

	if store.Name() != "jwt" {
		t.Errorf("Name() = %s, want jwt", store.Name())
	}
}

func TestJWTStore_Get_NoCookie(t *testing.T) {
	cfg := &config.SessionConfig{
		CookieName: "_auth_session",
		JWT: config.JWTStoreConfig{
			Algorithm:  "HS256",
			SigningKey: "test-secret-key-for-testing-1234",
		},
	}

	store, err := NewJWTStore(cfg)
	if err != nil {
		t.Fatalf("NewJWTStore failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err = store.Get(req)
	if err != ErrSessionNotFound {
		t.Errorf("Get should return ErrSessionNotFound, got %v", err)
	}
}

func TestJWTStore_Get_EmptyCookie(t *testing.T) {
	cfg := &config.SessionConfig{
		CookieName: "_auth_session",
		JWT: config.JWTStoreConfig{
			Algorithm:  "HS256",
			SigningKey: "test-secret-key-for-testing-1234",
		},
	}

	store, err := NewJWTStore(cfg)
	if err != nil {
		t.Fatalf("NewJWTStore failed: %v", err)
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

func TestJWTStore_Get_InvalidJWT(t *testing.T) {
	cfg := &config.SessionConfig{
		CookieName: "_auth_session",
		JWT: config.JWTStoreConfig{
			Algorithm:  "HS256",
			SigningKey: "test-secret-key-for-testing-1234",
		},
	}

	store, err := NewJWTStore(cfg)
	if err != nil {
		t.Fatalf("NewJWTStore failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "_auth_session",
		Value: "not-a-valid-jwt",
	})

	_, err = store.Get(req)
	if err != ErrSessionInvalid {
		t.Errorf("Get should return ErrSessionInvalid for invalid JWT, got %v", err)
	}
}

func TestJWTStore_SaveAndGet(t *testing.T) {
	cfg := &config.SessionConfig{
		CookieName: "_auth_session",
		TTL:        time.Hour,
		JWT: config.JWTStoreConfig{
			Algorithm:  "HS256",
			SigningKey: "test-secret-key-for-testing-1234",
		},
	}

	store, err := NewJWTStore(cfg)
	if err != nil {
		t.Fatalf("NewJWTStore failed: %v", err)
	}

	// Create session
	session := &model.Session{
		User: &model.User{
			ID:       "user-456",
			Email:    "test@example.com",
			Name:     "Test User",
			Roles:    []string{"admin", "user"},
			Groups:   []string{"engineering"},
			TenantID: "tenant-1",
		},
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

	if retrieved.User == nil {
		t.Fatal("session.User should not be nil")
	}
	if retrieved.User.ID != "user-456" {
		t.Errorf("session.User.ID = %s, want user-456", retrieved.User.ID)
	}
	if retrieved.User.Email != "test@example.com" {
		t.Errorf("session.User.Email = %s, want test@example.com", retrieved.User.Email)
	}
	if retrieved.User.Name != "Test User" {
		t.Errorf("session.User.Name = %s, want Test User", retrieved.User.Name)
	}
	if len(retrieved.User.Roles) != 2 {
		t.Errorf("session.User.Roles = %v, want 2 roles", retrieved.User.Roles)
	}
	if len(retrieved.User.Groups) != 1 {
		t.Errorf("session.User.Groups = %v, want 1 group", retrieved.User.Groups)
	}
	if retrieved.User.TenantID != "tenant-1" {
		t.Errorf("session.User.TenantID = %s, want tenant-1", retrieved.User.TenantID)
	}
}

func TestJWTStore_Save_NoUser(t *testing.T) {
	cfg := &config.SessionConfig{
		CookieName: "_auth_session",
		JWT: config.JWTStoreConfig{
			Algorithm:  "HS256",
			SigningKey: "test-secret-key-for-testing-1234",
		},
	}

	store, err := NewJWTStore(cfg)
	if err != nil {
		t.Fatalf("NewJWTStore failed: %v", err)
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

func TestJWTStore_Save_GeneratesSessionID(t *testing.T) {
	cfg := &config.SessionConfig{
		CookieName: "_auth_session",
		TTL:        time.Hour,
		JWT: config.JWTStoreConfig{
			Algorithm:  "HS256",
			SigningKey: "test-secret-key-for-testing-1234",
		},
	}

	store, err := NewJWTStore(cfg)
	if err != nil {
		t.Fatalf("NewJWTStore failed: %v", err)
	}

	session := &model.Session{
		ID: "", // empty - should be generated
		User: &model.User{
			ID:    "user-456",
			Email: "test@example.com",
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	err = store.Save(rr, req, session)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Session ID should be generated
	if session.ID == "" {
		t.Error("session.ID should be generated")
	}
}

func TestJWTStore_Delete(t *testing.T) {
	cfg := &config.SessionConfig{
		CookieName: "_auth_session",
		Secure:     true,
		SameSite:   "strict",
		JWT: config.JWTStoreConfig{
			Algorithm:  "HS256",
			SigningKey: "test-secret-key-for-testing-1234",
		},
	}

	store, err := NewJWTStore(cfg)
	if err != nil {
		t.Fatalf("NewJWTStore failed: %v", err)
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

func TestJWTStore_WrongSigningKey(t *testing.T) {
	cfg1 := &config.SessionConfig{
		CookieName: "_auth_session",
		TTL:        time.Hour,
		JWT: config.JWTStoreConfig{
			Algorithm:  "HS256",
			SigningKey: "signing-key-1-for-testing-32byte",
		},
	}

	cfg2 := &config.SessionConfig{
		CookieName: "_auth_session",
		TTL:        time.Hour,
		JWT: config.JWTStoreConfig{
			Algorithm:  "HS256",
			SigningKey: "signing-key-2-for-testing-32byte",
		},
	}

	store1, _ := NewJWTStore(cfg1)
	store2, _ := NewJWTStore(cfg2)

	// Save with store1
	session := &model.Session{
		User: &model.User{
			ID:    "user-456",
			Email: "test@example.com",
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_ = store1.Save(rr, req, session)

	// Try to get with store2 (different key)
	cookie := rr.Result().Cookies()[0]
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.AddCookie(cookie)

	_, err := store2.Get(req2)
	if err != ErrSessionInvalid {
		t.Errorf("Get should return ErrSessionInvalid for wrong signing key, got %v", err)
	}
}

func BenchmarkJWTStore_SaveAndGet(b *testing.B) {
	cfg := &config.SessionConfig{
		CookieName: "_auth_session",
		TTL:        time.Hour,
		JWT: config.JWTStoreConfig{
			Algorithm:  "HS256",
			SigningKey: "test-secret-key-for-testing-1234",
		},
	}

	store, _ := NewJWTStore(cfg)
	session := &model.Session{
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
