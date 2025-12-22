package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		require.NoError(t, err)
		require.NotNil(t, store)
		assert.Equal(t, "_auth_session", store.cookieName)
		assert.True(t, store.secure)
		assert.Equal(t, http.SameSiteLaxMode, store.sameSite)
	})

	t.Run("missing signing key", func(t *testing.T) {
		cfg := &config.SessionConfig{
			JWT: config.JWTStoreConfig{
				Algorithm:  "HS256",
				SigningKey: "",
			},
		}

		_, err := NewJWTStore(cfg)
		assert.Error(t, err)
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
	require.NoError(t, err)

	assert.Equal(t, "jwt", store.Name())
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
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err = store.Get(req)
	assert.Equal(t, ErrSessionNotFound, err)
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
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "_auth_session",
		Value: "",
	})

	_, err = store.Get(req)
	assert.Equal(t, ErrSessionNotFound, err)
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
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "_auth_session",
		Value: "not-a-valid-jwt",
	})

	_, err = store.Get(req)
	assert.Equal(t, ErrSessionInvalid, err)
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
	require.NoError(t, err)

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
	require.NoError(t, err)

	// Check cookie was set
	cookies := rr.Result().Cookies()
	require.Len(t, cookies, 1)

	cookie := cookies[0]
	assert.Equal(t, "_auth_session", cookie.Name)
	assert.NotEmpty(t, cookie.Value)
	assert.True(t, cookie.HttpOnly)

	// Get session back
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.AddCookie(cookie)

	retrieved, err := store.Get(req2)
	require.NoError(t, err)

	require.NotNil(t, retrieved.User)
	assert.Equal(t, "user-456", retrieved.User.ID)
	assert.Equal(t, "test@example.com", retrieved.User.Email)
	assert.Equal(t, "Test User", retrieved.User.Name)
	assert.Len(t, retrieved.User.Roles, 2)
	assert.Len(t, retrieved.User.Groups, 1)
	assert.Equal(t, "tenant-1", retrieved.User.TenantID)
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
	require.NoError(t, err)

	session := &model.Session{
		ID:   "session-123",
		User: nil, // no user
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	err = store.Save(rr, req, session)
	assert.Error(t, err)
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
	require.NoError(t, err)

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
	require.NoError(t, err)

	// Session ID should be generated
	assert.NotEmpty(t, session.ID)
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
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	err = store.Delete(rr, req)
	require.NoError(t, err)

	// Check cookie was cleared
	cookies := rr.Result().Cookies()
	require.Len(t, cookies, 1)

	cookie := cookies[0]
	assert.Equal(t, "_auth_session", cookie.Name)
	assert.Empty(t, cookie.Value)
	assert.Equal(t, -1, cookie.MaxAge)
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
	assert.Equal(t, ErrSessionInvalid, err)
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
