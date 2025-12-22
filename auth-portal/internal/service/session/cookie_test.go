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
		require.NoError(t, err)
		require.NotNil(t, store)
		assert.Equal(t, "_auth_session", store.cookieName)
		assert.True(t, store.secure)
		assert.Equal(t, http.SameSiteStrictMode, store.sameSite)
	})

	t.Run("encryption disabled", func(t *testing.T) {
		cfg := &config.SessionConfig{
			Encryption: config.EncryptionConfig{
				Enabled: false,
			},
		}

		_, err := NewCookieStore(cfg)
		assert.Error(t, err)
	})

	t.Run("invalid encryption key", func(t *testing.T) {
		cfg := &config.SessionConfig{
			Encryption: config.EncryptionConfig{
				Enabled: true,
				Key:     "short-key",
			},
		}

		_, err := NewCookieStore(cfg)
		assert.Error(t, err)
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
		require.NoError(t, err)
		assert.Equal(t, 4096, store.maxSize)
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
	require.NoError(t, err)

	assert.Equal(t, "cookie", store.Name())
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
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err = store.Get(req)
	assert.Equal(t, ErrSessionNotFound, err)
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
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "_auth_session",
		Value: "",
	})

	_, err = store.Get(req)
	assert.Equal(t, ErrSessionNotFound, err)
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
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "_auth_session",
		Value: "not-valid-encrypted-data",
	})

	_, err = store.Get(req)
	assert.Equal(t, ErrSessionInvalid, err)
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
	require.NoError(t, err)

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

	assert.Equal(t, "session-123", retrieved.ID)
	require.NotNil(t, retrieved.User)
	assert.Equal(t, "user-456", retrieved.User.ID)
	assert.Equal(t, "test@example.com", retrieved.User.Email)
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
	require.NoError(t, err)

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
	require.NoError(t, err)

	// Get session - should be expired
	cookie := rr.Result().Cookies()[0]
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.AddCookie(cookie)

	_, err = store.Get(req2)
	assert.Equal(t, ErrSessionExpired, err)
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
