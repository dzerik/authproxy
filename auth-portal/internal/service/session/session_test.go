package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.Equal(t, "cookie", m.StoreName())
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
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.Equal(t, "jwt", m.StoreName())
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
	require.NoError(t, err)
	assert.Equal(t, "cookie", m.StoreName())
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
	assert.Error(t, err)
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
	require.NoError(t, err)

	// Request without session cookie
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	assert.False(t, m.IsAuthenticated(req))
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
	require.NoError(t, err)

	// Request without session - should create new
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	session, created, err := m.GetOrCreate(req)
	require.NoError(t, err)
	assert.True(t, created)
	require.NotNil(t, session)
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
	require.NotNil(t, retrieved)
	assert.Equal(t, "test-session", retrieved.ID)

	// Context without session
	ctx = context.Background()
	retrieved = FromContext(ctx)
	assert.Nil(t, retrieved)
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
	require.NotNil(t, retrieved)
	assert.Equal(t, "test-session", retrieved.ID)

	// Request without session
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	retrieved = FromRequest(req)
	assert.Nil(t, retrieved)
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
	require.NoError(t, err)

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

	assert.Equal(t, http.StatusOK, rr.Code)

	// Session should be nil (no cookie)
	assert.Nil(t, sessionInContext)
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
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestErrors(t *testing.T) {
	t.Run("ErrSessionNotFound", func(t *testing.T) {
		assert.NotEmpty(t, ErrSessionNotFound.Error())
	})

	t.Run("ErrSessionExpired", func(t *testing.T) {
		assert.NotEmpty(t, ErrSessionExpired.Error())
	})

	t.Run("ErrSessionInvalid", func(t *testing.T) {
		assert.NotEmpty(t, ErrSessionInvalid.Error())
	})

	t.Run("ErrStoreFull", func(t *testing.T) {
		assert.NotEmpty(t, ErrStoreFull.Error())
	})
}
