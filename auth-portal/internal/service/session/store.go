package session

import (
	"context"
	"errors"
	"net/http"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/model"
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
	ErrSessionInvalid  = errors.New("session invalid")
	ErrStoreFull       = errors.New("session data too large for store")
)

// Store defines the interface for session storage
type Store interface {
	// Get retrieves a session from the request
	Get(r *http.Request) (*model.Session, error)

	// Save saves a session and sets the appropriate cookie
	Save(w http.ResponseWriter, r *http.Request, session *model.Session) error

	// Delete removes a session and clears the cookie
	Delete(w http.ResponseWriter, r *http.Request) error

	// Name returns the store type name
	Name() string
}

// Manager manages session operations
type Manager struct {
	store  Store
	config *config.SessionConfig
}

// NewManager creates a new session manager based on configuration
func NewManager(cfg *config.SessionConfig) (*Manager, error) {
	var store Store
	var err error

	switch cfg.Store {
	case "cookie":
		store, err = NewCookieStore(cfg)
	case "jwt":
		store, err = NewJWTStore(cfg)
	case "redis":
		store, err = NewRedisStore(cfg)
	default:
		store, err = NewCookieStore(cfg) // default to cookie
	}

	if err != nil {
		return nil, err
	}

	return &Manager{
		store:  store,
		config: cfg,
	}, nil
}

// Get retrieves the current session
func (m *Manager) Get(r *http.Request) (*model.Session, error) {
	return m.store.Get(r)
}

// Save saves the session
func (m *Manager) Save(w http.ResponseWriter, r *http.Request, session *model.Session) error {
	return m.store.Save(w, r, session)
}

// Delete removes the session
func (m *Manager) Delete(w http.ResponseWriter, r *http.Request) error {
	return m.store.Delete(w, r)
}

// GetOrCreate gets an existing session or creates a new one
func (m *Manager) GetOrCreate(r *http.Request) (*model.Session, bool, error) {
	session, err := m.Get(r)
	if err == nil {
		return session, false, nil
	}

	if errors.Is(err, ErrSessionNotFound) || errors.Is(err, ErrSessionExpired) {
		// Create new session (without user - will be set after auth)
		return &model.Session{}, true, nil
	}

	return nil, false, err
}

// IsAuthenticated checks if the request has a valid authenticated session
func (m *Manager) IsAuthenticated(r *http.Request) bool {
	session, err := m.Get(r)
	if err != nil {
		return false
	}
	return session.User != nil && !session.IsExpired()
}

// StoreName returns the name of the underlying store
func (m *Manager) StoreName() string {
	return m.store.Name()
}

// Middleware returns an HTTP middleware that loads session into context
func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := m.Get(r)
		if err == nil && session != nil {
			// Add session to context
			ctx := context.WithValue(r.Context(), sessionContextKey, session)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

// contextKey is the type for context keys
type contextKey string

const sessionContextKey contextKey = "session"

// FromContext retrieves session from context
func FromContext(ctx context.Context) *model.Session {
	if session, ok := ctx.Value(sessionContextKey).(*model.Session); ok {
		return session
	}
	return nil
}

// FromRequest retrieves session from request context
func FromRequest(r *http.Request) *model.Session {
	return FromContext(r.Context())
}
