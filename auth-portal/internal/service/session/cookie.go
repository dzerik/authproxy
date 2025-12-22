package session

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/model"
	"github.com/dzerik/auth-portal/internal/service/crypto"
)

// CookieStore stores session data in an encrypted cookie
type CookieStore struct {
	cookieName   string
	cookieDomain string // MED-02 security fix: configurable domain for cross-subdomain sessions
	encryptor    *crypto.Encryptor
	secure       bool
	sameSite     http.SameSite
	ttl          time.Duration
	maxSize      int
}

// NewCookieStore creates a new cookie-based session store
func NewCookieStore(cfg *config.SessionConfig) (*CookieStore, error) {
	if !cfg.Encryption.Enabled {
		return nil, fmt.Errorf("encryption must be enabled for cookie store")
	}

	encryptor, err := crypto.NewEncryptorFromString(cfg.Encryption.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryptor: %w", err)
	}

	sameSite := parseSameSite(cfg.SameSite)

	maxSize := cfg.Cookie.MaxSize
	if maxSize == 0 {
		maxSize = 4096
	}

	return &CookieStore{
		cookieName:   cfg.CookieName,
		cookieDomain: cfg.CookieDomain,
		encryptor:    encryptor,
		secure:       cfg.Secure,
		sameSite:     sameSite,
		ttl:          cfg.TTL,
		maxSize:      maxSize,
	}, nil
}

// Get retrieves a session from the cookie
func (s *CookieStore) Get(r *http.Request) (*model.Session, error) {
	cookie, err := r.Cookie(s.cookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("failed to get cookie: %w", err)
	}

	if cookie.Value == "" {
		return nil, ErrSessionNotFound
	}

	// Decrypt cookie value
	decrypted, err := s.encryptor.DecryptString(cookie.Value)
	if err != nil {
		return nil, ErrSessionInvalid
	}

	// Unmarshal session data
	var sessionData model.SessionData
	if err := json.Unmarshal([]byte(decrypted), &sessionData); err != nil {
		return nil, ErrSessionInvalid
	}

	// Convert to session
	session := sessionData.ToSession()

	// Check expiration
	if session.IsExpired() {
		return nil, ErrSessionExpired
	}

	// Touch last access time
	session.Touch()

	return session, nil
}

// Save saves a session to the cookie
func (s *CookieStore) Save(w http.ResponseWriter, r *http.Request, session *model.Session) error {
	// Set expiration if not set
	if session.ExpiresAt.IsZero() {
		session.ExpiresAt = time.Now().Add(s.ttl)
	}

	// Convert to session data
	sessionData := session.ToSessionData()
	if sessionData == nil {
		return fmt.Errorf("session has no user data")
	}

	// Marshal to JSON
	data, err := json.Marshal(sessionData)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	// Encrypt
	encrypted, err := s.encryptor.EncryptString(string(data))
	if err != nil {
		return fmt.Errorf("failed to encrypt session: %w", err)
	}

	// Check size limit
	if len(encrypted) > s.maxSize {
		return ErrStoreFull
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    encrypted,
		Path:     "/",
		Domain:   s.cookieDomain, // MED-02: configurable domain for cross-subdomain sessions
		Expires:  session.ExpiresAt,
		MaxAge:   int(time.Until(session.ExpiresAt).Seconds()),
		Secure:   s.secure,
		HttpOnly: true,
		SameSite: s.sameSite,
	})

	return nil
}

// Delete removes the session cookie
func (s *CookieStore) Delete(w http.ResponseWriter, r *http.Request) error {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    "",
		Path:     "/",
		Domain:   s.cookieDomain, // MED-02: must match domain used in Save
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   s.secure,
		HttpOnly: true,
		SameSite: s.sameSite,
	})
	return nil
}

// Name returns the store type name
func (s *CookieStore) Name() string {
	return "cookie"
}

// parseSameSite converts string to http.SameSite
func parseSameSite(s string) http.SameSite {
	switch s {
	case "strict":
		return http.SameSiteStrictMode
	case "lax":
		return http.SameSiteLaxMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}
