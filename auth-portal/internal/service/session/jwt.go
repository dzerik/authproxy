package session

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/model"
	"github.com/dzerik/auth-portal/internal/service/crypto"
)

// JWTStore stores session data in a signed JWT cookie
type JWTStore struct {
	cookieName   string
	cookieDomain string // MED-02 security fix: configurable domain for cross-subdomain sessions
	jwtManager   *crypto.JWTManager
	secure       bool
	sameSite     http.SameSite
	ttl          time.Duration
}

// NewJWTStore creates a new JWT-based session store
func NewJWTStore(cfg *config.SessionConfig) (*JWTStore, error) {
	jwtCfg := crypto.JWTConfig{
		Algorithm:  cfg.JWT.Algorithm,
		SigningKey: cfg.JWT.SigningKey,
		PrivateKey: cfg.JWT.PrivateKey,
		PublicKey:  cfg.JWT.PublicKey,
		Issuer:     "auth-portal",
	}

	jwtManager, err := crypto.NewJWTManager(jwtCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT manager: %w", err)
	}

	sameSite := parseSameSite(cfg.SameSite)

	return &JWTStore{
		cookieName:   cfg.CookieName,
		cookieDomain: cfg.CookieDomain,
		jwtManager:   jwtManager,
		secure:       cfg.Secure,
		sameSite:     sameSite,
		ttl:          cfg.TTL,
	}, nil
}

// Get retrieves a session from the JWT cookie
func (s *JWTStore) Get(r *http.Request) (*model.Session, error) {
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

	// Verify and parse JWT
	claims, err := s.jwtManager.Verify(cookie.Value)
	if err != nil {
		if err == crypto.ErrTokenExpired {
			return nil, ErrSessionExpired
		}
		return nil, ErrSessionInvalid
	}

	// Convert claims to session
	session := &model.Session{
		ID: claims.ID,
		User: &model.User{
			ID:       claims.UserID,
			Email:    claims.Email,
			Name:     claims.Name,
			Roles:    claims.Roles,
			Groups:   claims.Groups,
			TenantID: claims.TenantID,
		},
		ExpiresAt:    claims.ExpiresAt.Time,
		CreatedAt:    claims.IssuedAt.Time,
		LastAccessAt: time.Now(),
	}

	return session, nil
}

// Save saves a session to the JWT cookie
func (s *JWTStore) Save(w http.ResponseWriter, r *http.Request, session *model.Session) error {
	if session.User == nil {
		return fmt.Errorf("session has no user data")
	}

	// Generate session ID if not set
	if session.ID == "" {
		id, err := crypto.GenerateSessionID()
		if err != nil {
			return fmt.Errorf("failed to generate session ID: %w", err)
		}
		session.ID = id
	}

	// Create claims
	claims := crypto.CreateSessionClaims(
		session.ID,
		session.User.ID,
		session.User.Email,
		session.User.Name,
		session.User.Roles,
		session.User.Groups,
		s.ttl,
	)
	claims.TenantID = session.User.TenantID

	// Sign JWT
	token, err := s.jwtManager.Sign(claims)
	if err != nil {
		return fmt.Errorf("failed to sign JWT: %w", err)
	}

	// Calculate expiration
	expiresAt := time.Now().Add(s.ttl)
	if !session.ExpiresAt.IsZero() {
		expiresAt = session.ExpiresAt
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    token,
		Path:     "/",
		Domain:   s.cookieDomain, // MED-02: configurable domain for cross-subdomain sessions
		Expires:  expiresAt,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
		Secure:   s.secure,
		HttpOnly: true,
		SameSite: s.sameSite,
	})

	return nil
}

// Delete removes the session cookie
func (s *JWTStore) Delete(w http.ResponseWriter, r *http.Request) error {
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
func (s *JWTStore) Name() string {
	return "jwt"
}
