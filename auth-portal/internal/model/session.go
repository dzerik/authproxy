package model

import (
	"time"
)

// Session represents a user session
type Session struct {
	ID           string    `json:"id"`
	User         *User     `json:"user"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	IDToken      string    `json:"id_token"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
	LastAccessAt time.Time `json:"last_access_at"`
	ReturnTo     string    `json:"return_to,omitempty"` // URL to redirect after login
}

// NewSession creates a new session
func NewSession(id string, user *User) *Session {
	now := time.Now()
	return &Session{
		ID:           id,
		User:         user,
		CreatedAt:    now,
		LastAccessAt: now,
	}
}

// IsExpired checks if the session has expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsAccessTokenExpired checks if the access token has expired
func (s *Session) IsAccessTokenExpired() bool {
	return s.IsExpired()
}

// NeedsRefresh checks if the access token should be refreshed
func (s *Session) NeedsRefresh(threshold time.Duration) bool {
	if s.RefreshToken == "" {
		return false
	}
	return time.Until(s.ExpiresAt) < threshold
}

// Touch updates the last access time
func (s *Session) Touch() {
	s.LastAccessAt = time.Now()
}

// RemainingTTL returns the remaining time until session expires
func (s *Session) RemainingTTL() time.Duration {
	return time.Until(s.ExpiresAt)
}

// SetTokens sets the OAuth tokens
func (s *Session) SetTokens(accessToken, refreshToken, idToken string, expiresIn time.Duration) {
	s.AccessToken = accessToken
	s.RefreshToken = refreshToken
	s.IDToken = idToken
	s.ExpiresAt = time.Now().Add(expiresIn)
}

// SessionData represents serializable session data (for cookie/redis storage)
type SessionData struct {
	ID           string    `json:"id"`
	UserID       string    `json:"uid"`
	Email        string    `json:"email"`
	Name         string    `json:"name"`
	Roles        []string  `json:"roles,omitempty"`
	Groups       []string  `json:"groups,omitempty"`
	TenantID     string    `json:"tid,omitempty"`
	AccessToken  string    `json:"at"`
	RefreshToken string    `json:"rt,omitempty"`
	IDToken      string    `json:"it,omitempty"`
	ExpiresAt    int64     `json:"exp"`
	CreatedAt    int64     `json:"iat"`
}

// ToSessionData converts Session to SessionData for storage
func (s *Session) ToSessionData() *SessionData {
	if s.User == nil {
		return nil
	}
	return &SessionData{
		ID:           s.ID,
		UserID:       s.User.ID,
		Email:        s.User.Email,
		Name:         s.User.Name,
		Roles:        s.User.Roles,
		Groups:       s.User.Groups,
		TenantID:     s.User.TenantID,
		AccessToken:  s.AccessToken,
		RefreshToken: s.RefreshToken,
		IDToken:      s.IDToken,
		ExpiresAt:    s.ExpiresAt.Unix(),
		CreatedAt:    s.CreatedAt.Unix(),
	}
}

// ToSession converts SessionData back to Session
func (sd *SessionData) ToSession() *Session {
	return &Session{
		ID: sd.ID,
		User: &User{
			ID:       sd.UserID,
			Email:    sd.Email,
			Name:     sd.Name,
			Roles:    sd.Roles,
			Groups:   sd.Groups,
			TenantID: sd.TenantID,
		},
		AccessToken:  sd.AccessToken,
		RefreshToken: sd.RefreshToken,
		IDToken:      sd.IDToken,
		ExpiresAt:    time.Unix(sd.ExpiresAt, 0),
		CreatedAt:    time.Unix(sd.CreatedAt, 0),
		LastAccessAt: time.Now(),
	}
}
