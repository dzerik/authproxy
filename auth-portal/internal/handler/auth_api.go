package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/dzerik/auth-portal/internal/model"
	"github.com/dzerik/auth-portal/internal/service/session"
)

// HandleUserInfo returns current user information as JSON
func (h *AuthHandler) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	sess := session.FromRequest(r)
	if sess == nil || sess.User == nil {
		h.renderJSONError(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sess.User)
}

// HandleSessionInfo returns current session information as JSON
func (h *AuthHandler) HandleSessionInfo(w http.ResponseWriter, r *http.Request) {
	sess := session.FromRequest(r)
	if sess == nil {
		h.renderJSONError(w, "No session", http.StatusUnauthorized)
		return
	}

	// Return session info without sensitive tokens
	info := struct {
		ID           string      `json:"id"`
		User         *model.User `json:"user,omitempty"`
		ExpiresAt    time.Time   `json:"expires_at"`
		CreatedAt    time.Time   `json:"created_at"`
		LastAccessAt time.Time   `json:"last_access_at"`
		IsExpired    bool        `json:"is_expired"`
	}{
		ID:           sess.ID,
		User:         sess.User,
		ExpiresAt:    sess.ExpiresAt,
		CreatedAt:    sess.CreatedAt,
		LastAccessAt: sess.LastAccessAt,
		IsExpired:    sess.IsExpired(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}
