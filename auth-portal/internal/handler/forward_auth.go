package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/service/idp"
	"github.com/dzerik/auth-portal/internal/service/session"
)

// ForwardAuthHandler handles forward auth requests from Traefik/Nginx
type ForwardAuthHandler struct {
	sessionManager *session.Manager
	idpManager     *idp.Manager
	config         *config.Config
}

// NewForwardAuthHandler creates a new forward auth handler
func NewForwardAuthHandler(
	sessionMgr *session.Manager,
	idpMgr *idp.Manager,
	cfg *config.Config,
) *ForwardAuthHandler {
	return &ForwardAuthHandler{
		sessionManager: sessionMgr,
		idpManager:     idpMgr,
		config:         cfg,
	}
}

// HandleAuth handles the /auth endpoint for forward auth
// Returns 200 if authenticated with user headers, 401 otherwise
func (h *ForwardAuthHandler) HandleAuth(w http.ResponseWriter, r *http.Request) {
	// Get session
	sess, err := h.sessionManager.Get(r)
	if err != nil || sess == nil || sess.User == nil {
		h.handleUnauthenticated(w, r)
		return
	}

	// Check if session is expired
	if sess.IsExpired() {
		// Try to refresh token if available
		if sess.RefreshToken != "" && h.config.Token.AutoRefresh {
			if newTokens, err := h.idpManager.Refresh(r.Context(), sess.RefreshToken); err == nil {
				// Update session with new tokens
				sess.AccessToken = newTokens.AccessToken
				sess.RefreshToken = newTokens.RefreshToken
				sess.IDToken = newTokens.IDToken
				sess.ExpiresAt = time.Now().Add(time.Duration(newTokens.ExpiresIn) * time.Second)

				// Save updated session
				if saveErr := h.sessionManager.Save(w, r, sess); saveErr != nil {
					// Log error but continue - the old token might still work
				}
			} else {
				// Refresh failed, user needs to re-authenticate
				h.handleUnauthenticated(w, r)
				return
			}
		} else {
			h.handleUnauthenticated(w, r)
			return
		}
	}

	// Check token expiry threshold for proactive refresh
	if h.config.Token.AutoRefresh && sess.RefreshToken != "" {
		threshold := h.config.Token.RefreshThreshold
		if threshold > 0 && time.Until(sess.ExpiresAt) < threshold {
			// Proactively refresh token
			if newTokens, err := h.idpManager.Refresh(r.Context(), sess.RefreshToken); err == nil {
				sess.AccessToken = newTokens.AccessToken
				sess.RefreshToken = newTokens.RefreshToken
				sess.IDToken = newTokens.IDToken
				sess.ExpiresAt = time.Now().Add(time.Duration(newTokens.ExpiresIn) * time.Second)
				h.sessionManager.Save(w, r, sess)
			}
		}
	}

	// Set user headers
	user := sess.User

	// Standard headers
	w.Header().Set("X-Auth-Request-User", user.ID)
	w.Header().Set("X-Auth-Request-Email", user.Email)

	if user.Name != "" {
		w.Header().Set("X-Auth-Request-Name", user.Name)
	}
	if user.PreferredName != "" {
		w.Header().Set("X-Auth-Request-Preferred-Username", user.PreferredName)
	}

	// Roles as comma-separated list
	if len(user.Roles) > 0 {
		w.Header().Set("X-Auth-Request-Roles", strings.Join(user.Roles, ","))
	}

	// Groups as comma-separated list
	if len(user.Groups) > 0 {
		w.Header().Set("X-Auth-Request-Groups", strings.Join(user.Groups, ","))
	}

	// Tenant ID
	if user.TenantID != "" {
		w.Header().Set("X-Auth-Request-Tenant", user.TenantID)
	}

	// Access token for backend services that need to validate tokens themselves
	w.Header().Set("X-Auth-Request-Access-Token", sess.AccessToken)

	// Return 200 OK
	w.WriteHeader(http.StatusOK)
}

// handleUnauthenticated handles unauthenticated requests
func (h *ForwardAuthHandler) handleUnauthenticated(w http.ResponseWriter, r *http.Request) {
	// Set WWW-Authenticate header for proper OAuth2/OIDC response
	w.Header().Set("WWW-Authenticate", `Bearer realm="auth-portal"`)

	// Return 401 Unauthorized
	// Traefik/Nginx will handle the redirect based on their configuration
	w.WriteHeader(http.StatusUnauthorized)

	// Optionally return JSON body
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":   "unauthorized",
		"message": "Authentication required",
	})
}

// HandleAuthWithRedirect handles /auth with redirect to login
// This variant redirects unauthenticated users to login instead of returning 401
func (h *ForwardAuthHandler) HandleAuthWithRedirect(w http.ResponseWriter, r *http.Request) {
	// Get session
	sess, err := h.sessionManager.Get(r)
	if err != nil || sess == nil || sess.User == nil || sess.IsExpired() {
		// Build the original URL from forwarded headers
		originalURL := h.buildOriginalURL(r)

		// Redirect to login with redirect parameter
		loginURL := "/login?redirect=" + originalURL
		http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)
		return
	}

	// Same as HandleAuth from here
	user := sess.User

	w.Header().Set("X-Auth-Request-User", user.ID)
	w.Header().Set("X-Auth-Request-Email", user.Email)

	if user.Name != "" {
		w.Header().Set("X-Auth-Request-Name", user.Name)
	}
	if len(user.Roles) > 0 {
		w.Header().Set("X-Auth-Request-Roles", strings.Join(user.Roles, ","))
	}
	if len(user.Groups) > 0 {
		w.Header().Set("X-Auth-Request-Groups", strings.Join(user.Groups, ","))
	}
	if user.TenantID != "" {
		w.Header().Set("X-Auth-Request-Tenant", user.TenantID)
	}

	w.WriteHeader(http.StatusOK)
}

// HandleVerify verifies an access token and returns user info
// This endpoint is for service-to-service token validation
func (h *ForwardAuthHandler) HandleVerify(w http.ResponseWriter, r *http.Request) {
	// Get token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		h.renderJSONError(w, "Authorization header required", http.StatusUnauthorized)
		return
	}

	// Parse Bearer token
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		h.renderJSONError(w, "Invalid authorization header format", http.StatusUnauthorized)
		return
	}

	token := parts[1]

	// Verify token with IdP
	user, err := h.idpManager.Verify(r.Context(), token)
	if err != nil {
		h.renderJSONError(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Return user info
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// HandleIntrospect implements token introspection (RFC 7662)
func (h *ForwardAuthHandler) HandleIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.renderJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		h.renderJSONError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")
	if token == "" {
		h.renderJSONError(w, "Token required", http.StatusBadRequest)
		return
	}

	// Verify token
	user, err := h.idpManager.Verify(r.Context(), token)
	if err != nil {
		// Token is not active
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"active": false,
		})
		return
	}

	// Token is active, return introspection response
	response := map[string]interface{}{
		"active":     true,
		"sub":        user.ID,
		"username":   user.PreferredName,
		"email":      user.Email,
		"name":       user.Name,
		"given_name": user.GivenName,
		"family_name": user.FamilyName,
		"scope":      "openid profile email",
		"token_type": "Bearer",
	}

	if len(user.Roles) > 0 {
		response["roles"] = user.Roles
	}
	if len(user.Groups) > 0 {
		response["groups"] = user.Groups
	}
	if user.TenantID != "" {
		response["tenant_id"] = user.TenantID
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// buildOriginalURL builds the original URL from forwarded headers
func (h *ForwardAuthHandler) buildOriginalURL(r *http.Request) string {
	// Try X-Forwarded-* headers first (standard for reverse proxies)
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		scheme = r.Header.Get("X-Forwarded-Scheme")
	}
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}

	uri := r.Header.Get("X-Forwarded-Uri")
	if uri == "" {
		uri = r.URL.RequestURI()
	}

	return scheme + "://" + host + uri
}

// renderJSONError renders an error as JSON
func (h *ForwardAuthHandler) renderJSONError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":  message,
		"status": status,
	})
}
