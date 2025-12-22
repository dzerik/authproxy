package handler

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/dzerik/auth-portal/internal/model"
	"github.com/dzerik/auth-portal/internal/service/crypto"
	"github.com/dzerik/auth-portal/internal/service/idp"
	"github.com/dzerik/auth-portal/internal/service/state"
)

// HandleLoginKeycloak initiates login with Keycloak
func (h *AuthHandler) HandleLoginKeycloak(w http.ResponseWriter, r *http.Request) {
	h.initiateOAuth(w, r, "", "")
}

// HandleLoginSocial initiates login with a social provider via kc_idp_hint
func (h *AuthHandler) HandleLoginSocial(w http.ResponseWriter, r *http.Request) {
	// Extract provider from URL path using chi
	provider := chi.URLParam(r, "provider")
	if provider == "" {
		// Fallback for Go 1.22+ PathValue
		provider = r.PathValue("provider")
	}
	if provider == "" {
		// Fallback for manual extraction
		provider = extractPathParam(r.URL.Path, "/login/social/")
	}

	if provider == "" {
		h.renderError(w, "Provider not specified", http.StatusBadRequest)
		return
	}

	// Find the provider config to get the idp_hint
	var idpHint string
	for _, sp := range h.idpManager.GetSocialProviders() {
		if sp.Name == provider {
			idpHint = sp.IDPHint
			break
		}
	}

	if idpHint == "" {
		h.renderError(w, "Unknown social provider", http.StatusBadRequest)
		return
	}

	h.initiateOAuth(w, r, idpHint, provider)
}

// HandleLoginDevProfile handles dev mode login with a specific profile
func (h *AuthHandler) HandleLoginDevProfile(w http.ResponseWriter, r *http.Request) {
	if !h.idpManager.IsDevMode() {
		h.renderError(w, "Dev mode not enabled", http.StatusForbidden)
		return
	}

	// Extract profile from URL path using chi
	profile := chi.URLParam(r, "profile")
	if profile == "" {
		// Fallback for Go 1.22+ PathValue
		profile = r.PathValue("profile")
	}
	if profile == "" {
		// Fallback for manual extraction
		profile = extractPathParam(r.URL.Path, "/login/dev/")
	}

	if profile == "" {
		profile = "developer" // default profile
	}

	// In dev mode, we use the profile name as the IDPHint
	h.initiateOAuth(w, r, profile, "dev")
}

// initiateOAuth starts the OAuth flow
func (h *AuthHandler) initiateOAuth(w http.ResponseWriter, r *http.Request, idpHint, provider string) {
	// Generate state token
	stateToken, err := crypto.GenerateStateToken()
	if err != nil {
		h.renderError(w, "Failed to generate state token", http.StatusInternalServerError)
		return
	}

	// Generate nonce
	nonce, err := crypto.GenerateNonce()
	if err != nil {
		h.renderError(w, "Failed to generate nonce", http.StatusInternalServerError)
		return
	}

	// Get redirect URL from query param (validated to prevent open redirect)
	redirectURL := h.validateRedirectURL(r.URL.Query().Get("redirect"))

	// Store state for validation in callback
	h.stateStore.Set(&state.OAuthState{
		State:       stateToken,
		Nonce:       nonce,
		RedirectURL: redirectURL,
		Provider:    provider,
		CreatedAt:   time.Now(),
	})

	// Build auth URL options
	opts := idp.AuthURLOptions{
		State:   stateToken,
		Nonce:   nonce,
		IDPHint: idpHint,
	}

	// Get login hint from query param
	if loginHint := r.URL.Query().Get("login_hint"); loginHint != "" {
		opts.LoginHint = loginHint
	}

	// Get prompt from query param
	if prompt := r.URL.Query().Get("prompt"); prompt != "" {
		opts.Prompt = prompt
	}

	// Generate authorization URL
	authURL := h.idpManager.AuthURL(opts)

	// Redirect to IdP
	http.Redirect(w, r, authURL, http.StatusFound)
}

// HandleCallback handles the OAuth callback
func (h *AuthHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	// Check for error response (LOW-01: don't expose IdP error details to users)
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		// Error details are intentionally not exposed to prevent information disclosure
		h.renderError(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	// Get authorization code
	code := r.URL.Query().Get("code")
	if code == "" {
		h.renderError(w, "Authorization code not provided", http.StatusBadRequest)
		return
	}

	// Get state token
	stateToken := r.URL.Query().Get("state")
	if stateToken == "" {
		h.renderError(w, "State token not provided", http.StatusBadRequest)
		return
	}

	// Validate state
	oauthState, valid := h.stateStore.Get(stateToken)
	if !valid {
		h.renderError(w, "Invalid or expired state token", http.StatusBadRequest)
		return
	}

	// Exchange code for tokens
	ctx := r.Context()
	tokens, err := h.idpManager.Exchange(ctx, code)
	if err != nil {
		h.renderError(w, "Failed to exchange authorization code", http.StatusInternalServerError)
		return
	}

	// Validate nonce to prevent replay attacks (HIGH-01 security fix)
	if tokens.IDToken != "" && oauthState.Nonce != "" {
		tokenNonce, _ := h.extractNonceFromIDToken(tokens.IDToken)
		if tokenNonce != "" && tokenNonce != oauthState.Nonce {
			h.renderError(w, "Nonce mismatch - possible replay attack", http.StatusBadRequest)
			return
		}
	}

	// Get user info
	user, err := h.idpManager.UserInfo(ctx, tokens.AccessToken)
	if err != nil {
		// Error details not exposed to user (LOW-01 security fix)
		h.renderError(w, "Failed to get user information", http.StatusInternalServerError)
		return
	}

	// Create session
	sess := &model.Session{
		User:         user,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		IDToken:      tokens.IDToken,
		ExpiresAt:    time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second),
		CreatedAt:    time.Now(),
		LastAccessAt: time.Now(),
	}

	// Save session
	if err := h.sessionManager.Save(w, r, sess); err != nil {
		// Error details not exposed to user (LOW-01 security fix)
		h.renderError(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Redirect to original destination
	redirectURL := oauthState.RedirectURL
	if redirectURL == "" {
		redirectURL = "/portal"
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// HandleLogout handles user logout
func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	// Get current session for ID token hint
	sess, _ := h.sessionManager.Get(r)

	// Delete session
	if err := h.sessionManager.Delete(w, r); err != nil {
		// Log error but continue with logout
	}

	// Get post-logout redirect URL (validated then converted to absolute URL)
	postLogoutRedirectPath := h.validateRedirectURL(r.URL.Query().Get("redirect"))
	// For OIDC logout, we need absolute URL - convert validated relative path
	postLogoutRedirect := h.buildAbsoluteURL(r, postLogoutRedirectPath)
	// If redirect was explicitly set to portal, use login page after logout instead
	if postLogoutRedirectPath == "/portal" && r.URL.Query().Get("redirect") == "" {
		postLogoutRedirect = h.buildAbsoluteURL(r, "/login")
	}

	// Get ID token hint for RP-initiated logout
	var idTokenHint string
	if sess != nil {
		idTokenHint = sess.IDToken
	}

	// Build logout URL
	logoutURL := h.idpManager.LogoutURL(idTokenHint, postLogoutRedirect)

	http.Redirect(w, r, logoutURL, http.StatusFound)
}
