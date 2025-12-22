package handler

import (
	"encoding/json"
	"html/template"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/model"
	"github.com/dzerik/auth-portal/internal/service/crypto"
	"github.com/dzerik/auth-portal/internal/service/idp"
	"github.com/dzerik/auth-portal/internal/service/session"
)

// AuthHandler handles authentication routes
type AuthHandler struct {
	idpManager     *idp.Manager
	sessionManager *session.Manager
	config         *config.Config
	templates      *template.Template
	stateStore     *StateStore
}

// StateStore temporarily stores OAuth state tokens for validation
type StateStore struct {
	mu     sync.RWMutex
	states map[string]*OAuthState
}

// OAuthState represents an OAuth flow state
type OAuthState struct {
	State       string
	Nonce       string
	RedirectURL string
	Provider    string
	CreatedAt   time.Time
}

// NewStateStore creates a new state store
func NewStateStore() *StateStore {
	store := &StateStore{
		states: make(map[string]*OAuthState),
	}
	// Start cleanup goroutine
	go store.cleanup()
	return store
}

// Set stores a new state
func (s *StateStore) Set(state *OAuthState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[state.State] = state
}

// Get retrieves and removes a state (one-time use)
func (s *StateStore) Get(stateToken string) (*OAuthState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, exists := s.states[stateToken]
	if exists {
		delete(s.states, stateToken)
	}
	return state, exists
}

// Validate checks if a state exists without removing it
func (s *StateStore) Validate(stateToken string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.states[stateToken]
	return exists
}

// cleanup removes expired states (older than 10 minutes)
func (s *StateStore) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for key, state := range s.states {
			if now.Sub(state.CreatedAt) > 10*time.Minute {
				delete(s.states, key)
			}
		}
		s.mu.Unlock()
	}
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(
	idpMgr *idp.Manager,
	sessionMgr *session.Manager,
	cfg *config.Config,
	templates *template.Template,
) *AuthHandler {
	return &AuthHandler{
		idpManager:     idpMgr,
		sessionManager: sessionMgr,
		config:         cfg,
		templates:      templates,
		stateStore:     NewStateStore(),
	}
}

// HandleRoot handles the root path - redirects to login or portal
func (h *AuthHandler) HandleRoot(w http.ResponseWriter, r *http.Request) {
	// Check if user is authenticated
	if h.sessionManager.IsAuthenticated(r) {
		http.Redirect(w, r, "/portal", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

// HandleLogin shows the login page with provider buttons
func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	// Check if already authenticated
	if h.sessionManager.IsAuthenticated(r) {
		redirectURL := r.URL.Query().Get("redirect")
		if redirectURL == "" {
			redirectURL = "/portal"
		}
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	// Get redirect URL from query param
	redirectURL := r.URL.Query().Get("redirect")

	// Build template data
	data := LoginPageData{
		Title:           "Login",
		RedirectURL:     redirectURL,
		SocialProviders: h.idpManager.GetSocialProviders(),
		DevMode:         h.idpManager.IsDevMode(),
	}

	// If in dev mode, add available profiles
	if h.idpManager.IsDevMode() {
		if mockProvider, ok := h.idpManager.Provider().(*idp.MockProvider); ok {
			data.DevProfiles = mockProvider.GetProfiles()
		}
	}

	// Render login page
	if h.templates != nil {
		if err := h.templates.ExecuteTemplate(w, "login.html", data); err != nil {
			h.renderError(w, "Failed to render login page", http.StatusInternalServerError)
		}
		return
	}

	// Fallback: simple JSON response with login options
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// LoginPageData represents data for the login page template
type LoginPageData struct {
	Title           string
	RedirectURL     string
	SocialProviders []config.SocialProvider
	DevMode         bool
	DevProfiles     []string
	Error           string
}

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

	// Get redirect URL from query param
	redirectURL := r.URL.Query().Get("redirect")
	if redirectURL == "" {
		redirectURL = "/portal"
	}

	// Store state for validation in callback
	h.stateStore.Set(&OAuthState{
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
	// Check for error response
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		h.renderError(w, "Authentication failed: "+errParam+": "+errDesc, http.StatusUnauthorized)
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

	// Get user info
	user, err := h.idpManager.UserInfo(ctx, tokens.AccessToken)
	if err != nil {
		// Log actual error for debugging
		h.renderError(w, "Failed to get user information: "+err.Error(), http.StatusInternalServerError)
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
		h.renderError(w, "Failed to create session: "+err.Error(), http.StatusInternalServerError)
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

	// Get post-logout redirect URL
	postLogoutRedirect := r.URL.Query().Get("redirect")
	if postLogoutRedirect == "" {
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
		ID           string       `json:"id"`
		User         *model.User  `json:"user,omitempty"`
		ExpiresAt    time.Time    `json:"expires_at"`
		CreatedAt    time.Time    `json:"created_at"`
		LastAccessAt time.Time    `json:"last_access_at"`
		IsExpired    bool         `json:"is_expired"`
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

// renderError renders an error page or JSON response
func (h *AuthHandler) renderError(w http.ResponseWriter, message string, status int) {
	if h.templates != nil {
		w.WriteHeader(status)
		data := ErrorPageData{
			Title:   "Error",
			Message: message,
			Status:  status,
		}
		h.templates.ExecuteTemplate(w, "error.html", data)
		return
	}

	h.renderJSONError(w, message, status)
}

// renderJSONError renders an error as JSON
func (h *AuthHandler) renderJSONError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":  message,
		"status": status,
	})
}

// ErrorPageData represents data for the error page template
type ErrorPageData struct {
	Title   string
	Message string
	Status  int
}

// buildAbsoluteURL builds an absolute URL from a relative path
func (h *AuthHandler) buildAbsoluteURL(r *http.Request, path string) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := r.Host
	return scheme + "://" + host + path
}

// extractPathParam extracts a parameter from a URL path
// e.g., extractPathParam("/login/social/google", "/login/social/") returns "google"
func extractPathParam(path, prefix string) string {
	if len(path) > len(prefix) {
		return path[len(prefix):]
	}
	return ""
}

// RequireAuth is a middleware that requires authentication
func (h *AuthHandler) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.sessionManager.IsAuthenticated(r) {
			// Store original URL for redirect after login
			loginURL := "/login?redirect=" + r.URL.RequestURI()
			http.Redirect(w, r, loginURL, http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireAuthJSON is a middleware that requires authentication and returns JSON error
func (h *AuthHandler) RequireAuthJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.sessionManager.IsAuthenticated(r) {
			h.renderJSONError(w, "Authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireAuthMiddleware returns a chi-compatible middleware that requires authentication.
// Use this with r.Use() in chi router.
func (h *AuthHandler) RequireAuthMiddleware(next http.Handler) http.Handler {
	return h.RequireAuth(next)
}

// RequireAuthJSONMiddleware returns a chi-compatible middleware that requires authentication
// and returns JSON errors. Use this with r.Use() in chi router.
func (h *AuthHandler) RequireAuthJSONMiddleware(next http.Handler) http.Handler {
	return h.RequireAuthJSON(next)
}
