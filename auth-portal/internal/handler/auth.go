package handler

import (
	"encoding/json"
	"html/template"
	"net/http"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/service/idp"
	"github.com/dzerik/auth-portal/internal/service/session"
	"github.com/dzerik/auth-portal/internal/service/state"
)

// AuthHandler handles authentication routes
type AuthHandler struct {
	idpManager     *idp.Manager
	sessionManager *session.Manager
	config         *config.Config
	templates      *template.Template
	stateStore     state.Store // CRIT-02: now uses interface for Redis/memory backends
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(
	idpMgr *idp.Manager,
	sessionMgr *session.Manager,
	cfg *config.Config,
	templates *template.Template,
	stateStore state.Store, // CRIT-02: accepts state store as parameter for HA support
) *AuthHandler {
	return &AuthHandler{
		idpManager:     idpMgr,
		sessionManager: sessionMgr,
		config:         cfg,
		templates:      templates,
		stateStore:     stateStore,
	}
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
		redirectURL := h.validateRedirectURL(r.URL.Query().Get("redirect"))
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	// Get redirect URL from query param (validated)
	redirectURL := h.validateRedirectURL(r.URL.Query().Get("redirect"))

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
