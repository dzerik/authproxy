package handler

import (
	"encoding/json"
	"html/template"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/model"
	"github.com/dzerik/auth-portal/internal/service/security"
	"github.com/dzerik/auth-portal/internal/service/session"
	"github.com/dzerik/auth-portal/internal/service/visibility"
)

// PortalHandler handles portal routes
type PortalHandler struct {
	sessionManager   *session.Manager
	config           *config.Config
	templates        *template.Template
	visibilityFilter *visibility.Filter
	securityWarnings []security.Warning
	adminRoles       []string
}

// PortalHandlerOption is a functional option for PortalHandler.
type PortalHandlerOption func(*PortalHandler)

// WithSecurityWarnings sets security warnings to display to admins.
func WithSecurityWarnings(warnings []security.Warning) PortalHandlerOption {
	return func(h *PortalHandler) {
		h.securityWarnings = warnings
	}
}

// WithAdminRoles sets the roles that can see security warnings.
func WithAdminRoles(roles []string) PortalHandlerOption {
	return func(h *PortalHandler) {
		h.adminRoles = roles
	}
}

// NewPortalHandler creates a new portal handler
func NewPortalHandler(
	sessionMgr *session.Manager,
	cfg *config.Config,
	templates *template.Template,
	opts ...PortalHandlerOption,
) *PortalHandler {
	h := &PortalHandler{
		sessionManager:   sessionMgr,
		config:           cfg,
		templates:        templates,
		visibilityFilter: visibility.NewFilter(),
		adminRoles:       []string{"admin", "administrator", "portal-admin"},
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// SecurityWarningView represents a security warning for display in UI.
type SecurityWarningView struct {
	Code           string
	Severity       string
	Title          string
	Description    string
	Service        string
	Recommendation string
}

// PortalPageData represents data for the portal page template
type PortalPageData struct {
	Title            string
	User             *model.User
	Services         []ServiceView
	Error            string
	SecurityWarnings []SecurityWarningView
	IsAdmin          bool
}

// ServiceView represents a service for display
type ServiceView struct {
	Name        string
	DisplayName string
	Description string
	URL         string
	Icon        string
}

// HandlePortal displays the service portal
func (h *PortalHandler) HandlePortal(w http.ResponseWriter, r *http.Request) {
	sess := session.FromRequest(r)
	if sess == nil || sess.User == nil {
		http.Redirect(w, r, "/login?redirect=/portal", http.StatusFound)
		return
	}

	// Get available services for the user
	services := h.getServicesForUser(sess.User)

	// Check if user is admin
	isAdmin := h.isUserAdmin(sess.User)

	// Get security warnings for admins
	var warnings []SecurityWarningView
	if isAdmin && len(h.securityWarnings) > 0 {
		warnings = h.convertWarnings(h.securityWarnings)
	}

	data := PortalPageData{
		Title:            "Service Portal",
		User:             sess.User,
		Services:         services,
		SecurityWarnings: warnings,
		IsAdmin:          isAdmin,
	}

	if h.templates != nil {
		if err := h.templates.ExecuteTemplate(w, "portal.html", data); err != nil {
			h.renderError(w, "Failed to render portal page", http.StatusInternalServerError)
		}
		return
	}

	// Fallback: JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// isUserAdmin checks if the user has any admin role.
func (h *PortalHandler) isUserAdmin(user *model.User) bool {
	if user == nil {
		return false
	}
	for _, userRole := range user.Roles {
		for _, adminRole := range h.adminRoles {
			if userRole == adminRole {
				return true
			}
		}
	}
	return false
}

// convertWarnings converts security.Warning to SecurityWarningView for template.
func (h *PortalHandler) convertWarnings(warnings []security.Warning) []SecurityWarningView {
	views := make([]SecurityWarningView, 0, len(warnings))
	for _, w := range warnings {
		views = append(views, SecurityWarningView{
			Code:           w.Code,
			Severity:       string(w.Severity),
			Title:          w.Title,
			Description:    w.Description,
			Service:        w.Service,
			Recommendation: w.Recommendation,
		})
	}
	return views
}

// HandleServices returns the list of available services as JSON
func (h *PortalHandler) HandleServices(w http.ResponseWriter, r *http.Request) {
	sess := session.FromRequest(r)
	if sess == nil || sess.User == nil {
		h.renderJSONError(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	services := h.getServicesForUser(sess.User)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"services": services,
	})
}

// getServicesForUser returns services available to the user based on their roles and groups.
// Services with visibility config are filtered; services without it are visible to all.
func (h *PortalHandler) getServicesForUser(user *model.User) []ServiceView {
	// Filter services based on user's roles and groups
	visibleServices := h.visibilityFilter.FilterServices(h.config.Services, user)

	var services []ServiceView
	for _, svc := range visibleServices {
		// Build the service URL
		url := svc.Location
		if url == "" && svc.Upstream != "" {
			url = svc.Upstream
		}

		services = append(services, ServiceView{
			Name:        svc.Name,
			DisplayName: svc.DisplayName,
			Description: svc.Description,
			URL:         url,
			Icon:        svc.Icon,
		})
	}

	return services
}

// HandleServiceRedirect redirects to a specific service
func (h *PortalHandler) HandleServiceRedirect(w http.ResponseWriter, r *http.Request) {
	sess := session.FromRequest(r)
	if sess == nil || sess.User == nil {
		http.Redirect(w, r, "/login?redirect="+r.URL.RequestURI(), http.StatusFound)
		return
	}

	// Get service name from URL using chi
	serviceName := chi.URLParam(r, "service")
	if serviceName == "" {
		// Fallback for Go 1.22+ PathValue
		serviceName = r.PathValue("service")
	}
	if serviceName == "" {
		// Fallback for manual extraction
		serviceName = extractPathParam(r.URL.Path, "/service/")
	}

	if serviceName == "" {
		h.renderError(w, "Service name required", http.StatusBadRequest)
		return
	}

	// Find service
	var targetURL string
	for _, svc := range h.config.Services {
		if svc.Name == serviceName {
			targetURL = svc.Location
			if targetURL == "" {
				targetURL = svc.Upstream
			}
			break
		}
	}

	if targetURL == "" {
		h.renderError(w, "Service not found", http.StatusNotFound)
		return
	}

	http.Redirect(w, r, targetURL, http.StatusFound)
}

// renderError renders an error page or JSON response
func (h *PortalHandler) renderError(w http.ResponseWriter, message string, status int) {
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
func (h *PortalHandler) renderJSONError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":  message,
		"status": status,
	})
}
