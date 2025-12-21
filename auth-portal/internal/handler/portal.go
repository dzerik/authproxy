package handler

import (
	"encoding/json"
	"html/template"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/model"
	"github.com/dzerik/auth-portal/internal/service/session"
)

// PortalHandler handles portal routes
type PortalHandler struct {
	sessionManager *session.Manager
	config         *config.Config
	templates      *template.Template
}

// NewPortalHandler creates a new portal handler
func NewPortalHandler(
	sessionMgr *session.Manager,
	cfg *config.Config,
	templates *template.Template,
) *PortalHandler {
	return &PortalHandler{
		sessionManager: sessionMgr,
		config:         cfg,
		templates:      templates,
	}
}

// PortalPageData represents data for the portal page template
type PortalPageData struct {
	Title    string
	User     *model.User
	Services []ServiceView
	Error    string
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

	data := PortalPageData{
		Title:    "Service Portal",
		User:     sess.User,
		Services: services,
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

// getServicesForUser returns services available to the user
// Note: Auth portal doesn't filter by roles/groups - it shows all services
// Authorization is handled by the backend services themselves
func (h *PortalHandler) getServicesForUser(user *model.User) []ServiceView {
	var services []ServiceView

	for _, svc := range h.config.Services {
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
