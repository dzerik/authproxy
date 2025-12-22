package handler

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

// ErrorPageData represents data for the error page template
type ErrorPageData struct {
	Title   string
	Message string
	Status  int
}

// validateRedirectURL validates a redirect URL to prevent open redirect attacks.
// Only allows relative paths that don't contain path traversal or protocol-relative URLs.
func (h *AuthHandler) validateRedirectURL(redirectURL string) string {
	if redirectURL == "" {
		return "/portal"
	}

	// Only allow relative paths starting with /
	if !strings.HasPrefix(redirectURL, "/") {
		return "/portal"
	}

	// Prevent protocol-relative URLs (//evil.com)
	if strings.HasPrefix(redirectURL, "//") {
		return "/portal"
	}

	// Prevent path traversal
	if strings.Contains(redirectURL, "..") {
		return "/portal"
	}

	// Prevent URL encoded traversal
	if strings.Contains(redirectURL, "%2e") || strings.Contains(redirectURL, "%2E") {
		return "/portal"
	}

	return redirectURL
}

// extractNonceFromIDToken extracts the nonce claim from an ID token without full verification.
// The token is already verified by the IdP exchange, this just extracts the nonce for validation.
func (h *AuthHandler) extractNonceFromIDToken(idToken string) (string, error) {
	// ID token is a JWT: header.payload.signature
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return "", nil // Not a valid JWT format, skip nonce validation
	}

	// Decode payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", nil // Can't decode, skip nonce validation
	}

	// Parse claims
	var claims struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", nil // Can't parse, skip nonce validation
	}

	return claims.Nonce, nil
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
