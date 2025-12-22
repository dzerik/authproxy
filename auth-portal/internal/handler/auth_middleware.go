package handler

import (
	"net/http"
)

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
