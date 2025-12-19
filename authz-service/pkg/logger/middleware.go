package logger

import (
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
)

// CorrelationIDMiddleware extracts or generates a correlation ID and adds it
// to the request context and logger. It also adds the correlation ID to the
// response headers for end-to-end tracing.
func CorrelationIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to extract correlation ID from headers (order of precedence)
		correlationID := r.Header.Get(CorrelationIDHeader)
		if correlationID == "" {
			correlationID = r.Header.Get("X-Request-ID")
		}
		if correlationID == "" {
			// Fall back to chi's request ID if available
			correlationID = middleware.GetReqID(r.Context())
		}

		// If still no ID, this shouldn't happen if chi.RequestID middleware is used
		// but handle gracefully
		if correlationID == "" {
			correlationID = "unknown"
		}

		// Add correlation ID to context with logger
		ctx := WithCorrelationIDLogger(r.Context(), correlationID)

		// Add correlation ID to response header
		w.Header().Set(CorrelationIDHeader, correlationID)

		// Continue with the enriched context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
