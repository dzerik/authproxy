package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Middleware returns an HTTP middleware that records Prometheus metrics
// for each request.
func (m *Metrics) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Track in-flight requests
		m.InFlightInc()
		defer m.InFlightDec()

		// Wrap response writer to capture status code and size
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		// Process request
		next.ServeHTTP(ww, r)

		// Calculate duration
		duration := time.Since(start).Seconds()

		// Get route pattern or path
		path := r.URL.Path
		if rctx := chi.RouteContext(r.Context()); rctx != nil {
			if pattern := rctx.RoutePattern(); pattern != "" {
				path = pattern
			}
		}

		// Record metrics
		status := strconv.Itoa(ww.Status())
		m.RecordHTTPRequest(r.Method, path, status)
		m.RecordHTTPDuration(r.Method, path, duration)
		m.RecordHTTPResponseSize(r.Method, path, float64(ww.BytesWritten()))
	})
}

// NormalizePath normalizes the path for metrics to avoid high cardinality.
// It replaces dynamic segments with placeholders.
func NormalizePath(path string) string {
	if path == "" {
		return "/"
	}
	return path
}
