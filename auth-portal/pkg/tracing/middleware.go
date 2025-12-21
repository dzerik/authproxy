package tracing

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// Middleware returns an HTTP middleware that instruments requests with OpenTelemetry.
// It creates spans for each request and propagates context.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get route pattern from chi for better span naming
		routePattern := r.URL.Path
		if rctx := chi.RouteContext(r.Context()); rctx != nil {
			if pattern := rctx.RoutePattern(); pattern != "" {
				routePattern = pattern
			}
		}

		// Create span name
		spanName := r.Method + " " + routePattern

		// Get request ID if available
		requestID := middleware.GetReqID(r.Context())

		// Start span
		ctx, span := Start(r.Context(), spanName,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				AttrHTTPMethod.String(r.Method),
				AttrHTTPPath.String(r.URL.Path),
				AttrRequestID.String(requestID),
				attribute.String("http.scheme", getScheme(r)),
				attribute.String("http.host", r.Host),
				attribute.String("http.user_agent", r.UserAgent()),
				attribute.String("net.peer.ip", r.RemoteAddr),
			),
		)
		defer span.End()

		// Wrap response writer to capture status code
		ww := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Process request with updated context
		next.ServeHTTP(ww, r.WithContext(ctx))

		// Add response attributes
		span.SetAttributes(
			AttrHTTPStatus.Int(ww.statusCode),
			attribute.Int("http.response_size", ww.bytesWritten),
		)

		// Set span status based on HTTP status code
		if ww.statusCode >= 400 {
			span.SetStatus(codes.Error, http.StatusText(ww.statusCode))
		}
	})
}

// Handler wraps an http.Handler with OpenTelemetry instrumentation.
// This is an alternative to Middleware that uses otelhttp directly.
func Handler(handler http.Handler, operation string) http.Handler {
	return otelhttp.NewHandler(handler, operation,
		otelhttp.WithPropagators(propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		)),
	)
}

// Client returns an HTTP client with tracing instrumentation.
func Client(base *http.Client) *http.Client {
	if base == nil {
		base = http.DefaultClient
	}

	return &http.Client{
		Transport: otelhttp.NewTransport(base.Transport),
		Timeout:   base.Timeout,
	}
}

// RoundTripper returns an http.RoundTripper with tracing instrumentation.
func RoundTripper(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return otelhttp.NewTransport(base)
}

// responseWriter wraps http.ResponseWriter to capture status code and bytes written.
type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += n
	return n, err
}

// getScheme returns the request scheme (http or https).
func getScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	return "http"
}

// Flush implements http.Flusher.
func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker for WebSocket support.
func (rw *responseWriter) Hijack() (c interface{}, rw2 interface{}, err error) {
	if h, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}
