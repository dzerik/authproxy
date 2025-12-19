package metrics

import (
	"net/http"
	"strconv"
	"time"
)

// ListenerMetricsMiddleware wraps an http.Handler with per-listener metrics.
type ListenerMetricsMiddleware struct {
	handler      http.Handler
	listenerName string
	listenerType string
	metrics      *Metrics
}

// NewListenerMetricsMiddleware creates a new middleware that records per-listener metrics.
func NewListenerMetricsMiddleware(handler http.Handler, listenerName, listenerType string, m *Metrics) *ListenerMetricsMiddleware {
	if m == nil {
		m = DefaultMetrics
	}
	return &ListenerMetricsMiddleware{
		handler:      handler,
		listenerName: listenerName,
		listenerType: listenerType,
		metrics:      m,
	}
}

// ServeHTTP implements http.Handler.
func (m *ListenerMetricsMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Increment active connections
	m.metrics.IncListenerConnections(m.listenerName, m.listenerType)
	defer m.metrics.DecListenerConnections(m.listenerName, m.listenerType)

	// Track request body size if available
	if r.ContentLength > 0 {
		m.metrics.AddListenerBytesReceived(m.listenerName, m.listenerType, float64(r.ContentLength))
	}

	// Wrap response writer to capture status and bytes written
	wrapped := &metricsResponseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}

	// Call the underlying handler
	m.handler.ServeHTTP(wrapped, r)

	// Record metrics
	duration := time.Since(start).Seconds()
	status := strconv.Itoa(wrapped.statusCode)

	m.metrics.RecordListenerRequest(m.listenerName, m.listenerType, r.Method, status)
	m.metrics.RecordListenerDuration(m.listenerName, m.listenerType, duration)

	if wrapped.bytesWritten > 0 {
		m.metrics.AddListenerBytesSent(m.listenerName, m.listenerType, float64(wrapped.bytesWritten))
	}

	// Record errors (5xx status codes)
	if wrapped.statusCode >= 500 {
		m.metrics.RecordListenerError(m.listenerName, m.listenerType, "server_error")
	} else if wrapped.statusCode >= 400 {
		m.metrics.RecordListenerError(m.listenerName, m.listenerType, "client_error")
	}
}

// metricsResponseWriter wraps http.ResponseWriter to capture status and bytes written.
type metricsResponseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

func (w *metricsResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *metricsResponseWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.bytesWritten += int64(n)
	return n, err
}

// Flush implements http.Flusher if the underlying ResponseWriter supports it.
func (w *metricsResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// WrapWithListenerMetrics is a convenience function to wrap a handler with listener metrics.
func WrapWithListenerMetrics(handler http.Handler, listenerName, listenerType string) http.Handler {
	return NewListenerMetricsMiddleware(handler, listenerName, listenerType, DefaultMetrics)
}
