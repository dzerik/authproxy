package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListenerMetricsMiddleware_ServeHTTP(t *testing.T) {
	// Create a fresh metrics instance for testing
	m := &Metrics{
		ListenerRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "test_listener_requests_total",
			},
			[]string{"listener", "type", "method", "status"},
		),
		ListenerRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "test_listener_request_duration",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"listener", "type"},
		),
		ListenerConnectionsActive: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "test_listener_connections_active",
			},
			[]string{"listener", "type"},
		),
		ListenerBytesReceived: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "test_listener_bytes_received",
			},
			[]string{"listener", "type"},
		),
		ListenerBytesSent: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "test_listener_bytes_sent",
			},
			[]string{"listener", "type"},
		),
		ListenerErrorsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "test_listener_errors_total",
			},
			[]string{"listener", "type", "error_type"},
		),
	}

	t.Run("successful request", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Hello, World!"))
		})

		middleware := NewListenerMetricsMiddleware(handler, "test-listener", "proxy", m)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		middleware.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "Hello, World!", rec.Body.String())
	})

	t.Run("error request", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal Server Error"))
		})

		middleware := NewListenerMetricsMiddleware(handler, "test-listener", "proxy", m)

		req := httptest.NewRequest(http.MethodPost, "/error", nil)
		rec := httptest.NewRecorder()

		middleware.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("client error request", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		})

		middleware := NewListenerMetricsMiddleware(handler, "test-listener", "egress", m)

		req := httptest.NewRequest(http.MethodDelete, "/bad", nil)
		rec := httptest.NewRecorder()

		middleware.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestWrapWithListenerMetrics(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := WrapWithListenerMetrics(handler, "my-listener", "proxy")
	require.NotNil(t, wrapped)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMetricsResponseWriter(t *testing.T) {
	t.Run("captures status code", func(t *testing.T) {
		rec := httptest.NewRecorder()
		w := &metricsResponseWriter{ResponseWriter: rec, statusCode: http.StatusOK}

		w.WriteHeader(http.StatusNotFound)
		assert.Equal(t, http.StatusNotFound, w.statusCode)
	})

	t.Run("captures bytes written", func(t *testing.T) {
		rec := httptest.NewRecorder()
		w := &metricsResponseWriter{ResponseWriter: rec, statusCode: http.StatusOK}

		n, err := w.Write([]byte("Hello"))
		require.NoError(t, err)
		assert.Equal(t, 5, n)
		assert.Equal(t, int64(5), w.bytesWritten)

		n, err = w.Write([]byte(" World"))
		require.NoError(t, err)
		assert.Equal(t, 6, n)
		assert.Equal(t, int64(11), w.bytesWritten)
	})

	t.Run("implements Flusher", func(t *testing.T) {
		rec := httptest.NewRecorder()
		w := &metricsResponseWriter{ResponseWriter: rec, statusCode: http.StatusOK}

		// Should not panic
		w.Flush()
	})
}
