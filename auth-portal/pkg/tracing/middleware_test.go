package tracing

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	wrapped := Middleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "OK", rr.Body.String())
}

func TestMiddleware_DifferentStatusCodes(t *testing.T) {
	tests := []struct {
		name   string
		status int
	}{
		{"200 OK", http.StatusOK},
		{"201 Created", http.StatusCreated},
		{"302 Redirect", http.StatusFound},
		{"400 Bad Request", http.StatusBadRequest},
		{"401 Unauthorized", http.StatusUnauthorized},
		{"404 Not Found", http.StatusNotFound},
		{"500 Internal Server Error", http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
			})

			wrapped := Middleware(handler)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rr := httptest.NewRecorder()

			wrapped.ServeHTTP(rr, req)

			assert.Equal(t, tt.status, rr.Code)
		})
	}
}

func TestMiddleware_WithChiRouter(t *testing.T) {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(Middleware)

	r.Get("/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("User: " + id))
	})

	req := httptest.NewRequest(http.MethodGet, "/users/123", nil)
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "User: 123", rr.Body.String())
}

func TestHandler(t *testing.T) {
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	wrapped := Handler(innerHandler, "test-operation")

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestClient(t *testing.T) {
	t.Run("with nil base", func(t *testing.T) {
		client := Client(nil)
		require.NotNil(t, client)
		assert.NotNil(t, client.Transport)
	})

	t.Run("with custom base", func(t *testing.T) {
		base := &http.Client{
			Timeout: 30 * 1000000000, // 30s
		}
		client := Client(base)
		require.NotNil(t, client)
		assert.Equal(t, base.Timeout, client.Timeout)
	})
}

func TestRoundTripper(t *testing.T) {
	t.Run("with nil base", func(t *testing.T) {
		rt := RoundTripper(nil)
		assert.NotNil(t, rt)
	})

	t.Run("with custom base", func(t *testing.T) {
		base := http.DefaultTransport
		rt := RoundTripper(base)
		assert.NotNil(t, rt)
	})
}

func TestResponseWriter(t *testing.T) {
	t.Run("WriteHeader", func(t *testing.T) {
		rr := httptest.NewRecorder()
		rw := &responseWriter{ResponseWriter: rr, statusCode: http.StatusOK}

		rw.WriteHeader(http.StatusNotFound)

		assert.Equal(t, http.StatusNotFound, rw.statusCode)
		assert.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("Write", func(t *testing.T) {
		rr := httptest.NewRecorder()
		rw := &responseWriter{ResponseWriter: rr, statusCode: http.StatusOK}

		data := []byte("Hello, World!")
		n, err := rw.Write(data)

		require.NoError(t, err)
		assert.Equal(t, len(data), n)
		assert.Equal(t, len(data), rw.bytesWritten)
	})

	t.Run("multiple writes", func(t *testing.T) {
		rr := httptest.NewRecorder()
		rw := &responseWriter{ResponseWriter: rr, statusCode: http.StatusOK}

		rw.Write([]byte("Hello"))
		rw.Write([]byte(", "))
		rw.Write([]byte("World!"))

		assert.Equal(t, 13, rw.bytesWritten)
	})
}

func TestGetScheme(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*http.Request)
		expected string
	}{
		{
			name:     "http default",
			setup:    func(r *http.Request) {},
			expected: "http",
		},
		{
			name: "https from TLS",
			setup: func(r *http.Request) {
				r.TLS = &tls.ConnectionState{}
			},
			expected: "https",
		},
		{
			name: "from X-Forwarded-Proto",
			setup: func(r *http.Request) {
				r.Header.Set("X-Forwarded-Proto", "https")
			},
			expected: "https",
		},
		{
			name: "TLS takes precedence",
			setup: func(r *http.Request) {
				r.TLS = &tls.ConnectionState{}
				r.Header.Set("X-Forwarded-Proto", "http")
			},
			expected: "https",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			tt.setup(req)

			scheme := getScheme(req)
			assert.Equal(t, tt.expected, scheme)
		})
	}
}

func TestResponseWriter_Flush(t *testing.T) {
	rr := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rr, statusCode: http.StatusOK}

	// Should not panic
	rw.Flush()

	// Verify flush was called on underlying writer
	assert.True(t, rr.Flushed)
}

func TestResponseWriter_Hijack(t *testing.T) {
	t.Run("without hijacker", func(t *testing.T) {
		rr := httptest.NewRecorder()
		rw := &responseWriter{ResponseWriter: rr, statusCode: http.StatusOK}

		_, _, err := rw.Hijack()
		assert.Equal(t, http.ErrNotSupported, err)
	})
}

func TestMiddleware_SpanContext(t *testing.T) {
	// Initialize tracing first
	_, _ = Init(context.Background(), Config{
		Enabled:     false,
		ServiceName: "test",
	})

	var capturedCtx context.Context
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedCtx = r.Context()
		w.WriteHeader(http.StatusOK)
	})

	wrapped := Middleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	// Context should have span
	span := SpanFromContext(capturedCtx)
	assert.NotNil(t, span)
}

func BenchmarkMiddleware(b *testing.B) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := Middleware(handler)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)
	}
}

func BenchmarkHandler(b *testing.B) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := Handler(handler, "benchmark")
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)
	}
}

func BenchmarkResponseWriter_Write(b *testing.B) {
	data := []byte("Hello, World!")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		rw := &responseWriter{ResponseWriter: rr, statusCode: http.StatusOK}
		rw.Write(data)
	}
}
