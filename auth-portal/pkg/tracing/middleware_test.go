package tracing

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
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

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	if rr.Body.String() != "OK" {
		t.Errorf("body = %s, want OK", rr.Body.String())
	}
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

			if rr.Code != tt.status {
				t.Errorf("status = %d, want %d", rr.Code, tt.status)
			}
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

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	if rr.Body.String() != "User: 123" {
		t.Errorf("body = %s, want User: 123", rr.Body.String())
	}
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

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestClient(t *testing.T) {
	t.Run("with nil base", func(t *testing.T) {
		client := Client(nil)
		if client == nil {
			t.Error("Client should not return nil")
		}
		if client.Transport == nil {
			t.Error("Transport should be instrumented")
		}
	})

	t.Run("with custom base", func(t *testing.T) {
		base := &http.Client{
			Timeout: 30 * 1000000000, // 30s
		}
		client := Client(base)
		if client == nil {
			t.Error("Client should not return nil")
		}
		if client.Timeout != base.Timeout {
			t.Error("Timeout should be preserved")
		}
	})
}

func TestRoundTripper(t *testing.T) {
	t.Run("with nil base", func(t *testing.T) {
		rt := RoundTripper(nil)
		if rt == nil {
			t.Error("RoundTripper should not return nil")
		}
	})

	t.Run("with custom base", func(t *testing.T) {
		base := http.DefaultTransport
		rt := RoundTripper(base)
		if rt == nil {
			t.Error("RoundTripper should not return nil")
		}
	})
}

func TestResponseWriter(t *testing.T) {
	t.Run("WriteHeader", func(t *testing.T) {
		rr := httptest.NewRecorder()
		rw := &responseWriter{ResponseWriter: rr, statusCode: http.StatusOK}

		rw.WriteHeader(http.StatusNotFound)

		if rw.statusCode != http.StatusNotFound {
			t.Errorf("statusCode = %d, want %d", rw.statusCode, http.StatusNotFound)
		}
		if rr.Code != http.StatusNotFound {
			t.Errorf("underlying status = %d, want %d", rr.Code, http.StatusNotFound)
		}
	})

	t.Run("Write", func(t *testing.T) {
		rr := httptest.NewRecorder()
		rw := &responseWriter{ResponseWriter: rr, statusCode: http.StatusOK}

		data := []byte("Hello, World!")
		n, err := rw.Write(data)

		if err != nil {
			t.Errorf("Write failed: %v", err)
		}
		if n != len(data) {
			t.Errorf("bytes written = %d, want %d", n, len(data))
		}
		if rw.bytesWritten != len(data) {
			t.Errorf("bytesWritten = %d, want %d", rw.bytesWritten, len(data))
		}
	})

	t.Run("multiple writes", func(t *testing.T) {
		rr := httptest.NewRecorder()
		rw := &responseWriter{ResponseWriter: rr, statusCode: http.StatusOK}

		rw.Write([]byte("Hello"))
		rw.Write([]byte(", "))
		rw.Write([]byte("World!"))

		if rw.bytesWritten != 13 {
			t.Errorf("bytesWritten = %d, want 13", rw.bytesWritten)
		}
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
			if scheme != tt.expected {
				t.Errorf("getScheme = %s, want %s", scheme, tt.expected)
			}
		})
	}
}

func TestResponseWriter_Flush(t *testing.T) {
	rr := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rr, statusCode: http.StatusOK}

	// Should not panic
	rw.Flush()

	// Verify flush was called on underlying writer
	if !rr.Flushed {
		t.Error("Underlying writer should be flushed")
	}
}

func TestResponseWriter_Hijack(t *testing.T) {
	t.Run("without hijacker", func(t *testing.T) {
		rr := httptest.NewRecorder()
		rw := &responseWriter{ResponseWriter: rr, statusCode: http.StatusOK}

		_, _, err := rw.Hijack()
		if err != http.ErrNotSupported {
			t.Errorf("Hijack should return ErrNotSupported, got %v", err)
		}
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
	if span == nil {
		t.Error("Context should have span")
	}
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
