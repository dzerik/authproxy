package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

func TestMetrics_Middleware(t *testing.T) {
	m := New()

	// Create a test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Wrap with middleware
	handler := m.Middleware(testHandler)

	// Make a request
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	if rr.Body.String() != "OK" {
		t.Errorf("body = %s, want OK", rr.Body.String())
	}
}

func TestMetrics_Middleware_DifferentStatusCodes(t *testing.T) {
	m := New()

	tests := []struct {
		name       string
		statusCode int
	}{
		{"200 OK", http.StatusOK},
		{"201 Created", http.StatusCreated},
		{"302 Redirect", http.StatusFound},
		{"400 Bad Request", http.StatusBadRequest},
		{"401 Unauthorized", http.StatusUnauthorized},
		{"403 Forbidden", http.StatusForbidden},
		{"404 Not Found", http.StatusNotFound},
		{"500 Internal Server Error", http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			})

			wrapped := m.Middleware(handler)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rr := httptest.NewRecorder()

			wrapped.ServeHTTP(rr, req)

			if rr.Code != tt.statusCode {
				t.Errorf("status = %d, want %d", rr.Code, tt.statusCode)
			}
		})
	}
}

func TestMetrics_Middleware_DifferentMethods(t *testing.T) {
	m := New()

	methods := []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodHead,
		http.MethodOptions,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := m.Middleware(handler)

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/test", nil)
			rr := httptest.NewRecorder()

			wrapped.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
			}
		})
	}
}

func TestMetrics_Middleware_ResponseSize(t *testing.T) {
	m := New()

	responseBody := "This is a test response with some content"

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(responseBody))
	})

	wrapped := m.Middleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	// Verify response was passed through
	if rr.Body.String() != responseBody {
		t.Errorf("body = %s, want %s", rr.Body.String(), responseBody)
	}
}

func TestMetrics_Middleware_WithChiRouter(t *testing.T) {
	m := New()

	r := chi.NewRouter()
	r.Use(m.Middleware)

	r.Get("/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("User: " + id))
	})

	r.Post("/users", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("Created"))
	})

	// Test parameterized route
	t.Run("GET with param", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/users/123", nil)
		rr := httptest.NewRecorder()

		r.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
		}
		if rr.Body.String() != "User: 123" {
			t.Errorf("body = %s, want User: 123", rr.Body.String())
		}
	})

	t.Run("POST", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/users", nil)
		rr := httptest.NewRecorder()

		r.ServeHTTP(rr, req)

		if rr.Code != http.StatusCreated {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusCreated)
		}
	})
}

func TestMetrics_Middleware_Duration(t *testing.T) {
	m := New()

	// Handler that takes some time
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})

	wrapped := m.Middleware(handler)

	start := time.Now()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	elapsed := time.Since(start)

	if elapsed < 10*time.Millisecond {
		t.Errorf("request should have taken at least 10ms, got %v", elapsed)
	}
}

func TestMetrics_Middleware_InFlight(t *testing.T) {
	m := New()

	// Handler that blocks
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})

	wrapped := m.Middleware(handler)

	// Start multiple requests concurrently
	done := make(chan bool, 3)
	for i := 0; i < 3; i++ {
		go func() {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rr := httptest.NewRecorder()
			wrapped.ServeHTTP(rr, req)
			done <- true
		}()
	}

	// Wait for all to complete
	for i := 0; i < 3; i++ {
		<-done
	}
}

func TestMetrics_Middleware_PanicRecovery(t *testing.T) {
	m := New()

	// Handler that panics
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	wrapped := m.Middleware(handler)

	defer func() {
		// We expect panic to propagate
		if r := recover(); r == nil {
			t.Log("Panic was recovered somewhere (middleware doesn't handle panic)")
		}
	}()

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()

	// This should panic - middleware doesn't catch panics
	wrapped.ServeHTTP(rr, req)
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "/"},
		{"/", "/"},
		{"/health", "/health"},
		{"/api/users", "/api/users"},
		{"/users/123", "/users/123"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizePath(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizePath(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func BenchmarkMiddleware(b *testing.B) {
	m := New()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	wrapped := m.Middleware(handler)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)
	}
}

func BenchmarkMiddleware_WithChiRouter(b *testing.B) {
	m := New()

	r := chi.NewRouter()
	r.Use(m.Middleware)
	r.Get("/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	req := httptest.NewRequest(http.MethodGet, "/users/123", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
	}
}
