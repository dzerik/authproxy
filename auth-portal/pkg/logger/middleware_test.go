package logger

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"
)

func TestRequestLogger(t *testing.T) {
	// Create test handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Wrap with middleware
	wrapped := RequestLogger(handler)

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

func TestRequestLogger_DifferentStatusCodes(t *testing.T) {
	tests := []struct {
		name   string
		status int
	}{
		{"200 OK", http.StatusOK},
		{"302 Redirect", http.StatusFound},
		{"400 Bad Request", http.StatusBadRequest},
		{"401 Unauthorized", http.StatusUnauthorized},
		{"404 Not Found", http.StatusNotFound},
		{"500 Internal Server Error", http.StatusInternalServerError},
		{"503 Service Unavailable", http.StatusServiceUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
			})

			wrapped := RequestLogger(handler)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rr := httptest.NewRecorder()

			wrapped.ServeHTTP(rr, req)

			if rr.Code != tt.status {
				t.Errorf("status = %d, want %d", rr.Code, tt.status)
			}
		})
	}
}

func TestRequestLogger_WithRequestID(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that correlation ID is in context
		id := GetCorrelationID(r.Context())
		if id == "" {
			t.Error("Correlation ID should be set in context")
		}
		w.WriteHeader(http.StatusOK)
	})

	// Use chi's request ID middleware first
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(RequestLogger)
	r.Get("/test", handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestRequestLogger_PreservesContext(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Logger should be in context
		l := FromContext(r.Context())
		if l == nil {
			t.Error("Logger should be in context")
		}
		w.WriteHeader(http.StatusOK)
	})

	wrapped := RequestLogger(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestRecoveryLogger(t *testing.T) {
	t.Run("no panic", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrapped := RecoveryLogger(handler)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rr := httptest.NewRecorder()

		wrapped.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
		}
	})

	t.Run("with panic", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("test panic")
		})

		wrapped := RecoveryLogger(handler)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rr := httptest.NewRecorder()

		// Should not panic - recovery middleware catches it
		wrapped.ServeHTTP(rr, req)

		// Should return 500
		if rr.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
		}
	})

	t.Run("panic with error", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("some error message")
		})

		wrapped := RecoveryLogger(handler)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rr := httptest.NewRecorder()

		wrapped.ServeHTTP(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
		}
	})
}

func TestGenerateRequestID(t *testing.T) {
	id1 := generateRequestID()
	id2 := generateRequestID()

	if id1 == "" {
		t.Error("generateRequestID should not return empty string")
	}

	if id1 == id2 {
		t.Error("generateRequestID should return unique IDs")
	}
}

func TestStructuredLogger(t *testing.T) {
	sl := NewStructuredLogger()

	if sl == nil {
		t.Fatal("NewStructuredLogger returned nil")
	}

	if sl.Logger == nil {
		t.Error("Logger should not be nil")
	}
}

func TestStructuredLogger_NewLogEntry(t *testing.T) {
	sl := &StructuredLogger{Logger: zap.NewNop()}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	// Add request ID to context
	ctx := req.Context()
	req = req.WithContext(ctx)

	entry := sl.NewLogEntry(req)

	if entry == nil {
		t.Fatal("NewLogEntry returned nil")
	}

	sle, ok := entry.(*StructuredLogEntry)
	if !ok {
		t.Fatal("Entry should be *StructuredLogEntry")
	}

	if sle.Logger == nil {
		t.Error("Logger should not be nil")
	}
}

func TestStructuredLogEntry_Write(t *testing.T) {
	tests := []struct {
		name   string
		status int
	}{
		{"success", http.StatusOK},
		{"client error", http.StatusBadRequest},
		{"server error", http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := &StructuredLogEntry{Logger: zap.NewNop()}

			// Should not panic
			entry.Write(tt.status, 100, nil, 10*time.Millisecond, nil)
		})
	}
}

func TestStructuredLogEntry_Panic(t *testing.T) {
	entry := &StructuredLogEntry{Logger: zap.NewNop()}

	// Should not panic
	entry.Panic("test error", []byte("stack trace"))
}

func TestNewStructuredLogger_Integration(t *testing.T) {
	// Initialize logger first
	Init(Config{
		Level:       "debug",
		Development: true,
		OutputPaths: []string{"stdout"},
	})

	sl := NewStructuredLogger()

	if sl.Logger == nil {
		t.Error("Logger should not be nil")
	}

	// Test creating log entry
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	entry := sl.NewLogEntry(req)

	if entry == nil {
		t.Error("NewLogEntry should not return nil")
	}
}

func TestChiMiddlewareIntegration(t *testing.T) {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(RequestLogger)
	r.Use(RecoveryLogger)

	r.Get("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func BenchmarkRequestLogger(b *testing.B) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := RequestLogger(handler)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)
	}
}

func BenchmarkRecoveryLogger(b *testing.B) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := RecoveryLogger(handler)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)
	}
}

func BenchmarkGenerateRequestID(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = generateRequestID()
	}
}
