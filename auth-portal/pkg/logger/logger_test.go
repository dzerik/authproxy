package logger

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"go.uber.org/zap"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Level != "info" {
		t.Errorf("Level = %s, want info", cfg.Level)
	}
	if cfg.Development {
		t.Error("Development should be false")
	}
	if len(cfg.OutputPaths) != 1 || cfg.OutputPaths[0] != "stdout" {
		t.Errorf("OutputPaths = %v, want [stdout]", cfg.OutputPaths)
	}
	if len(cfg.ErrorOutputPaths) != 1 || cfg.ErrorOutputPaths[0] != "stderr" {
		t.Errorf("ErrorOutputPaths = %v, want [stderr]", cfg.ErrorOutputPaths)
	}
}

func TestConfig_Struct(t *testing.T) {
	cfg := Config{
		Level:            "debug",
		Development:      true,
		OutputPaths:      []string{"stdout", "/var/log/app.log"},
		ErrorOutputPaths: []string{"stderr"},
		InitialFields:    map[string]interface{}{"app": "test"},
	}

	if cfg.Level != "debug" {
		t.Errorf("Level = %s, want debug", cfg.Level)
	}
	if !cfg.Development {
		t.Error("Development should be true")
	}
	if len(cfg.OutputPaths) != 2 {
		t.Errorf("OutputPaths length = %d, want 2", len(cfg.OutputPaths))
	}
	if cfg.InitialFields["app"] != "test" {
		t.Error("InitialFields should contain app=test")
	}
}

func TestL_BeforeInit(t *testing.T) {
	// Before initialization, L should return a no-op logger
	// Note: This test may not work if Init was called elsewhere
	l := L()
	if l == nil {
		t.Error("L should not return nil")
	}
	// Should not panic
	l.Info("test message")
}

func TestS_BeforeInit(t *testing.T) {
	s := S()
	if s == nil {
		t.Error("S should not return nil")
	}
	// Should not panic
	s.Info("test message")
}

func TestInit(t *testing.T) {
	// Note: Due to sync.Once, Init can only be called once
	// This test may behave differently if run in isolation
	cfg := Config{
		Level:       "debug",
		Development: true,
		OutputPaths: []string{"stdout"},
	}

	err := Init(cfg)
	// First call may succeed, subsequent calls return the same result
	if err != nil {
		t.Logf("Init returned error (may be expected if already initialized): %v", err)
	}
}

func TestNamed(t *testing.T) {
	l := Named("test-logger")
	if l == nil {
		t.Fatal("Named returned nil")
	}
	// Should not panic
	l.Info("named logger test")
}

func TestWith(t *testing.T) {
	l := With(zap.String("key", "value"))
	if l == nil {
		t.Fatal("With returned nil")
	}
	// Should not panic
	l.Info("with fields test")
}

func TestSetLevel(t *testing.T) {
	tests := []struct {
		level   string
		wantErr bool
	}{
		{"debug", false},
		{"info", false},
		{"warn", false},
		{"error", false},
		{"invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			err := SetLevel(tt.level)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetLevel(%s) error = %v, wantErr = %v", tt.level, err, tt.wantErr)
			}
		})
	}
}

func TestGetLevel(t *testing.T) {
	// Set a known level first
	_ = SetLevel("info")

	level := GetLevel()
	if level == "" {
		t.Error("GetLevel should not return empty string")
	}
}

func TestLevelHandler(t *testing.T) {
	handler := LevelHandler()
	if handler == nil {
		t.Fatal("LevelHandler returned nil")
	}

	// Test GET request
	req := httptest.NewRequest(http.MethodGet, "/log/level", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return current level
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestSync(t *testing.T) {
	// Should not panic
	err := Sync()
	if err != nil {
		// Sync may fail on some outputs, that's OK
		t.Logf("Sync returned error (may be expected): %v", err)
	}
}

func TestFromContext(t *testing.T) {
	t.Run("nil context", func(t *testing.T) {
		l := FromContext(nil)
		if l == nil {
			t.Error("FromContext should not return nil")
		}
	})

	t.Run("empty context", func(t *testing.T) {
		l := FromContext(context.Background())
		if l == nil {
			t.Error("FromContext should not return nil")
		}
	})

	t.Run("context with logger", func(t *testing.T) {
		testLogger := zap.NewNop()
		ctx := ToContext(context.Background(), testLogger)

		l := FromContext(ctx)
		if l != testLogger {
			t.Error("FromContext should return the logger from context")
		}
	})

	t.Run("context with correlation ID", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), correlationIDKey, "test-correlation-id")

		l := FromContext(ctx)
		if l == nil {
			t.Error("FromContext should not return nil")
		}
	})
}

func TestToContext(t *testing.T) {
	testLogger := zap.NewNop()
	ctx := ToContext(context.Background(), testLogger)

	if ctx == nil {
		t.Fatal("ToContext returned nil context")
	}

	l, ok := ctx.Value(loggerKey).(*zap.Logger)
	if !ok {
		t.Error("Logger not found in context")
	}
	if l != testLogger {
		t.Error("Logger in context doesn't match")
	}
}

func TestWithCorrelationID(t *testing.T) {
	ctx := WithCorrelationID(context.Background(), "test-correlation-123")

	if ctx == nil {
		t.Fatal("WithCorrelationID returned nil context")
	}

	// Check correlation ID is stored
	id := GetCorrelationID(ctx)
	if id != "test-correlation-123" {
		t.Errorf("GetCorrelationID = %s, want test-correlation-123", id)
	}

	// Check logger is in context
	l := FromContext(ctx)
	if l == nil {
		t.Error("Logger should be in context")
	}
}

func TestGetCorrelationID(t *testing.T) {
	t.Run("with correlation ID", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), correlationIDKey, "test-id")
		id := GetCorrelationID(ctx)
		if id != "test-id" {
			t.Errorf("GetCorrelationID = %s, want test-id", id)
		}
	})

	t.Run("without correlation ID", func(t *testing.T) {
		id := GetCorrelationID(context.Background())
		if id != "" {
			t.Errorf("GetCorrelationID = %s, want empty string", id)
		}
	})
}

func TestNewRequestLogger(t *testing.T) {
	ctx := context.Background()

	l := NewRequestLogger(ctx, "GET", "/api/test", "request-123")
	if l == nil {
		t.Fatal("NewRequestLogger returned nil")
	}

	// Should not panic
	l.Info("test request log")
}

func TestMustInit(t *testing.T) {
	// MustInit with valid config should not panic
	// Note: Due to sync.Once, this may not actually reinitialize
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MustInit panicked: %v", r)
		}
	}()

	MustInit(DefaultConfig())
}

func TestInitFromEnv(t *testing.T) {
	// Set test environment variables
	os.Setenv("LOG_LEVEL", "debug")
	os.Setenv("DEV_MODE", "true")
	defer func() {
		os.Unsetenv("LOG_LEVEL")
		os.Unsetenv("DEV_MODE")
	}()

	err := InitFromEnv()
	// May succeed or return nil (already initialized)
	if err != nil {
		t.Logf("InitFromEnv returned error (may be expected if already initialized): %v", err)
	}
}

func TestLogFunctions(t *testing.T) {
	// Test that global log functions don't panic
	Debug("debug message", zap.String("key", "value"))
	Info("info message", zap.String("key", "value"))
	Warn("warn message", zap.String("key", "value"))
	Error("error message", zap.String("key", "value"))
	// Don't test Fatal as it would exit
}

func TestFieldConstructors(t *testing.T) {
	// Test that field constructors are properly aliased
	s := String("key", "value")
	if s.Key != "key" {
		t.Error("String field key incorrect")
	}

	i := Int("count", 42)
	if i.Key != "count" {
		t.Error("Int field key incorrect")
	}

	i64 := Int64("big", 1234567890)
	if i64.Key != "big" {
		t.Error("Int64 field key incorrect")
	}

	f := Float64("ratio", 3.14)
	if f.Key != "ratio" {
		t.Error("Float64 field key incorrect")
	}

	b := Bool("enabled", true)
	if b.Key != "enabled" {
		t.Error("Bool field key incorrect")
	}
}

func TestContextKey(t *testing.T) {
	// Test that context keys are distinct
	if correlationIDKey == loggerKey {
		t.Error("Context keys should be different")
	}
}

func BenchmarkFromContext(b *testing.B) {
	ctx := WithCorrelationID(context.Background(), "bench-correlation-id")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FromContext(ctx)
	}
}

func BenchmarkNewRequestLogger(b *testing.B) {
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewRequestLogger(ctx, "GET", "/api/test", "request-123")
	}
}

func BenchmarkInfo(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Info("benchmark message", zap.String("key", "value"))
	}
}
