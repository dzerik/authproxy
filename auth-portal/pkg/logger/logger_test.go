package logger

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, "info", cfg.Level)
	assert.False(t, cfg.Development)
	require.Len(t, cfg.OutputPaths, 1)
	assert.Equal(t, "stdout", cfg.OutputPaths[0])
	require.Len(t, cfg.ErrorOutputPaths, 1)
	assert.Equal(t, "stderr", cfg.ErrorOutputPaths[0])
}

func TestConfig_Struct(t *testing.T) {
	cfg := Config{
		Level:            "debug",
		Development:      true,
		OutputPaths:      []string{"stdout", "/var/log/app.log"},
		ErrorOutputPaths: []string{"stderr"},
		InitialFields:    map[string]interface{}{"app": "test"},
	}

	assert.Equal(t, "debug", cfg.Level)
	assert.True(t, cfg.Development)
	assert.Len(t, cfg.OutputPaths, 2)
	assert.Equal(t, "test", cfg.InitialFields["app"])
}

func TestL_BeforeInit(t *testing.T) {
	// Before initialization, L should return a no-op logger
	// Note: This test may not work if Init was called elsewhere
	l := L()
	require.NotNil(t, l)
	// Should not panic
	l.Info("test message")
}

func TestS_BeforeInit(t *testing.T) {
	s := S()
	require.NotNil(t, s)
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
	require.NotNil(t, l)
	// Should not panic
	l.Info("named logger test")
}

func TestWith(t *testing.T) {
	l := With(zap.String("key", "value"))
	require.NotNil(t, l)
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
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetLevel(t *testing.T) {
	// Set a known level first
	_ = SetLevel("info")

	level := GetLevel()
	assert.NotEmpty(t, level)
}

func TestLevelHandler(t *testing.T) {
	handler := LevelHandler()
	require.NotNil(t, handler)

	// Test GET request
	req := httptest.NewRequest(http.MethodGet, "/log/level", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return current level
	assert.Equal(t, http.StatusOK, rr.Code)
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
		assert.NotNil(t, l)
	})

	t.Run("empty context", func(t *testing.T) {
		l := FromContext(context.Background())
		assert.NotNil(t, l)
	})

	t.Run("context with logger", func(t *testing.T) {
		testLogger := zap.NewNop()
		ctx := ToContext(context.Background(), testLogger)

		l := FromContext(ctx)
		assert.Equal(t, testLogger, l)
	})

	t.Run("context with correlation ID", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), correlationIDKey, "test-correlation-id")

		l := FromContext(ctx)
		assert.NotNil(t, l)
	})
}

func TestToContext(t *testing.T) {
	testLogger := zap.NewNop()
	ctx := ToContext(context.Background(), testLogger)

	require.NotNil(t, ctx)

	l, ok := ctx.Value(loggerKey).(*zap.Logger)
	assert.True(t, ok)
	assert.Equal(t, testLogger, l)
}

func TestWithCorrelationID(t *testing.T) {
	ctx := WithCorrelationID(context.Background(), "test-correlation-123")

	require.NotNil(t, ctx)

	// Check correlation ID is stored
	id := GetCorrelationID(ctx)
	assert.Equal(t, "test-correlation-123", id)

	// Check logger is in context
	l := FromContext(ctx)
	assert.NotNil(t, l)
}

func TestGetCorrelationID(t *testing.T) {
	t.Run("with correlation ID", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), correlationIDKey, "test-id")
		id := GetCorrelationID(ctx)
		assert.Equal(t, "test-id", id)
	})

	t.Run("without correlation ID", func(t *testing.T) {
		id := GetCorrelationID(context.Background())
		assert.Empty(t, id)
	})
}

func TestNewRequestLogger(t *testing.T) {
	ctx := context.Background()

	l := NewRequestLogger(ctx, "GET", "/api/test", "request-123")
	require.NotNil(t, l)

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
	assert.Equal(t, "key", s.Key)

	i := Int("count", 42)
	assert.Equal(t, "count", i.Key)

	i64 := Int64("big", 1234567890)
	assert.Equal(t, "big", i64.Key)

	f := Float64("ratio", 3.14)
	assert.Equal(t, "ratio", f.Key)

	b := Bool("enabled", true)
	assert.Equal(t, "enabled", b.Key)
}

func TestContextKey(t *testing.T) {
	// Test that context keys are distinct
	assert.NotEqual(t, correlationIDKey, loggerKey)
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
