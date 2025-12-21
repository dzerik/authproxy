// Package logger provides a structured logging solution using zap.
// It supports context-aware logging with correlation IDs, dynamic log level changes,
// and both development and production configurations.
package logger

import (
	"context"
	"net/http"
	"os"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const (
	// correlationIDKey is the context key for correlation ID.
	correlationIDKey contextKey = "correlation_id"
	// loggerKey is the context key for the logger instance.
	loggerKey contextKey = "logger"
)

var (
	// globalLogger is the singleton logger instance.
	globalLogger *zap.Logger
	// atomicLevel allows runtime log level changes.
	atomicLevel zap.AtomicLevel
	// once ensures single initialization.
	once sync.Once
	// initErr stores any initialization error.
	initErr error
)

// Config represents logger configuration.
type Config struct {
	// Level is the minimum log level (debug, info, warn, error).
	Level string
	// Development enables development mode with human-readable output.
	Development bool
	// OutputPaths specifies where to write logs (stdout, stderr, file paths).
	OutputPaths []string
	// ErrorOutputPaths specifies where to write internal logger errors.
	ErrorOutputPaths []string
	// InitialFields are fields added to every log entry.
	InitialFields map[string]interface{}
}

// DefaultConfig returns a default configuration suitable for production.
func DefaultConfig() Config {
	return Config{
		Level:            "info",
		Development:      false,
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}
}

// Init initializes the global logger with the given configuration.
// It is safe to call multiple times; only the first call takes effect.
func Init(cfg Config) error {
	once.Do(func() {
		initErr = initLogger(cfg)
	})
	return initErr
}

// initLogger creates and configures the logger.
func initLogger(cfg Config) error {
	// Parse log level
	atomicLevel = zap.NewAtomicLevel()
	if err := atomicLevel.UnmarshalText([]byte(cfg.Level)); err != nil {
		atomicLevel.SetLevel(zapcore.InfoLevel)
	}

	// Configure encoder
	var encoderConfig zapcore.EncoderConfig
	if cfg.Development {
		encoderConfig = zap.NewDevelopmentEncoderConfig()
		encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	} else {
		encoderConfig = zap.NewProductionEncoderConfig()
		encoderConfig.TimeKey = "timestamp"
		encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}

	// Build zap config
	zapCfg := zap.Config{
		Level:            atomicLevel,
		Development:      cfg.Development,
		Encoding:         "json",
		EncoderConfig:    encoderConfig,
		OutputPaths:      cfg.OutputPaths,
		ErrorOutputPaths: cfg.ErrorOutputPaths,
		InitialFields:    cfg.InitialFields,
	}

	if cfg.Development {
		zapCfg.Encoding = "console"
	}

	// Ensure output paths exist
	if len(zapCfg.OutputPaths) == 0 {
		zapCfg.OutputPaths = []string{"stdout"}
	}
	if len(zapCfg.ErrorOutputPaths) == 0 {
		zapCfg.ErrorOutputPaths = []string{"stderr"}
	}

	// Build logger
	var err error
	globalLogger, err = zapCfg.Build(
		zap.AddCaller(),
		zap.AddCallerSkip(1),
		zap.AddStacktrace(zapcore.ErrorLevel),
	)
	if err != nil {
		return err
	}

	// Replace global logger
	zap.ReplaceGlobals(globalLogger)

	return nil
}

// L returns the global logger instance.
// If not initialized, returns a no-op logger.
func L() *zap.Logger {
	if globalLogger == nil {
		return zap.NewNop()
	}
	return globalLogger
}

// S returns the global sugared logger for convenient logging.
func S() *zap.SugaredLogger {
	return L().Sugar()
}

// Named returns a named child logger.
func Named(name string) *zap.Logger {
	return L().Named(name)
}

// With returns a logger with additional fields.
func With(fields ...zap.Field) *zap.Logger {
	return L().With(fields...)
}

// SetLevel changes the log level at runtime.
func SetLevel(level string) error {
	return atomicLevel.UnmarshalText([]byte(level))
}

// GetLevel returns the current log level.
func GetLevel() string {
	return atomicLevel.Level().String()
}

// ServeHTTP provides an HTTP handler for changing log level via HTTP.
// Usage: http.Handle("/log/level", logger.LevelHandler())
func LevelHandler() http.Handler {
	return atomicLevel
}

// Sync flushes any buffered log entries.
// Applications should call this before exiting.
func Sync() error {
	if globalLogger != nil {
		return globalLogger.Sync()
	}
	return nil
}

// FromContext retrieves the logger from context.
// If no logger is found, returns the global logger with correlation ID if present.
func FromContext(ctx context.Context) *zap.Logger {
	if ctx == nil {
		return L()
	}

	// Check for logger in context
	if l, ok := ctx.Value(loggerKey).(*zap.Logger); ok {
		return l
	}

	// Check for correlation ID and add to global logger
	if id, ok := ctx.Value(correlationIDKey).(string); ok {
		return L().With(zap.String("correlation_id", id))
	}

	return L()
}

// ToContext stores the logger in the context.
func ToContext(ctx context.Context, l *zap.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, l)
}

// WithCorrelationID adds a correlation ID to the context and returns a new context
// with a logger that includes the correlation ID.
func WithCorrelationID(ctx context.Context, correlationID string) context.Context {
	ctx = context.WithValue(ctx, correlationIDKey, correlationID)
	l := L().With(zap.String("correlation_id", correlationID))
	return ToContext(ctx, l)
}

// GetCorrelationID retrieves the correlation ID from context.
func GetCorrelationID(ctx context.Context) string {
	if id, ok := ctx.Value(correlationIDKey).(string); ok {
		return id
	}
	return ""
}

// NewRequestLogger creates a logger for HTTP request handling.
func NewRequestLogger(ctx context.Context, method, path, requestID string) *zap.Logger {
	return FromContext(ctx).With(
		zap.String("method", method),
		zap.String("path", path),
		zap.String("request_id", requestID),
	)
}

// MustInit initializes the logger or panics on error.
func MustInit(cfg Config) {
	if err := Init(cfg); err != nil {
		panic("failed to initialize logger: " + err.Error())
	}
}

// InitFromEnv initializes logger from environment variables.
// Supported env vars:
//   - LOG_LEVEL: debug, info, warn, error (default: info)
//   - LOG_FORMAT: json, console (default: json)
//   - DEV_MODE: true/false (default: false)
func InitFromEnv() error {
	level := os.Getenv("LOG_LEVEL")
	if level == "" {
		level = "info"
	}

	dev := os.Getenv("DEV_MODE") == "true"

	return Init(Config{
		Level:       level,
		Development: dev,
	})
}

// Debug logs a debug message.
func Debug(msg string, fields ...zap.Field) {
	L().Debug(msg, fields...)
}

// Info logs an info message.
func Info(msg string, fields ...zap.Field) {
	L().Info(msg, fields...)
}

// Warn logs a warning message.
func Warn(msg string, fields ...zap.Field) {
	L().Warn(msg, fields...)
}

// Error logs an error message.
func Error(msg string, fields ...zap.Field) {
	L().Error(msg, fields...)
}

// Fatal logs a fatal message and exits.
func Fatal(msg string, fields ...zap.Field) {
	L().Fatal(msg, fields...)
}

// Common field constructors for convenience.
var (
	String   = zap.String
	Int      = zap.Int
	Int64    = zap.Int64
	Float64  = zap.Float64
	Bool     = zap.Bool
	Err      = zap.Error
	Duration = zap.Duration
	Any      = zap.Any
	Time     = zap.Time
)
