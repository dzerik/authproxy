package logger

import (
	"context"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger is the global logger instance.
var defaultLogger *zap.Logger

// atomicLevel allows dynamic log level changes at runtime.
var atomicLevel zap.AtomicLevel

// ctxKey is the context key for logger.
type ctxKey struct{}

// correlationIDKey is the context key for correlation ID.
type correlationIDKey struct{}

// CorrelationIDHeader is the standard header name for correlation ID.
const CorrelationIDHeader = "X-Correlation-ID"

// Config holds logger configuration.
type Config struct {
	Level      string `mapstructure:"level" jsonschema:"description=Log level. Controls which messages are logged.,enum=debug,enum=info,enum=warn,enum=error,default=info"`
	Format     string `mapstructure:"format" jsonschema:"description=Log output format.,enum=json,enum=console,default=json"`
	Output     string `mapstructure:"output" jsonschema:"description=Log output destination. Can be 'stdout'\\, 'stderr'\\, or a file path.,default=stdout"`
	AddCaller  bool   `mapstructure:"add_caller" jsonschema:"description=Include caller information (file:line) in log entries.,default=true"`
	Stacktrace bool   `mapstructure:"stacktrace" jsonschema:"description=Include stack trace for error level logs.,default=false"`
}

// DefaultConfig returns default logger configuration.
func DefaultConfig() Config {
	return Config{
		Level:      "info",
		Format:     "json",
		Output:     "stdout",
		AddCaller:  true,
		Stacktrace: false,
	}
}

// Init initializes the global logger.
func Init(cfg Config) error {
	level, err := zapcore.ParseLevel(cfg.Level)
	if err != nil {
		level = zapcore.InfoLevel
	}

	// Initialize atomic level for runtime changes
	atomicLevel = zap.NewAtomicLevelAt(level)

	var encoder zapcore.Encoder
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder

	if cfg.Format == "console" {
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	}

	var writer zapcore.WriteSyncer
	switch cfg.Output {
	case "stdout":
		writer = zapcore.AddSync(os.Stdout)
	case "stderr":
		writer = zapcore.AddSync(os.Stderr)
	default:
		file, err := os.OpenFile(cfg.Output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		writer = zapcore.AddSync(file)
	}

	// Use atomicLevel instead of static level
	core := zapcore.NewCore(encoder, writer, atomicLevel)

	opts := []zap.Option{}
	if cfg.AddCaller {
		opts = append(opts, zap.AddCaller(), zap.AddCallerSkip(1))
	}
	if cfg.Stacktrace {
		opts = append(opts, zap.AddStacktrace(zapcore.ErrorLevel))
	}

	defaultLogger = zap.New(core, opts...)
	return nil
}

// GetLevel returns the current log level as a string.
func GetLevel() string {
	return atomicLevel.Level().String()
}

// SetLevel changes the log level at runtime.
// Valid levels: debug, info, warn, error.
func SetLevel(level string) error {
	lvl, err := zapcore.ParseLevel(level)
	if err != nil {
		return err
	}
	atomicLevel.SetLevel(lvl)
	return nil
}

// L returns the default logger.
func L() *zap.Logger {
	if defaultLogger == nil {
		defaultLogger, _ = zap.NewProduction()
	}
	return defaultLogger
}

// S returns the default sugared logger.
func S() *zap.SugaredLogger {
	return L().Sugar()
}

// WithContext returns a logger from context or the default logger.
func WithContext(ctx context.Context) *zap.Logger {
	if ctx == nil {
		return L()
	}
	if l, ok := ctx.Value(ctxKey{}).(*zap.Logger); ok {
		return l
	}
	return L()
}

// ToContext adds a logger to context.
func ToContext(ctx context.Context, l *zap.Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, l)
}

// WithCorrelationID adds a correlation ID to the context.
func WithCorrelationID(ctx context.Context, correlationID string) context.Context {
	return context.WithValue(ctx, correlationIDKey{}, correlationID)
}

// CorrelationIDFromContext retrieves the correlation ID from context.
func CorrelationIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if id, ok := ctx.Value(correlationIDKey{}).(string); ok {
		return id
	}
	return ""
}

// WithCorrelationIDLogger creates a context with both correlation ID and a logger
// that includes the correlation ID field.
func WithCorrelationIDLogger(ctx context.Context, correlationID string) context.Context {
	ctx = WithCorrelationID(ctx, correlationID)
	l := L().With(zap.String("correlation_id", correlationID))
	return ToContext(ctx, l)
}

// With creates a child logger with the given fields.
func With(fields ...zap.Field) *zap.Logger {
	return L().With(fields...)
}

// Info logs at info level.
func Info(msg string, fields ...zap.Field) {
	L().Info(msg, fields...)
}

// Debug logs at debug level.
func Debug(msg string, fields ...zap.Field) {
	L().Debug(msg, fields...)
}

// Warn logs at warn level.
func Warn(msg string, fields ...zap.Field) {
	L().Warn(msg, fields...)
}

// Error logs at error level.
func Error(msg string, fields ...zap.Field) {
	L().Error(msg, fields...)
}

// Fatal logs at fatal level and exits.
func Fatal(msg string, fields ...zap.Field) {
	L().Fatal(msg, fields...)
}

// Sync flushes any buffered log entries.
func Sync() error {
	if defaultLogger != nil {
		return defaultLogger.Sync()
	}
	return nil
}

// Logger is a type alias for *zap.Logger for convenience.
type Logger = *zap.Logger

// Field aliases for convenience
var (
	String   = zap.String
	Strings  = zap.Strings
	Int      = zap.Int
	Int64    = zap.Int64
	Float64  = zap.Float64
	Bool     = zap.Bool
	Duration = zap.Duration
	Time     = zap.Time
	Any      = zap.Any
	Err = zap.Error
)
