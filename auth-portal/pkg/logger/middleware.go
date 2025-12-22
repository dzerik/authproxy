package logger

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"
)

// RequestLogger is a middleware that logs HTTP requests using zap.
// It logs the start and end of each request with timing information.
func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Get or generate request ID
		requestID := middleware.GetReqID(r.Context())
		if requestID == "" {
			requestID = generateRequestID()
		}

		// Create request-scoped logger
		ctx := WithCorrelationID(r.Context(), requestID)
		log := FromContext(ctx)

		// Wrap response writer to capture status code
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		// LOW-02 security fix: Add X-Request-ID to response headers for traceability
		ww.Header().Set("X-Request-ID", requestID)

		// Log request start
		log.Debug("request started",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("user_agent", r.UserAgent()),
		)

		// Process request
		next.ServeHTTP(ww, r.WithContext(ctx))

		// Calculate duration
		duration := time.Since(start)

		// Determine log level based on status code
		status := ww.Status()
		fields := []zap.Field{
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Int("status", status),
			zap.Duration("duration", duration),
			zap.Int("bytes", ww.BytesWritten()),
		}

		switch {
		case status >= 500:
			log.Error("request completed", fields...)
		case status >= 400:
			log.Warn("request completed", fields...)
		default:
			log.Info("request completed", fields...)
		}
	})
}

// RecoveryLogger is a middleware that recovers from panics and logs them.
func RecoveryLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log := FromContext(r.Context())
				log.Error("panic recovered",
					zap.Any("error", err),
					zap.String("method", r.Method),
					zap.String("path", r.URL.Path),
					zap.Stack("stack"),
				)

				// Return 500
				w.WriteHeader(http.StatusInternalServerError)
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// generateRequestID generates a simple request ID.
func generateRequestID() string {
	return fmt.Sprintf("%d", middleware.NextRequestID())
}

// StructuredLogger implements chi's LogFormatter interface for integration
// with chi's built-in logging middleware.
type StructuredLogger struct {
	Logger *zap.Logger
}

// NewLogEntry creates a new log entry for a request.
func (l *StructuredLogger) NewLogEntry(r *http.Request) middleware.LogEntry {
	requestID := middleware.GetReqID(r.Context())

	entry := &StructuredLogEntry{
		Logger: l.Logger.With(
			zap.String("request_id", requestID),
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("remote_addr", r.RemoteAddr),
		),
	}

	entry.Logger.Debug("request started")
	return entry
}

// StructuredLogEntry represents a single log entry for a request.
type StructuredLogEntry struct {
	Logger *zap.Logger
}

// Write logs the completion of a request.
func (e *StructuredLogEntry) Write(status, bytes int, header http.Header, elapsed time.Duration, extra interface{}) {
	fields := []zap.Field{
		zap.Int("status", status),
		zap.Int("bytes", bytes),
		zap.Duration("elapsed", elapsed),
	}

	switch {
	case status >= 500:
		e.Logger.Error("request completed", fields...)
	case status >= 400:
		e.Logger.Warn("request completed", fields...)
	default:
		e.Logger.Info("request completed", fields...)
	}
}

// Panic logs a panic that occurred during request handling.
func (e *StructuredLogEntry) Panic(v interface{}, stack []byte) {
	e.Logger.Error("panic",
		zap.Any("error", v),
		zap.ByteString("stack", stack),
	)
}

// NewStructuredLogger creates a chi-compatible logger.
func NewStructuredLogger() *StructuredLogger {
	return &StructuredLogger{Logger: L()}
}
