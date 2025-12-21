// Package tracing provides OpenTelemetry distributed tracing support.
package tracing

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// Config represents tracing configuration.
type Config struct {
	// Enabled enables/disables tracing.
	Enabled bool
	// ServiceName is the name of the service for tracing.
	ServiceName string
	// ServiceVersion is the version of the service.
	ServiceVersion string
	// Environment is the deployment environment (dev, staging, prod).
	Environment string
	// Endpoint is the OTLP collector endpoint.
	Endpoint string
	// Protocol is the OTLP protocol (grpc or http).
	Protocol string
	// Insecure disables TLS for the connection.
	Insecure bool
	// SamplingRatio is the sampling ratio (0.0 to 1.0).
	SamplingRatio float64
	// Headers are additional headers for the exporter.
	Headers map[string]string
}

// DefaultConfig returns a default tracing configuration.
func DefaultConfig() Config {
	return Config{
		Enabled:        false,
		ServiceName:    "auth-portal",
		ServiceVersion: "dev",
		Environment:    "development",
		Endpoint:       "localhost:4317",
		Protocol:       "grpc",
		Insecure:       true,
		SamplingRatio:  1.0,
	}
}

// TracerProvider wraps the OpenTelemetry tracer provider.
type TracerProvider struct {
	provider *sdktrace.TracerProvider
	tracer   trace.Tracer
}

var (
	globalProvider *TracerProvider
)

// Init initializes the global tracer provider.
func Init(ctx context.Context, cfg Config) (*TracerProvider, error) {
	if !cfg.Enabled {
		// Return a no-op provider
		globalProvider = &TracerProvider{
			tracer: otel.Tracer(cfg.ServiceName),
		}
		return globalProvider, nil
	}

	// Create resource with service information
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
			attribute.String("deployment.environment", cfg.Environment),
			attribute.String("service.namespace", "auth-portal"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create exporter based on protocol
	var exporter sdktrace.SpanExporter
	switch cfg.Protocol {
	case "http":
		exporter, err = createHTTPExporter(ctx, cfg)
	case "grpc":
		fallthrough
	default:
		exporter, err = createGRPCExporter(ctx, cfg)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create exporter: %w", err)
	}

	// Create sampler
	var sampler sdktrace.Sampler
	if cfg.SamplingRatio >= 1.0 {
		sampler = sdktrace.AlwaysSample()
	} else if cfg.SamplingRatio <= 0.0 {
		sampler = sdktrace.NeverSample()
	} else {
		sampler = sdktrace.TraceIDRatioBased(cfg.SamplingRatio)
	}

	// Create tracer provider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter,
			sdktrace.WithBatchTimeout(5*time.Second),
			sdktrace.WithMaxExportBatchSize(512),
		),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)

	// Set global tracer provider
	otel.SetTracerProvider(tp)

	// Set global propagator for context propagation
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	globalProvider = &TracerProvider{
		provider: tp,
		tracer:   tp.Tracer(cfg.ServiceName),
	}

	return globalProvider, nil
}

// createGRPCExporter creates an OTLP gRPC exporter.
func createGRPCExporter(ctx context.Context, cfg Config) (sdktrace.SpanExporter, error) {
	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(cfg.Endpoint),
	}

	if cfg.Insecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}

	if len(cfg.Headers) > 0 {
		opts = append(opts, otlptracegrpc.WithHeaders(cfg.Headers))
	}

	return otlptracegrpc.New(ctx, opts...)
}

// createHTTPExporter creates an OTLP HTTP exporter.
func createHTTPExporter(ctx context.Context, cfg Config) (sdktrace.SpanExporter, error) {
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(cfg.Endpoint),
	}

	if cfg.Insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}

	if len(cfg.Headers) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(cfg.Headers))
	}

	return otlptracehttp.New(ctx, opts...)
}

// Shutdown gracefully shuts down the tracer provider.
func (tp *TracerProvider) Shutdown(ctx context.Context) error {
	if tp.provider != nil {
		return tp.provider.Shutdown(ctx)
	}
	return nil
}

// Tracer returns the tracer instance.
func (tp *TracerProvider) Tracer() trace.Tracer {
	return tp.tracer
}

// Provider returns the underlying tracer provider.
func (tp *TracerProvider) Provider() *sdktrace.TracerProvider {
	return tp.provider
}

// Tracer returns the global tracer.
func Tracer() trace.Tracer {
	if globalProvider != nil {
		return globalProvider.tracer
	}
	return otel.Tracer("auth-portal")
}

// Start starts a new span with the given name.
func Start(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return Tracer().Start(ctx, name, opts...)
}

// SpanFromContext returns the current span from context.
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// AddEvent adds an event to the current span.
func AddEvent(ctx context.Context, name string, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	span.AddEvent(name, trace.WithAttributes(attrs...))
}

// SetAttributes sets attributes on the current span.
func SetAttributes(ctx context.Context, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attrs...)
}

// RecordError records an error on the current span.
func RecordError(ctx context.Context, err error, opts ...trace.EventOption) {
	span := trace.SpanFromContext(ctx)
	span.RecordError(err, opts...)
}

// SetStatus sets the status of the current span.
func SetStatus(ctx context.Context, code codes.Code, description string) {
	span := trace.SpanFromContext(ctx)
	span.SetStatus(code, description)
}

// Common attribute keys for auth-portal.
var (
	AttrUserID       = attribute.Key("user.id")
	AttrUserEmail    = attribute.Key("user.email")
	AttrSessionID    = attribute.Key("session.id")
	AttrProvider     = attribute.Key("auth.provider")
	AttrAuthMethod   = attribute.Key("auth.method")
	AttrServiceName  = attribute.Key("service.name")
	AttrRequestID    = attribute.Key("request.id")
	AttrHTTPMethod   = attribute.Key("http.method")
	AttrHTTPPath     = attribute.Key("http.path")
	AttrHTTPStatus   = attribute.Key("http.status_code")
	AttrErrorType    = attribute.Key("error.type")
	AttrErrorMessage = attribute.Key("error.message")
)

// WithUserInfo adds user information attributes to a span.
func WithUserInfo(userID, email string) []attribute.KeyValue {
	return []attribute.KeyValue{
		AttrUserID.String(userID),
		AttrUserEmail.String(email),
	}
}

// WithSession adds session information to a span.
func WithSession(sessionID string) attribute.KeyValue {
	return AttrSessionID.String(sessionID)
}

// WithProvider adds provider information to a span.
func WithProvider(provider string) attribute.KeyValue {
	return AttrProvider.String(provider)
}

// WithRequestID adds request ID to a span.
func WithRequestID(requestID string) attribute.KeyValue {
	return AttrRequestID.String(requestID)
}
