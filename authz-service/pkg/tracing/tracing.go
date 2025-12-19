// Package tracing provides OpenTelemetry distributed tracing support.
package tracing

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Config holds tracing configuration.
type Config struct {
	// Enabled enables distributed tracing
	Enabled bool `mapstructure:"enabled" jsonschema:"description=Enable OpenTelemetry distributed tracing.,default=false"`
	// Endpoint is the OTLP collector endpoint (e.g., localhost:4317)
	Endpoint string `mapstructure:"endpoint" jsonschema:"description=OTLP gRPC collector endpoint.,example=localhost:4317"`
	// Insecure disables TLS for collector connection
	Insecure bool `mapstructure:"insecure" jsonschema:"description=Use insecure (non-TLS) connection to collector.,default=true"`
	// ServiceName is the service name in traces
	ServiceName string `mapstructure:"service_name" jsonschema:"description=Service name for traces.,default=authz-service"`
	// ServiceVersion is the service version in traces
	ServiceVersion string `mapstructure:"service_version" jsonschema:"description=Service version for traces."`
	// Environment is the deployment environment
	Environment string `mapstructure:"environment" jsonschema:"description=Deployment environment (e.g. production\\, staging).,default=development"`
	// SampleRate is the trace sampling rate (0.0-1.0)
	SampleRate float64 `mapstructure:"sample_rate" jsonschema:"description=Trace sampling rate (0.0=none\\, 1.0=all).,default=1.0"`
	// BatchTimeout is the maximum time before exporting a batch
	BatchTimeout time.Duration `mapstructure:"batch_timeout" jsonschema:"description=Maximum time before exporting a trace batch.,default=5s"`
	// ExportTimeout is the timeout for export operations
	ExportTimeout time.Duration `mapstructure:"export_timeout" jsonschema:"description=Timeout for trace export operations.,default=30s"`
}

// Provider wraps the OpenTelemetry TracerProvider.
type Provider struct {
	tp      *sdktrace.TracerProvider
	tracer  trace.Tracer
	enabled bool
}

// NewProvider creates a new tracing provider.
func NewProvider(ctx context.Context, cfg Config) (*Provider, error) {
	if !cfg.Enabled {
		return &Provider{enabled: false}, nil
	}

	// Set defaults
	if cfg.ServiceName == "" {
		cfg.ServiceName = "authz-service"
	}
	if cfg.SampleRate == 0 {
		cfg.SampleRate = 1.0
	}
	if cfg.BatchTimeout == 0 {
		cfg.BatchTimeout = 5 * time.Second
	}
	if cfg.ExportTimeout == 0 {
		cfg.ExportTimeout = 30 * time.Second
	}

	// Create resource with service information
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
			semconv.DeploymentEnvironment(cfg.Environment),
		),
	)
	if err != nil {
		return nil, err
	}

	// Create OTLP exporter
	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(cfg.Endpoint),
		otlptracegrpc.WithTimeout(cfg.ExportTimeout),
	}
	if cfg.Insecure {
		opts = append(opts, otlptracegrpc.WithDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())))
		opts = append(opts, otlptracegrpc.WithInsecure())
	}

	exporter, err := otlptracegrpc.New(ctx, opts...)
	if err != nil {
		return nil, err
	}

	// Create sampler
	var sampler sdktrace.Sampler
	if cfg.SampleRate >= 1.0 {
		sampler = sdktrace.AlwaysSample()
	} else if cfg.SampleRate <= 0 {
		sampler = sdktrace.NeverSample()
	} else {
		sampler = sdktrace.TraceIDRatioBased(cfg.SampleRate)
	}

	// Create TracerProvider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter,
			sdktrace.WithBatchTimeout(cfg.BatchTimeout),
		),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)

	// Set global TracerProvider and Propagator
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return &Provider{
		tp:      tp,
		tracer:  tp.Tracer(cfg.ServiceName),
		enabled: true,
	}, nil
}

// Shutdown gracefully shuts down the tracing provider.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p.tp == nil {
		return nil
	}
	return p.tp.Shutdown(ctx)
}

// Tracer returns the tracer instance.
func (p *Provider) Tracer() trace.Tracer {
	if !p.enabled {
		return trace.NewNoopTracerProvider().Tracer("")
	}
	return p.tracer
}

// Enabled returns whether tracing is enabled.
func (p *Provider) Enabled() bool {
	return p.enabled
}

// StartSpan starts a new span with the given name.
func (p *Provider) StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	if !p.enabled {
		return ctx, trace.SpanFromContext(ctx)
	}
	return p.tracer.Start(ctx, name, opts...)
}

// Common span attribute keys.
const (
	// Authorization attributes
	AttrAuthzAllowed    = "authz.allowed"
	AttrAuthzCached     = "authz.cached"
	AttrAuthzReason     = "authz.reason"
	AttrAuthzPolicyName = "authz.policy_name"
	AttrAuthzEngine     = "authz.engine"

	// Request attributes
	AttrHTTPMethod = "http.method"
	AttrHTTPPath   = "http.path"
	AttrHTTPStatus = "http.status_code"
	AttrUserID     = "user.id"
	AttrUserRoles  = "user.roles"

	// JWT attributes
	AttrJWTIssuer  = "jwt.issuer"
	AttrJWTSubject = "jwt.subject"
	AttrJWTValid   = "jwt.valid"

	// Cache attributes
	AttrCacheHit   = "cache.hit"
	AttrCacheLayer = "cache.layer"
)

// SpanAttributes is a helper to build span attributes.
type SpanAttributes struct {
	attrs []attribute.KeyValue
}

// NewSpanAttributes creates a new SpanAttributes builder.
func NewSpanAttributes() *SpanAttributes {
	return &SpanAttributes{}
}

// Add adds a key-value attribute.
func (a *SpanAttributes) Add(key string, value interface{}) *SpanAttributes {
	switch v := value.(type) {
	case string:
		a.attrs = append(a.attrs, attribute.String(key, v))
	case int:
		a.attrs = append(a.attrs, attribute.Int(key, v))
	case int64:
		a.attrs = append(a.attrs, attribute.Int64(key, v))
	case float64:
		a.attrs = append(a.attrs, attribute.Float64(key, v))
	case bool:
		a.attrs = append(a.attrs, attribute.Bool(key, v))
	case []string:
		a.attrs = append(a.attrs, attribute.StringSlice(key, v))
	}
	return a
}

// Build returns the attribute slice.
func (a *SpanAttributes) Build() []attribute.KeyValue {
	return a.attrs
}

// SetSpanAttributes sets attributes on a span.
func SetSpanAttributes(span trace.Span, attrs *SpanAttributes) {
	if span == nil || attrs == nil {
		return
	}
	span.SetAttributes(attrs.Build()...)
}

// RecordError records an error on the span.
func RecordError(span trace.Span, err error) {
	if span == nil || err == nil {
		return
	}
	span.RecordError(err)
}

// SpanFromContext returns the current span from context.
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// ContextWithSpan returns a new context with the span.
func ContextWithSpan(ctx context.Context, span trace.Span) context.Context {
	return trace.ContextWithSpan(ctx, span)
}
