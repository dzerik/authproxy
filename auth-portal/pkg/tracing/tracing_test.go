package tracing

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.False(t, cfg.Enabled)
	assert.Equal(t, "auth-portal", cfg.ServiceName)
	assert.Equal(t, "dev", cfg.ServiceVersion)
	assert.Equal(t, "development", cfg.Environment)
	assert.Equal(t, "localhost:4317", cfg.Endpoint)
	assert.Equal(t, "grpc", cfg.Protocol)
	assert.True(t, cfg.Insecure)
	assert.Equal(t, 1.0, cfg.SamplingRatio)
}

func TestConfig_Struct(t *testing.T) {
	cfg := Config{
		Enabled:        true,
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Environment:    "production",
		Endpoint:       "collector.example.com:4317",
		Protocol:       "grpc",
		Insecure:       false,
		SamplingRatio:  0.5,
		Headers: map[string]string{
			"Authorization": "Bearer token",
		},
	}

	assert.True(t, cfg.Enabled)
	assert.Equal(t, "test-service", cfg.ServiceName)
	assert.Equal(t, 0.5, cfg.SamplingRatio)
	assert.Equal(t, "Bearer token", cfg.Headers["Authorization"])
}

func TestInit_Disabled(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		Enabled:     false,
		ServiceName: "test-service",
	}

	tp, err := Init(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, tp)
	assert.NotNil(t, tp.Tracer())

	// Provider should be nil for disabled tracing
	assert.Nil(t, tp.Provider())

	// Shutdown should not fail
	err = tp.Shutdown(ctx)
	assert.NoError(t, err)
}

func TestTracerProvider_Shutdown_Nil(t *testing.T) {
	tp := &TracerProvider{}
	err := tp.Shutdown(context.Background())
	assert.NoError(t, err)
}

func TestTracer(t *testing.T) {
	// Initialize with disabled config first
	_, _ = Init(context.Background(), Config{
		Enabled:     false,
		ServiceName: "test",
	})

	tracer := Tracer()
	assert.NotNil(t, tracer)
}

func TestStart(t *testing.T) {
	ctx := context.Background()

	newCtx, span := Start(ctx, "test-span")
	assert.NotNil(t, newCtx)
	assert.NotNil(t, span)

	span.End()
}

func TestSpanFromContext(t *testing.T) {
	ctx := context.Background()

	// Without span
	span := SpanFromContext(ctx)
	assert.NotNil(t, span)

	// With span
	ctx, createdSpan := Start(ctx, "test-span")
	defer createdSpan.End()

	retrievedSpan := SpanFromContext(ctx)
	assert.NotNil(t, retrievedSpan)
}

func TestAddEvent(t *testing.T) {
	ctx, span := Start(context.Background(), "test-span")
	defer span.End()

	// Should not panic
	AddEvent(ctx, "test-event", attribute.String("key", "value"))
}

func TestSetAttributes(t *testing.T) {
	ctx, span := Start(context.Background(), "test-span")
	defer span.End()

	// Should not panic
	SetAttributes(ctx, attribute.String("key", "value"), attribute.Int("count", 42))
}

func TestRecordError(t *testing.T) {
	ctx, span := Start(context.Background(), "test-span")
	defer span.End()

	// Should not panic
	err := errors.New("test error")
	RecordError(ctx, err)
}

func TestSetStatus(t *testing.T) {
	ctx, span := Start(context.Background(), "test-span")
	defer span.End()

	// Should not panic
	SetStatus(ctx, codes.Error, "something went wrong")
	SetStatus(ctx, codes.Ok, "success")
}

func TestAttributeKeys(t *testing.T) {
	// Verify attribute keys are properly defined
	assert.NotEqual(t, attribute.KeyValue{}, AttrUserID.String("test"))
	assert.NotEqual(t, attribute.KeyValue{}, AttrUserEmail.String("test@example.com"))
	assert.NotEqual(t, attribute.KeyValue{}, AttrSessionID.String("session-123"))
	assert.NotEqual(t, attribute.KeyValue{}, AttrProvider.String("keycloak"))
	assert.NotEqual(t, attribute.KeyValue{}, AttrAuthMethod.String("oidc"))
	assert.NotEqual(t, attribute.KeyValue{}, AttrServiceName.String("service"))
	assert.NotEqual(t, attribute.KeyValue{}, AttrRequestID.String("req-123"))
	assert.NotEqual(t, attribute.KeyValue{}, AttrHTTPMethod.String("GET"))
	assert.NotEqual(t, attribute.KeyValue{}, AttrHTTPPath.String("/api/test"))
	assert.NotEqual(t, attribute.KeyValue{}, AttrHTTPStatus.Int(200))
	assert.NotEqual(t, attribute.KeyValue{}, AttrErrorType.String("validation"))
	assert.NotEqual(t, attribute.KeyValue{}, AttrErrorMessage.String("error msg"))
}

func TestWithUserInfo(t *testing.T) {
	attrs := WithUserInfo("user-123", "user@example.com")

	assert.Len(t, attrs, 2)

	foundUserID := false
	foundEmail := false
	for _, attr := range attrs {
		if attr.Key == AttrUserID {
			foundUserID = true
			assert.Equal(t, "user-123", attr.Value.AsString())
		}
		if attr.Key == AttrUserEmail {
			foundEmail = true
			assert.Equal(t, "user@example.com", attr.Value.AsString())
		}
	}

	assert.True(t, foundUserID)
	assert.True(t, foundEmail)
}

func TestWithSession(t *testing.T) {
	attr := WithSession("session-456")

	assert.Equal(t, AttrSessionID, attr.Key)
	assert.Equal(t, "session-456", attr.Value.AsString())
}

func TestWithProvider(t *testing.T) {
	attr := WithProvider("keycloak")

	assert.Equal(t, AttrProvider, attr.Key)
	assert.Equal(t, "keycloak", attr.Value.AsString())
}

func TestWithRequestID(t *testing.T) {
	attr := WithRequestID("req-789")

	assert.Equal(t, AttrRequestID, attr.Key)
	assert.Equal(t, "req-789", attr.Value.AsString())
}

func BenchmarkStart(b *testing.B) {
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, span := Start(ctx, "benchmark-span")
		span.End()
	}
}

func BenchmarkSetAttributes(b *testing.B) {
	ctx, span := Start(context.Background(), "benchmark-span")
	defer span.End()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SetAttributes(ctx, attribute.String("key", "value"))
	}
}

func BenchmarkWithUserInfo(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = WithUserInfo("user-123", "user@example.com")
	}
}
