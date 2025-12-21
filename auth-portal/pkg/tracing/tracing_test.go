package tracing

import (
	"context"
	"errors"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Enabled {
		t.Error("Enabled should be false by default")
	}
	if cfg.ServiceName != "auth-portal" {
		t.Errorf("ServiceName = %s, want auth-portal", cfg.ServiceName)
	}
	if cfg.ServiceVersion != "dev" {
		t.Errorf("ServiceVersion = %s, want dev", cfg.ServiceVersion)
	}
	if cfg.Environment != "development" {
		t.Errorf("Environment = %s, want development", cfg.Environment)
	}
	if cfg.Endpoint != "localhost:4317" {
		t.Errorf("Endpoint = %s, want localhost:4317", cfg.Endpoint)
	}
	if cfg.Protocol != "grpc" {
		t.Errorf("Protocol = %s, want grpc", cfg.Protocol)
	}
	if !cfg.Insecure {
		t.Error("Insecure should be true by default")
	}
	if cfg.SamplingRatio != 1.0 {
		t.Errorf("SamplingRatio = %f, want 1.0", cfg.SamplingRatio)
	}
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

	if !cfg.Enabled {
		t.Error("Enabled should be true")
	}
	if cfg.ServiceName != "test-service" {
		t.Errorf("ServiceName = %s", cfg.ServiceName)
	}
	if cfg.SamplingRatio != 0.5 {
		t.Errorf("SamplingRatio = %f", cfg.SamplingRatio)
	}
	if cfg.Headers["Authorization"] != "Bearer token" {
		t.Error("Headers should contain Authorization")
	}
}

func TestInit_Disabled(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		Enabled:     false,
		ServiceName: "test-service",
	}

	tp, err := Init(ctx, cfg)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	if tp == nil {
		t.Fatal("Init returned nil TracerProvider")
	}

	if tp.Tracer() == nil {
		t.Error("Tracer should not be nil")
	}

	// Provider should be nil for disabled tracing
	if tp.Provider() != nil {
		t.Error("Provider should be nil when tracing is disabled")
	}

	// Shutdown should not fail
	err = tp.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown failed: %v", err)
	}
}

func TestTracerProvider_Shutdown_Nil(t *testing.T) {
	tp := &TracerProvider{}
	err := tp.Shutdown(context.Background())
	if err != nil {
		t.Errorf("Shutdown with nil provider should not fail: %v", err)
	}
}

func TestTracer(t *testing.T) {
	// Initialize with disabled config first
	_, _ = Init(context.Background(), Config{
		Enabled:     false,
		ServiceName: "test",
	})

	tracer := Tracer()
	if tracer == nil {
		t.Error("Tracer should not return nil")
	}
}

func TestStart(t *testing.T) {
	ctx := context.Background()

	newCtx, span := Start(ctx, "test-span")
	if newCtx == nil {
		t.Error("Start should return non-nil context")
	}
	if span == nil {
		t.Error("Start should return non-nil span")
	}

	span.End()
}

func TestSpanFromContext(t *testing.T) {
	ctx := context.Background()

	// Without span
	span := SpanFromContext(ctx)
	if span == nil {
		t.Error("SpanFromContext should not return nil")
	}

	// With span
	ctx, createdSpan := Start(ctx, "test-span")
	defer createdSpan.End()

	retrievedSpan := SpanFromContext(ctx)
	if retrievedSpan == nil {
		t.Error("SpanFromContext should return the span")
	}
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
	if AttrUserID.String("test") == (attribute.KeyValue{}) {
		t.Error("AttrUserID should create valid attribute")
	}
	if AttrUserEmail.String("test@example.com") == (attribute.KeyValue{}) {
		t.Error("AttrUserEmail should create valid attribute")
	}
	if AttrSessionID.String("session-123") == (attribute.KeyValue{}) {
		t.Error("AttrSessionID should create valid attribute")
	}
	if AttrProvider.String("keycloak") == (attribute.KeyValue{}) {
		t.Error("AttrProvider should create valid attribute")
	}
	if AttrAuthMethod.String("oidc") == (attribute.KeyValue{}) {
		t.Error("AttrAuthMethod should create valid attribute")
	}
	if AttrServiceName.String("service") == (attribute.KeyValue{}) {
		t.Error("AttrServiceName should create valid attribute")
	}
	if AttrRequestID.String("req-123") == (attribute.KeyValue{}) {
		t.Error("AttrRequestID should create valid attribute")
	}
	if AttrHTTPMethod.String("GET") == (attribute.KeyValue{}) {
		t.Error("AttrHTTPMethod should create valid attribute")
	}
	if AttrHTTPPath.String("/api/test") == (attribute.KeyValue{}) {
		t.Error("AttrHTTPPath should create valid attribute")
	}
	if AttrHTTPStatus.Int(200) == (attribute.KeyValue{}) {
		t.Error("AttrHTTPStatus should create valid attribute")
	}
	if AttrErrorType.String("validation") == (attribute.KeyValue{}) {
		t.Error("AttrErrorType should create valid attribute")
	}
	if AttrErrorMessage.String("error msg") == (attribute.KeyValue{}) {
		t.Error("AttrErrorMessage should create valid attribute")
	}
}

func TestWithUserInfo(t *testing.T) {
	attrs := WithUserInfo("user-123", "user@example.com")

	if len(attrs) != 2 {
		t.Errorf("WithUserInfo should return 2 attributes, got %d", len(attrs))
	}

	foundUserID := false
	foundEmail := false
	for _, attr := range attrs {
		if attr.Key == AttrUserID {
			foundUserID = true
			if attr.Value.AsString() != "user-123" {
				t.Errorf("User ID = %s, want user-123", attr.Value.AsString())
			}
		}
		if attr.Key == AttrUserEmail {
			foundEmail = true
			if attr.Value.AsString() != "user@example.com" {
				t.Errorf("Email = %s, want user@example.com", attr.Value.AsString())
			}
		}
	}

	if !foundUserID {
		t.Error("WithUserInfo should include user ID")
	}
	if !foundEmail {
		t.Error("WithUserInfo should include email")
	}
}

func TestWithSession(t *testing.T) {
	attr := WithSession("session-456")

	if attr.Key != AttrSessionID {
		t.Errorf("Key = %s, want session.id", attr.Key)
	}
	if attr.Value.AsString() != "session-456" {
		t.Errorf("Value = %s, want session-456", attr.Value.AsString())
	}
}

func TestWithProvider(t *testing.T) {
	attr := WithProvider("keycloak")

	if attr.Key != AttrProvider {
		t.Errorf("Key = %s, want auth.provider", attr.Key)
	}
	if attr.Value.AsString() != "keycloak" {
		t.Errorf("Value = %s, want keycloak", attr.Value.AsString())
	}
}

func TestWithRequestID(t *testing.T) {
	attr := WithRequestID("req-789")

	if attr.Key != AttrRequestID {
		t.Errorf("Key = %s, want request.id", attr.Key)
	}
	if attr.Value.AsString() != "req-789" {
		t.Errorf("Value = %s, want req-789", attr.Value.AsString())
	}
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
