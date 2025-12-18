package audit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/internal/domain"
)

// =============================================================================
// Service Tests
// =============================================================================

func TestNewService(t *testing.T) {
	cfg := config.AuditConfig{
		Enabled: true,
		Events:  []string{"AUTHZ_DECISION", "TOKEN_VALIDATION"},
		Export: config.ExportConfig{
			Stdout: config.StdoutExportConfig{
				Enabled: true,
				Format:  "json",
			},
		},
	}

	svc := NewService(cfg)

	require.NotNil(t, svc)
	assert.True(t, svc.enabled)
	assert.Len(t, svc.enabledEvents, 2)
	assert.Len(t, svc.exporters, 1)
}

func TestNewService_Disabled(t *testing.T) {
	cfg := config.AuditConfig{
		Enabled: false,
	}

	svc := NewService(cfg)

	require.NotNil(t, svc)
	assert.False(t, svc.enabled)
}

func TestNewService_NoExporters(t *testing.T) {
	cfg := config.AuditConfig{
		Enabled: true,
		Events:  []string{"AUTHZ_DECISION"},
	}

	svc := NewService(cfg)

	require.NotNil(t, svc)
	assert.Empty(t, svc.exporters)
}

func TestService_Start(t *testing.T) {
	svc := NewService(config.AuditConfig{Enabled: true})

	err := svc.Start(context.Background())

	assert.NoError(t, err)
}

func TestService_Stop(t *testing.T) {
	cfg := config.AuditConfig{
		Enabled: true,
		Export: config.ExportConfig{
			Stdout: config.StdoutExportConfig{
				Enabled: true,
				Format:  "json",
			},
		},
	}
	svc := NewService(cfg)

	err := svc.Stop()

	assert.NoError(t, err)
}

func TestService_Log_Disabled(t *testing.T) {
	svc := NewService(config.AuditConfig{Enabled: false})

	// Should not panic when disabled
	svc.Log(context.Background(), domain.NewAuditEvent(domain.AuditEventAuthzDecision))
}

func TestService_Log_EventTypeNotEnabled(t *testing.T) {
	cfg := config.AuditConfig{
		Enabled: true,
		Events:  []string{"TOKEN_VALIDATION"}, // Only TOKEN_VALIDATION enabled
	}
	svc := NewService(cfg)

	// Should not log AUTHZ_DECISION events
	event := domain.NewAuditEvent(domain.AuditEventAuthzDecision)
	svc.Log(context.Background(), event)
	// No panic = success
}

func TestService_Log_SetsEventID(t *testing.T) {
	cfg := config.AuditConfig{
		Enabled: true,
		Events:  []string{"AUTHZ_DECISION"},
	}
	svc := NewService(cfg)

	event := domain.NewAuditEvent(domain.AuditEventAuthzDecision)
	event.EventID = "" // Ensure it's empty

	svc.Log(context.Background(), event)

	assert.NotEmpty(t, event.EventID)
}

func TestService_Log_SetsTimestamp(t *testing.T) {
	cfg := config.AuditConfig{
		Enabled: true,
		Events:  []string{"AUTHZ_DECISION"},
	}
	svc := NewService(cfg)

	event := domain.NewAuditEvent(domain.AuditEventAuthzDecision)
	event.Timestamp = time.Time{} // Zero timestamp

	svc.Log(context.Background(), event)

	assert.False(t, event.Timestamp.IsZero())
}

func TestService_LogAuthzDecision_Disabled(t *testing.T) {
	svc := NewService(config.AuditConfig{Enabled: false})

	input := &domain.PolicyInput{
		Request: domain.RequestInfo{
			Method: "GET",
			Path:   "/api/test",
		},
	}
	decision := domain.Allow()

	// Should not panic
	svc.LogAuthzDecision(context.Background(), input, decision, time.Millisecond)
}

func TestService_LogAuthzDecision_WithToken(t *testing.T) {
	cfg := config.AuditConfig{
		Enabled: true,
		Events:  []string{"AUTHZ_DECISION"},
	}
	svc := NewService(cfg)

	input := &domain.PolicyInput{
		Request: domain.RequestInfo{
			Method: "POST",
			Path:   "/api/users",
		},
		Token: &domain.TokenInfo{
			Subject: "user123",
			Issuer:  "https://issuer.example.com",
			Roles:   []string{"admin"},
		},
		Destination: domain.DestinationInfo{
			Service: "user-service",
		},
		Context: domain.ContextInfo{
			RequestID: "req-123",
			TraceID:   "trace-456",
		},
		Source: domain.SourceInfo{
			Address: "192.168.1.1",
		},
	}
	decision := domain.Allow("rule matched")

	// Should not panic
	svc.LogAuthzDecision(context.Background(), input, decision, 5*time.Millisecond)
}

func TestService_LogAuthzDecision_Anonymous(t *testing.T) {
	cfg := config.AuditConfig{
		Enabled: true,
		Events:  []string{"AUTHZ_DECISION"},
	}
	svc := NewService(cfg)

	input := &domain.PolicyInput{
		Request: domain.RequestInfo{
			Method: "GET",
			Path:   "/health",
		},
		// No token
	}
	decision := domain.Allow()

	// Should not panic
	svc.LogAuthzDecision(context.Background(), input, decision, time.Millisecond)
}

func TestService_LogTokenValidation_Disabled(t *testing.T) {
	svc := NewService(config.AuditConfig{Enabled: false})

	token := &domain.TokenInfo{Subject: "user123"}

	// Should not panic
	svc.LogTokenValidation(context.Background(), token, true, nil)
}

func TestService_LogTokenValidation_Success(t *testing.T) {
	cfg := config.AuditConfig{
		Enabled: true,
		Events:  []string{"TOKEN_VALIDATION"},
	}
	svc := NewService(cfg)

	token := &domain.TokenInfo{
		Subject: "user123",
		Issuer:  "https://issuer.example.com",
	}

	// Should not panic
	svc.LogTokenValidation(context.Background(), token, true, nil)
}

func TestService_LogTokenValidation_Failure(t *testing.T) {
	cfg := config.AuditConfig{
		Enabled: true,
		Events:  []string{"TOKEN_VALIDATION"},
	}
	svc := NewService(cfg)

	token := &domain.TokenInfo{
		Subject: "user123",
	}

	// Should not panic
	svc.LogTokenValidation(context.Background(), token, false, assert.AnError)
}

func TestService_LogTokenValidation_NilToken(t *testing.T) {
	cfg := config.AuditConfig{
		Enabled: true,
		Events:  []string{"TOKEN_VALIDATION"},
	}
	svc := NewService(cfg)

	// Should not panic with nil token
	svc.LogTokenValidation(context.Background(), nil, false, assert.AnError)
}

// =============================================================================
// StdoutExporter Tests
// =============================================================================

func TestNewStdoutExporter(t *testing.T) {
	cfg := config.StdoutExportConfig{
		Enabled: true,
		Format:  "json",
	}

	exp := NewStdoutExporter(cfg)

	require.NotNil(t, exp)
	assert.Equal(t, "json", exp.format)
}

func TestStdoutExporter_Name(t *testing.T) {
	exp := NewStdoutExporter(config.StdoutExportConfig{})

	assert.Equal(t, "stdout", exp.Name())
}

func TestStdoutExporter_Close(t *testing.T) {
	exp := NewStdoutExporter(config.StdoutExportConfig{})

	err := exp.Close()

	assert.NoError(t, err)
}

func TestStdoutExporter_Export_JSON(t *testing.T) {
	exp := NewStdoutExporter(config.StdoutExportConfig{Format: "json"})

	event := domain.NewAuditEvent(domain.AuditEventAuthzDecision)
	event.EventID = "test-id"
	event.Subject = domain.AuditSubject{ID: "user123"}

	err := exp.Export(context.Background(), event)

	assert.NoError(t, err)
}

func TestStdoutExporter_Export_Text(t *testing.T) {
	exp := NewStdoutExporter(config.StdoutExportConfig{Format: "text"})

	event := domain.NewAuditEvent(domain.AuditEventAuthzDecision)
	event.EventID = "test-id"
	event.Subject = domain.AuditSubject{ID: "user123"}
	event.Action = "GET /api/users"
	event.Decision = domain.AuditDecision{Allowed: true}

	err := exp.Export(context.Background(), event)

	assert.NoError(t, err)
}

// =============================================================================
// Mock Exporter for Testing
// =============================================================================

type mockExporter struct {
	name      string
	exported  []*domain.AuditEvent
	closeErr  error
	exportErr error
}

func (m *mockExporter) Export(ctx context.Context, event *domain.AuditEvent) error {
	if m.exportErr != nil {
		return m.exportErr
	}
	m.exported = append(m.exported, event)
	return nil
}

func (m *mockExporter) Name() string {
	return m.name
}

func (m *mockExporter) Close() error {
	return m.closeErr
}

func TestService_Log_WithMockExporter(t *testing.T) {
	cfg := config.AuditConfig{
		Enabled: true,
		Events:  []string{"AUTHZ_DECISION"},
	}
	svc := NewService(cfg)

	// Replace exporters with mock
	mock := &mockExporter{name: "mock"}
	svc.exporters = []Exporter{mock}

	event := domain.NewAuditEvent(domain.AuditEventAuthzDecision)
	svc.Log(context.Background(), event)

	require.Len(t, mock.exported, 1)
	assert.Equal(t, domain.AuditEventAuthzDecision, mock.exported[0].EventType)
}

func TestService_Log_ExporterError(t *testing.T) {
	cfg := config.AuditConfig{
		Enabled: true,
		Events:  []string{"AUTHZ_DECISION"},
	}
	svc := NewService(cfg)

	// Replace with failing mock
	mock := &mockExporter{name: "mock", exportErr: assert.AnError}
	svc.exporters = []Exporter{mock}

	event := domain.NewAuditEvent(domain.AuditEventAuthzDecision)

	// Should not panic even with error
	svc.Log(context.Background(), event)
}

func TestService_Stop_ExporterError(t *testing.T) {
	cfg := config.AuditConfig{Enabled: true}
	svc := NewService(cfg)

	// Replace with failing mock
	mock := &mockExporter{name: "mock", closeErr: assert.AnError}
	svc.exporters = []Exporter{mock}

	// Should not fail, just log warning
	err := svc.Stop()
	assert.NoError(t, err)
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkService_Log(b *testing.B) {
	cfg := config.AuditConfig{
		Enabled: true,
		Events:  []string{"AUTHZ_DECISION"},
	}
	svc := NewService(cfg)
	ctx := context.Background()

	event := domain.NewAuditEvent(domain.AuditEventAuthzDecision)
	event.EventID = "bench-event"
	event.Timestamp = time.Now()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		svc.Log(ctx, event)
	}
}

func BenchmarkService_LogAuthzDecision(b *testing.B) {
	cfg := config.AuditConfig{
		Enabled: true,
		Events:  []string{"AUTHZ_DECISION"},
	}
	svc := NewService(cfg)
	ctx := context.Background()

	input := &domain.PolicyInput{
		Request: domain.RequestInfo{Method: "GET", Path: "/api/test"},
		Token:   &domain.TokenInfo{Subject: "user123"},
	}
	decision := domain.Allow()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		svc.LogAuthzDecision(ctx, input, decision, time.Millisecond)
	}
}

func BenchmarkStdoutExporter_Export_JSON(b *testing.B) {
	exp := NewStdoutExporter(config.StdoutExportConfig{Format: "json"})
	ctx := context.Background()

	event := domain.NewAuditEvent(domain.AuditEventAuthzDecision)
	event.EventID = "bench-event"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		exp.Export(ctx, event)
	}
}
