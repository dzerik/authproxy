package audit

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/internal/domain"
	"github.com/your-org/authz-service/pkg/logger"
)

// Exporter defines the interface for audit event exporters.
type Exporter interface {
	// Export exports an audit event.
	Export(ctx context.Context, event *domain.AuditEvent) error

	// Name returns the exporter name.
	Name() string

	// Close closes the exporter.
	Close() error
}

// Service provides audit logging capabilities.
type Service struct {
	exporters     []Exporter
	enabledEvents map[domain.AuditEventType]bool
	enrichment    config.EnrichConfig
	enabled       bool
	mu            sync.RWMutex
}

// NewService creates a new audit service.
func NewService(cfg config.AuditConfig) *Service {
	s := &Service{
		enabledEvents: make(map[domain.AuditEventType]bool),
		enrichment:    cfg.Enrichment,
		enabled:       cfg.Enabled,
	}

	// Configure enabled events
	for _, event := range cfg.Events {
		s.enabledEvents[domain.AuditEventType(event)] = true
	}

	// Add exporters
	if cfg.Export.Stdout.Enabled {
		s.exporters = append(s.exporters, NewStdoutExporter(cfg.Export.Stdout))
	}

	// TODO: Add OTLP exporter when enabled
	// if cfg.Export.OTLP.Enabled {
	//     s.exporters = append(s.exporters, NewOTLPExporter(cfg.Export.OTLP))
	// }

	return s
}

// Start initializes the audit service.
func (s *Service) Start(ctx context.Context) error {
	logger.Info("audit service started",
		logger.Bool("enabled", s.enabled),
		logger.Int("exporters", len(s.exporters)),
	)
	return nil
}

// Stop shuts down the audit service.
func (s *Service) Stop() error {
	for _, exp := range s.exporters {
		if err := exp.Close(); err != nil {
			logger.Warn("error closing exporter",
				logger.String("exporter", exp.Name()),
				logger.Err(err),
			)
		}
	}
	return nil
}

// Log logs an audit event.
func (s *Service) Log(ctx context.Context, event *domain.AuditEvent) {
	if !s.enabled {
		return
	}

	// Check if event type is enabled
	if !s.enabledEvents[event.EventType] {
		return
	}

	// Set event ID if not set
	if event.EventID == "" {
		event.EventID = uuid.New().String()
	}

	// Set timestamp if not set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Export to all exporters
	for _, exp := range s.exporters {
		if err := exp.Export(ctx, event); err != nil {
			logger.Warn("failed to export audit event",
				logger.String("exporter", exp.Name()),
				logger.Err(err),
			)
		}
	}
}

// LogAuthzDecision logs an authorization decision event.
func (s *Service) LogAuthzDecision(ctx context.Context, input *domain.PolicyInput, decision *domain.Decision, duration time.Duration) {
	if !s.enabled {
		return
	}

	event := domain.NewAuditEvent(domain.AuditEventAuthzDecision)
	event.Action = input.Request.Method + " " + input.Request.Path

	// Set subject info
	if input.Token != nil {
		event.Subject = domain.AuditSubject{
			ID:     input.Token.Subject,
			Type:   "user",
			Roles:  input.Token.Roles,
			Issuer: input.Token.Issuer,
		}
	} else {
		event.Subject = domain.AuditSubject{
			Type: "anonymous",
		}
	}

	// Set resource info
	event.Resource = domain.AuditResource{
		Type:    "api",
		Path:    input.Request.Path,
		Service: input.Destination.Service,
	}

	// Set decision info
	event.Decision = domain.AuditDecision{
		Allowed:       decision.Allowed,
		Reasons:       decision.Reasons,
		PolicyVersion: decision.PolicyVersion,
		Cached:        decision.Cached,
		DurationMs:    float64(duration.Microseconds()) / 1000.0,
	}

	// Set request info
	event.Request = domain.AuditRequest{
		ID:        input.Context.RequestID,
		TraceID:   input.Context.TraceID,
		SourceIP:  input.Source.Address,
	}

	s.Log(ctx, event)
}

// LogTokenValidation logs a token validation event.
func (s *Service) LogTokenValidation(ctx context.Context, token *domain.TokenInfo, success bool, err error) {
	if !s.enabled {
		return
	}

	event := domain.NewAuditEvent(domain.AuditEventTokenValidation)

	if token != nil {
		event.Subject = domain.AuditSubject{
			ID:     token.Subject,
			Type:   "user",
			Issuer: token.Issuer,
		}
	}

	event.Decision = domain.AuditDecision{
		Allowed: success,
	}

	if err != nil {
		event.Decision.Reasons = []string{err.Error()}
	}

	s.Log(ctx, event)
}

// StdoutExporter exports audit events to stdout.
type StdoutExporter struct {
	format string
}

// NewStdoutExporter creates a new stdout exporter.
func NewStdoutExporter(cfg config.StdoutExportConfig) *StdoutExporter {
	return &StdoutExporter{
		format: cfg.Format,
	}
}

// Export exports an event to stdout.
func (e *StdoutExporter) Export(ctx context.Context, event *domain.AuditEvent) error {
	if e.format == "json" {
		data, err := json.Marshal(event)
		if err != nil {
			return err
		}
		logger.Info("audit",
			logger.String("event_type", string(event.EventType)),
			logger.Any("data", json.RawMessage(data)),
		)
	} else {
		logger.Info("audit",
			logger.String("event_type", string(event.EventType)),
			logger.String("event_id", event.EventID),
			logger.String("subject", event.Subject.ID),
			logger.String("action", event.Action),
			logger.Bool("allowed", event.Decision.Allowed),
		)
	}
	return nil
}

// Name returns the exporter name.
func (e *StdoutExporter) Name() string {
	return "stdout"
}

// Close closes the exporter.
func (e *StdoutExporter) Close() error {
	return nil
}
