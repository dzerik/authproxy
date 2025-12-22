package security

import (
	"testing"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/stretchr/testify/assert"
)

func TestChecker_Check_DevMode(t *testing.T) {
	cfg := &config.Config{
		DevMode: config.DevModeConfig{
			Enabled: true,
		},
	}

	checker := NewChecker(cfg)
	warnings := checker.Check()

	var found bool
	for _, w := range warnings {
		if w.Code == "SEC-001" {
			found = true
			assert.Equal(t, SeverityCritical, w.Severity, "SEC-001 expected severity critical")
			break
		}
	}

	assert.True(t, found, "expected SEC-001 warning for dev mode enabled")
}

func TestChecker_Check_InsecureCookie(t *testing.T) {
	cfg := &config.Config{
		Session: config.SessionConfig{
			Secure: false,
		},
		DevMode: config.DevModeConfig{
			Enabled: false,
		},
	}

	checker := NewChecker(cfg)
	warnings := checker.Check()

	var found bool
	for _, w := range warnings {
		if w.Code == "SEC-002" {
			found = true
			assert.Equal(t, SeverityHigh, w.Severity, "SEC-002 expected severity high")
			break
		}
	}

	assert.True(t, found, "expected SEC-002 warning for insecure cookie")
}

func TestChecker_Check_NoEncryption(t *testing.T) {
	cfg := &config.Config{
		Session: config.SessionConfig{
			Secure: true,
			Encryption: config.EncryptionConfig{
				Enabled: false,
			},
		},
	}

	checker := NewChecker(cfg)
	warnings := checker.Check()

	var found bool
	for _, w := range warnings {
		if w.Code == "SEC-003" {
			found = true
			assert.Equal(t, SeverityHigh, w.Severity, "SEC-003 expected severity high")
			break
		}
	}

	assert.True(t, found, "expected SEC-003 warning for disabled encryption")
}

func TestChecker_Check_SameSiteNoneWithoutSecure(t *testing.T) {
	cfg := &config.Config{
		Session: config.SessionConfig{
			Secure:   false,
			SameSite: "none",
			Encryption: config.EncryptionConfig{
				Enabled: true,
			},
		},
		DevMode: config.DevModeConfig{
			Enabled: true, // skip SEC-002
		},
	}

	checker := NewChecker(cfg)
	warnings := checker.Check()

	var found bool
	for _, w := range warnings {
		if w.Code == "SEC-004" {
			found = true
			assert.Equal(t, SeverityMedium, w.Severity, "SEC-004 expected severity medium")
			break
		}
	}

	assert.True(t, found, "expected SEC-004 warning for SameSite=None without Secure")
}

func TestChecker_Check_ServiceAuthorizationRemoved(t *testing.T) {
	cfg := &config.Config{
		Session: config.SessionConfig{
			Secure: true,
			Encryption: config.EncryptionConfig{
				Enabled: true,
			},
		},
		Services: []config.ServiceConfig{
			{
				Name:         "grafana",
				AuthRequired: true,
				Headers: config.HeadersConfig{
					Remove: []string{"Authorization"},
				},
			},
		},
	}

	checker := NewChecker(cfg)
	warnings := checker.Check()

	var found bool
	for _, w := range warnings {
		if w.Code == "SEC-010" {
			found = true
			assert.Equal(t, SeverityHigh, w.Severity, "SEC-010 expected severity high")
			assert.Equal(t, "grafana", w.Service, "SEC-010 expected service grafana")
			break
		}
	}

	assert.True(t, found, "expected SEC-010 warning for service removing Authorization header")
}

func TestChecker_Check_ServiceNginxExtra(t *testing.T) {
	cfg := &config.Config{
		Session: config.SessionConfig{
			Secure: true,
			Encryption: config.EncryptionConfig{
				Enabled: true,
			},
		},
		Services: []config.ServiceConfig{
			{
				Name:         "custom",
				AuthRequired: true,
				NginxExtra:   "proxy_set_header X-Custom value;",
			},
		},
	}

	checker := NewChecker(cfg)
	warnings := checker.Check()

	var found bool
	for _, w := range warnings {
		if w.Code == "SEC-011" {
			found = true
			assert.Equal(t, SeverityMedium, w.Severity, "SEC-011 expected severity medium")
			assert.Equal(t, "custom", w.Service, "SEC-011 expected service custom")
			break
		}
	}

	assert.True(t, found, "expected SEC-011 warning for service with nginx_extra")
}

func TestChecker_Check_NoWarnings(t *testing.T) {
	cfg := &config.Config{
		Session: config.SessionConfig{
			Secure:   true,
			SameSite: "lax",
			Encryption: config.EncryptionConfig{
				Enabled: true,
			},
		},
		DevMode: config.DevModeConfig{
			Enabled: false,
		},
		Server: config.ServerConfig{
			TLS: config.TLSConfig{
				Enabled: true,
			},
		},
		Services: []config.ServiceConfig{
			{
				Name:         "safe-service",
				AuthRequired: true,
				// No Authorization in Remove list
			},
		},
	}

	checker := NewChecker(cfg)
	warnings := checker.Check()

	assert.Empty(t, warnings, "expected 0 warnings for secure config")
}

func TestChecker_HasCritical(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *config.Config
		expected bool
	}{
		{
			name: "has critical - dev mode",
			cfg: &config.Config{
				DevMode: config.DevModeConfig{Enabled: true},
			},
			expected: true,
		},
		{
			name: "no critical",
			cfg: &config.Config{
				Session: config.SessionConfig{
					Secure:     true,
					Encryption: config.EncryptionConfig{Enabled: true},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := NewChecker(tt.cfg)
			assert.Equal(t, tt.expected, checker.HasCritical())
		})
	}
}

func TestCountBySeverity(t *testing.T) {
	warnings := []Warning{
		{Severity: SeverityCritical},
		{Severity: SeverityHigh},
		{Severity: SeverityHigh},
		{Severity: SeverityMedium},
		{Severity: SeverityLow},
		{Severity: SeverityLow},
		{Severity: SeverityLow},
	}

	counts := CountBySeverity(warnings)

	assert.Equal(t, 1, counts[SeverityCritical], "expected 1 critical")
	assert.Equal(t, 2, counts[SeverityHigh], "expected 2 high")
	assert.Equal(t, 1, counts[SeverityMedium], "expected 1 medium")
	assert.Equal(t, 3, counts[SeverityLow], "expected 3 low")
}

func TestFormatSummary(t *testing.T) {
	tests := []struct {
		name     string
		warnings []Warning
		expected string
	}{
		{
			name:     "no warnings",
			warnings: nil,
			expected: "No security warnings found",
		},
		{
			name:     "empty slice",
			warnings: []Warning{},
			expected: "No security warnings found",
		},
		{
			name: "mixed warnings",
			warnings: []Warning{
				{Severity: SeverityCritical},
				{Severity: SeverityHigh},
				{Severity: SeverityMedium},
				{Severity: SeverityLow},
			},
			expected: "Security warnings: 1 critical, 1 high, 1 medium, 1 low",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, FormatSummary(tt.warnings))
		})
	}
}

func TestGetBySeverity(t *testing.T) {
	warnings := []Warning{
		{Code: "W1", Severity: SeverityCritical},
		{Code: "W2", Severity: SeverityHigh},
		{Code: "W3", Severity: SeverityHigh},
		{Code: "W4", Severity: SeverityMedium},
	}

	high := GetBySeverity(warnings, SeverityHigh)
	assert.Len(t, high, 2, "expected 2 high severity warnings")

	critical := GetBySeverity(warnings, SeverityCritical)
	assert.Len(t, critical, 1, "expected 1 critical severity warning")

	low := GetBySeverity(warnings, SeverityLow)
	assert.Len(t, low, 0, "expected 0 low severity warnings")
}

func TestGetByService(t *testing.T) {
	warnings := []Warning{
		{Code: "G1", Service: "grafana"},
		{Code: "G2", Service: "grafana"},
		{Code: "K1", Service: "kibana"},
		{Code: "GL", Service: ""},
	}

	grafana := GetByService(warnings, "grafana")
	// Should include grafana-specific and global warnings
	assert.Len(t, grafana, 3, "expected 3 warnings for grafana (2 specific + 1 global)")

	kibana := GetByService(warnings, "kibana")
	assert.Len(t, kibana, 2, "expected 2 warnings for kibana (1 specific + 1 global)")
}
