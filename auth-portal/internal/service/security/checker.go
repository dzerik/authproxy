// Package security provides security configuration analysis and warnings.
package security

import (
	"fmt"
	"strings"

	"github.com/dzerik/auth-portal/internal/config"
)

// Severity represents the severity level of a security warning.
type Severity string

const (
	// SeverityCritical indicates a critical security issue that must be fixed before production.
	SeverityCritical Severity = "critical"
	// SeverityHigh indicates a high-risk security issue.
	SeverityHigh Severity = "high"
	// SeverityMedium indicates a medium-risk security issue.
	SeverityMedium Severity = "medium"
	// SeverityLow indicates a low-risk informational issue.
	SeverityLow Severity = "low"
)

// Warning represents a security warning.
type Warning struct {
	// Code is a unique identifier for the warning (e.g., "SEC-001").
	Code string
	// Severity indicates the risk level.
	Severity Severity
	// Title is a short summary of the issue.
	Title string
	// Description provides detailed explanation of the risk.
	Description string
	// Service is the affected service name (if applicable).
	Service string
	// Recommendation provides guidance on how to fix the issue.
	Recommendation string
}

// Checker analyzes configuration for security issues.
type Checker struct {
	cfg *config.Config
}

// NewChecker creates a new security checker.
func NewChecker(cfg *config.Config) *Checker {
	return &Checker{cfg: cfg}
}

// Check analyzes the configuration and returns all security warnings.
func (c *Checker) Check() []Warning {
	var warnings []Warning

	// Check global configuration issues
	warnings = append(warnings, c.checkDevMode()...)
	warnings = append(warnings, c.checkSessionSecurity()...)
	warnings = append(warnings, c.checkTLSSecurity()...)

	// Check per-service issues
	warnings = append(warnings, c.checkServiceAuthentication()...)

	return warnings
}

// HasCritical returns true if there are any critical warnings.
func (c *Checker) HasCritical() bool {
	for _, w := range c.Check() {
		if w.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

// GetByService returns warnings for a specific service.
func GetByService(warnings []Warning, serviceName string) []Warning {
	var result []Warning
	for _, w := range warnings {
		if w.Service == serviceName || w.Service == "" {
			result = append(result, w)
		}
	}
	return result
}

// GetBySeverity returns warnings filtered by severity.
func GetBySeverity(warnings []Warning, severity Severity) []Warning {
	var result []Warning
	for _, w := range warnings {
		if w.Severity == severity {
			result = append(result, w)
		}
	}
	return result
}

// checkDevMode checks if dev mode is enabled.
func (c *Checker) checkDevMode() []Warning {
	if c.cfg.DevMode.Enabled {
		return []Warning{{
			Code:        "SEC-001",
			Severity:    SeverityCritical,
			Title:       "Development mode enabled",
			Description: "Dev mode bypasses real authentication and uses mock profiles. This is a critical security risk in production.",
			Recommendation: "Set dev_mode.enabled: false in configuration or remove DEV_MODE environment variable.",
		}}
	}
	return nil
}

// checkSessionSecurity checks session-related security settings.
func (c *Checker) checkSessionSecurity() []Warning {
	var warnings []Warning

	// Check secure cookie flag
	if !c.cfg.Session.Secure && !c.cfg.DevMode.Enabled {
		warnings = append(warnings, Warning{
			Code:        "SEC-002",
			Severity:    SeverityHigh,
			Title:       "Session cookie not marked as Secure",
			Description: "Session cookies can be transmitted over unencrypted HTTP connections, exposing them to interception.",
			Recommendation: "Set session.secure: true when using HTTPS in production.",
		})
	}

	// Check encryption
	if !c.cfg.Session.Encryption.Enabled {
		warnings = append(warnings, Warning{
			Code:        "SEC-003",
			Severity:    SeverityHigh,
			Title:       "Session encryption disabled",
			Description: "Session data is not encrypted, potentially exposing sensitive user information.",
			Recommendation: "Set session.encryption.enabled: true and provide a secure encryption key.",
		})
	}

	// Check SameSite
	if strings.ToLower(c.cfg.Session.SameSite) == "none" && !c.cfg.Session.Secure {
		warnings = append(warnings, Warning{
			Code:        "SEC-004",
			Severity:    SeverityMedium,
			Title:       "SameSite=None without Secure flag",
			Description: "Cookies with SameSite=None must have Secure flag enabled for browser compatibility.",
			Recommendation: "Set session.secure: true when using session.same_site: none.",
		})
	}

	return warnings
}

// checkTLSSecurity checks TLS configuration.
func (c *Checker) checkTLSSecurity() []Warning {
	var warnings []Warning

	// Skip TLS checks if dev mode is enabled
	if c.cfg.DevMode.Enabled {
		return nil
	}

	// Check if TLS is disabled in production-like config
	if !c.cfg.Server.TLS.Enabled && c.cfg.Session.Secure {
		warnings = append(warnings, Warning{
			Code:        "SEC-005",
			Severity:    SeverityMedium,
			Title:       "Secure cookies without TLS",
			Description: "Session is configured with secure cookies but TLS is disabled. This may work behind a TLS-terminating proxy, but verify your setup.",
			Recommendation: "Ensure TLS termination happens upstream (load balancer, ingress) or enable server.tls.enabled.",
		})
	}

	return warnings
}

// checkServiceAuthentication checks per-service authentication configuration.
func (c *Checker) checkServiceAuthentication() []Warning {
	var warnings []Warning

	for _, svc := range c.cfg.Services {
		// Skip services that don't require auth
		if !svc.AuthRequired {
			continue
		}

		// Check if Authorization header is removed - service relies on X-Auth-Request-* only
		authHeaderRemoved := false
		for _, header := range svc.Headers.Remove {
			if strings.EqualFold(header, "Authorization") {
				authHeaderRemoved = true
				break
			}
		}

		if authHeaderRemoved {
			warnings = append(warnings, Warning{
				Code:        "SEC-010",
				Severity:    SeverityHigh,
				Title:       fmt.Sprintf("Service '%s' uses insecure authentication", svc.Name),
				Description: fmt.Sprintf("Service '%s' removes the Authorization header and relies only on X-Auth-Request-* headers for authentication. These headers are not cryptographically signed and can be spoofed if the network is compromised.", svc.Name),
				Service:     svc.Name,
				Recommendation: "Remove 'Authorization' from headers.remove list to pass JWT tokens to the backend. Backend services should validate JWTs using the Keycloak JWKS endpoint.",
			})
		}

		// Check if service has nginx_extra (potential config injection)
		if svc.NginxExtra != "" {
			warnings = append(warnings, Warning{
				Code:        "SEC-011",
				Severity:    SeverityMedium,
				Title:       fmt.Sprintf("Service '%s' uses custom nginx config", svc.Name),
				Description: fmt.Sprintf("Service '%s' has nginx_extra configuration which may introduce security risks if not carefully reviewed.", svc.Name),
				Service:     svc.Name,
				Recommendation: "Review nginx_extra content for security implications. Consider using structured configuration options instead.",
			})
		}
	}

	return warnings
}

// CountBySeverity returns the count of warnings by severity.
func CountBySeverity(warnings []Warning) map[Severity]int {
	counts := map[Severity]int{
		SeverityCritical: 0,
		SeverityHigh:     0,
		SeverityMedium:   0,
		SeverityLow:      0,
	}
	for _, w := range warnings {
		counts[w.Severity]++
	}
	return counts
}

// FormatSummary returns a formatted summary of warnings.
func FormatSummary(warnings []Warning) string {
	if len(warnings) == 0 {
		return "No security warnings found"
	}

	counts := CountBySeverity(warnings)
	return fmt.Sprintf("Security warnings: %d critical, %d high, %d medium, %d low",
		counts[SeverityCritical],
		counts[SeverityHigh],
		counts[SeverityMedium],
		counts[SeverityLow],
	)
}
