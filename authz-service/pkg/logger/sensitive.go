package logger

import (
	"regexp"
	"strings"

	"go.uber.org/zap"
)

// SensitiveDataConfig configures sensitive data masking in logs.
// This is a local copy to avoid import cycles with internal/config.
type SensitiveDataConfig struct {
	Enabled     bool              `mapstructure:"enabled"`
	MaskValue   string            `mapstructure:"mask_value"`
	Fields      []string          `mapstructure:"fields"`
	Headers     []string          `mapstructure:"headers"`
	MaskJWT     bool              `mapstructure:"mask_jwt"`
	PartialMask PartialMaskConfig `mapstructure:"partial_mask"`
}

// PartialMaskConfig configures partial masking behavior.
type PartialMaskConfig struct {
	Enabled   bool `mapstructure:"enabled"`
	ShowFirst int  `mapstructure:"show_first"`
	ShowLast  int  `mapstructure:"show_last"`
	MinLength int  `mapstructure:"min_length"`
}

// SensitiveMasker masks sensitive data in log values.
type SensitiveMasker struct {
	cfg           SensitiveDataConfig
	fieldPatterns []*regexp.Regexp
	headerSet     map[string]struct{}
}

var globalMasker *SensitiveMasker

// InitMasker initializes the global sensitive data masker.
func InitMasker(cfg SensitiveDataConfig) {
	globalMasker = NewSensitiveMasker(cfg)
}

// NewSensitiveMasker creates a new sensitive data masker.
func NewSensitiveMasker(cfg SensitiveDataConfig) *SensitiveMasker {
	m := &SensitiveMasker{
		cfg:           cfg,
		fieldPatterns: make([]*regexp.Regexp, 0, len(cfg.Fields)),
		headerSet:     make(map[string]struct{}, len(cfg.Headers)),
	}

	// Compile field patterns (case-insensitive)
	for _, field := range cfg.Fields {
		pattern := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(field))
		m.fieldPatterns = append(m.fieldPatterns, pattern)
	}

	// Build header set (lowercase for case-insensitive comparison)
	for _, header := range cfg.Headers {
		m.headerSet[strings.ToLower(header)] = struct{}{}
	}

	return m
}

// MaskString masks a sensitive string value.
func (m *SensitiveMasker) MaskString(value string) string {
	if !m.cfg.Enabled || value == "" {
		return value
	}

	if m.cfg.PartialMask.Enabled && len(value) >= m.cfg.PartialMask.MinLength {
		return m.partialMask(value)
	}

	return m.cfg.MaskValue
}

// partialMask applies partial masking to a value.
func (m *SensitiveMasker) partialMask(value string) string {
	showFirst := m.cfg.PartialMask.ShowFirst
	showLast := m.cfg.PartialMask.ShowLast

	if showFirst+showLast >= len(value) {
		return m.cfg.MaskValue
	}

	return value[:showFirst] + m.cfg.MaskValue + value[len(value)-showLast:]
}

// MaskJWT masks a JWT token, keeping header visible.
func (m *SensitiveMasker) MaskJWT(token string) string {
	if !m.cfg.Enabled || !m.cfg.MaskJWT || token == "" {
		return token
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		// Not a valid JWT format, mask entirely
		return m.cfg.MaskValue
	}

	// Keep header, mask payload and signature
	return parts[0] + "." + m.cfg.MaskValue + "." + m.cfg.MaskValue[:len(m.cfg.MaskValue)/2]
}

// IsSensitiveField checks if a field name is sensitive.
func (m *SensitiveMasker) IsSensitiveField(fieldName string) bool {
	if !m.cfg.Enabled {
		return false
	}

	fieldLower := strings.ToLower(fieldName)
	for _, pattern := range m.fieldPatterns {
		if pattern.MatchString(fieldLower) {
			return true
		}
	}
	return false
}

// IsSensitiveHeader checks if a header name is sensitive.
func (m *SensitiveMasker) IsSensitiveHeader(headerName string) bool {
	if !m.cfg.Enabled {
		return false
	}

	_, exists := m.headerSet[strings.ToLower(headerName)]
	return exists
}

// MaskHeaders masks sensitive headers from a map.
func (m *SensitiveMasker) MaskHeaders(headers map[string]string) map[string]string {
	if !m.cfg.Enabled || headers == nil {
		return headers
	}

	masked := make(map[string]string, len(headers))
	for k, v := range headers {
		if m.IsSensitiveHeader(k) {
			masked[k] = m.MaskString(v)
		} else {
			masked[k] = v
		}
	}
	return masked
}

// MaskHeaderSlice masks sensitive headers from a map with slice values.
func (m *SensitiveMasker) MaskHeaderSlice(headers map[string][]string) map[string][]string {
	if !m.cfg.Enabled || headers == nil {
		return headers
	}

	masked := make(map[string][]string, len(headers))
	for k, values := range headers {
		if m.IsSensitiveHeader(k) {
			maskedValues := make([]string, len(values))
			for i, v := range values {
				maskedValues[i] = m.MaskString(v)
			}
			masked[k] = maskedValues
		} else {
			masked[k] = values
		}
	}
	return masked
}

// Global masking functions using the global masker

// MaskSensitive masks a value if it's sensitive.
func MaskSensitive(value string) string {
	if globalMasker == nil {
		return value
	}
	return globalMasker.MaskString(value)
}

// MaskJWTToken masks a JWT token.
func MaskJWTToken(token string) string {
	if globalMasker == nil {
		return token
	}
	return globalMasker.MaskJWT(token)
}

// SensitiveString creates a zap field with masked value if the field name is sensitive.
func SensitiveString(key, value string) zap.Field {
	if globalMasker != nil && globalMasker.IsSensitiveField(key) {
		return zap.String(key, globalMasker.MaskString(value))
	}
	return zap.String(key, value)
}

// SensitiveHeader creates a zap field for a header, masking if sensitive.
func SensitiveHeader(headerName, value string) zap.Field {
	if globalMasker != nil && globalMasker.IsSensitiveHeader(headerName) {
		return zap.String(headerName, globalMasker.MaskString(value))
	}
	return zap.String(headerName, value)
}

// SensitiveHeaders creates a zap field for headers, masking sensitive ones.
func SensitiveHeaders(headers map[string]string) zap.Field {
	if globalMasker != nil {
		return zap.Any("headers", globalMasker.MaskHeaders(headers))
	}
	return zap.Any("headers", headers)
}

// Token creates a zap field for a token, applying JWT masking if configured.
func Token(key, value string) zap.Field {
	if globalMasker != nil {
		// Check if it looks like a JWT
		if strings.Count(value, ".") == 2 {
			return zap.String(key, globalMasker.MaskJWT(value))
		}
		return zap.String(key, globalMasker.MaskString(value))
	}
	return zap.String(key, value)
}
