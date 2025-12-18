package logger

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSensitiveMasker(t *testing.T) {
	cfg := SensitiveDataConfig{
		Enabled:   true,
		MaskValue: "***",
		Fields:    []string{"password", "secret"},
		Headers:   []string{"Authorization", "X-API-Key"},
		MaskJWT:   true,
	}

	masker := NewSensitiveMasker(cfg)

	require.NotNil(t, masker)
	assert.Equal(t, cfg.Enabled, masker.cfg.Enabled)
	assert.Len(t, masker.fieldPatterns, 2)
	assert.Len(t, masker.headerSet, 2)
}

func TestSensitiveMasker_MaskString(t *testing.T) {
	tests := []struct {
		name     string
		cfg      SensitiveDataConfig
		input    string
		expected string
	}{
		{
			name: "disabled masking",
			cfg: SensitiveDataConfig{
				Enabled:   false,
				MaskValue: "***",
			},
			input:    "sensitive-value",
			expected: "sensitive-value",
		},
		{
			name: "empty value",
			cfg: SensitiveDataConfig{
				Enabled:   true,
				MaskValue: "***",
			},
			input:    "",
			expected: "",
		},
		{
			name: "full masking",
			cfg: SensitiveDataConfig{
				Enabled:   true,
				MaskValue: "[MASKED]",
			},
			input:    "my-secret-password",
			expected: "[MASKED]",
		},
		{
			name: "partial masking - show first and last",
			cfg: SensitiveDataConfig{
				Enabled:   true,
				MaskValue: "***",
				PartialMask: PartialMaskConfig{
					Enabled:   true,
					ShowFirst: 2,
					ShowLast:  2,
					MinLength: 8,
				},
			},
			input:    "mysecretvalue",
			expected: "my***ue",
		},
		{
			name: "partial masking - value too short",
			cfg: SensitiveDataConfig{
				Enabled:   true,
				MaskValue: "***",
				PartialMask: PartialMaskConfig{
					Enabled:   true,
					ShowFirst: 2,
					ShowLast:  2,
					MinLength: 20,
				},
			},
			input:    "short",
			expected: "***",
		},
		{
			name: "partial masking - show chars exceed length",
			cfg: SensitiveDataConfig{
				Enabled:   true,
				MaskValue: "***",
				PartialMask: PartialMaskConfig{
					Enabled:   true,
					ShowFirst: 5,
					ShowLast:  5,
					MinLength: 5,
				},
			},
			input:    "short",
			expected: "***",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			masker := NewSensitiveMasker(tt.cfg)
			result := masker.MaskString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSensitiveMasker_MaskJWT(t *testing.T) {
	tests := []struct {
		name     string
		cfg      SensitiveDataConfig
		token    string
		expected string
	}{
		{
			name: "disabled masking",
			cfg: SensitiveDataConfig{
				Enabled:   false,
				MaskJWT:   true,
				MaskValue: "***",
			},
			token:    "header.payload.signature",
			expected: "header.payload.signature",
		},
		{
			name: "jwt masking disabled",
			cfg: SensitiveDataConfig{
				Enabled:   true,
				MaskJWT:   false,
				MaskValue: "***",
			},
			token:    "header.payload.signature",
			expected: "header.payload.signature",
		},
		{
			name: "empty token",
			cfg: SensitiveDataConfig{
				Enabled:   true,
				MaskJWT:   true,
				MaskValue: "***",
			},
			token:    "",
			expected: "",
		},
		{
			name: "valid JWT format",
			cfg: SensitiveDataConfig{
				Enabled:   true,
				MaskJWT:   true,
				MaskValue: "******",
			},
			token:    "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature",
			expected: "eyJhbGciOiJSUzI1NiJ9.******.***",
		},
		{
			name: "invalid JWT format - not 3 parts",
			cfg: SensitiveDataConfig{
				Enabled:   true,
				MaskJWT:   true,
				MaskValue: "[MASKED]",
			},
			token:    "invalid.token",
			expected: "[MASKED]",
		},
		{
			name: "invalid JWT format - no dots",
			cfg: SensitiveDataConfig{
				Enabled:   true,
				MaskJWT:   true,
				MaskValue: "[MASKED]",
			},
			token:    "notavalidtoken",
			expected: "[MASKED]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			masker := NewSensitiveMasker(tt.cfg)
			result := masker.MaskJWT(tt.token)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSensitiveMasker_IsSensitiveField(t *testing.T) {
	cfg := SensitiveDataConfig{
		Enabled:   true,
		MaskValue: "***",
		Fields:    []string{"password", "secret", "token", "key"},
	}
	masker := NewSensitiveMasker(cfg)

	tests := []struct {
		fieldName string
		expected  bool
	}{
		{"password", true},
		{"Password", true},
		{"PASSWORD", true},
		{"user_password", true},
		{"secret", true},
		{"api_secret", true},
		{"token", true},
		{"access_token", true},
		{"key", true},
		{"api_key", true},
		{"username", false},
		{"email", false},
		{"id", false},
	}

	for _, tt := range tests {
		t.Run(tt.fieldName, func(t *testing.T) {
			result := masker.IsSensitiveField(tt.fieldName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSensitiveMasker_IsSensitiveField_Disabled(t *testing.T) {
	cfg := SensitiveDataConfig{
		Enabled: false,
		Fields:  []string{"password"},
	}
	masker := NewSensitiveMasker(cfg)

	assert.False(t, masker.IsSensitiveField("password"))
}

func TestSensitiveMasker_IsSensitiveHeader(t *testing.T) {
	cfg := SensitiveDataConfig{
		Enabled:   true,
		MaskValue: "***",
		Headers:   []string{"Authorization", "X-API-Key", "Cookie"},
	}
	masker := NewSensitiveMasker(cfg)

	tests := []struct {
		headerName string
		expected   bool
	}{
		{"Authorization", true},
		{"authorization", true},
		{"AUTHORIZATION", true},
		{"X-API-Key", true},
		{"x-api-key", true},
		{"Cookie", true},
		{"Content-Type", false},
		{"Accept", false},
		{"X-Request-ID", false},
	}

	for _, tt := range tests {
		t.Run(tt.headerName, func(t *testing.T) {
			result := masker.IsSensitiveHeader(tt.headerName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSensitiveMasker_MaskHeaders(t *testing.T) {
	cfg := SensitiveDataConfig{
		Enabled:   true,
		MaskValue: "[MASKED]",
		Headers:   []string{"Authorization", "X-API-Key"},
	}
	masker := NewSensitiveMasker(cfg)

	headers := map[string]string{
		"Authorization": "Bearer token123",
		"Content-Type":  "application/json",
		"X-API-Key":     "secret-key",
		"X-Request-ID":  "req-123",
	}

	result := masker.MaskHeaders(headers)

	assert.Equal(t, "[MASKED]", result["Authorization"])
	assert.Equal(t, "application/json", result["Content-Type"])
	assert.Equal(t, "[MASKED]", result["X-API-Key"])
	assert.Equal(t, "req-123", result["X-Request-ID"])
}

func TestSensitiveMasker_MaskHeaders_Disabled(t *testing.T) {
	cfg := SensitiveDataConfig{
		Enabled: false,
		Headers: []string{"Authorization"},
	}
	masker := NewSensitiveMasker(cfg)

	headers := map[string]string{
		"Authorization": "Bearer token123",
	}

	result := masker.MaskHeaders(headers)
	assert.Equal(t, "Bearer token123", result["Authorization"])
}

func TestSensitiveMasker_MaskHeaders_NilInput(t *testing.T) {
	cfg := SensitiveDataConfig{
		Enabled: true,
		Headers: []string{"Authorization"},
	}
	masker := NewSensitiveMasker(cfg)

	result := masker.MaskHeaders(nil)
	assert.Nil(t, result)
}

func TestSensitiveMasker_MaskHeaderSlice(t *testing.T) {
	cfg := SensitiveDataConfig{
		Enabled:   true,
		MaskValue: "[MASKED]",
		Headers:   []string{"Authorization", "Cookie"},
	}
	masker := NewSensitiveMasker(cfg)

	headers := map[string][]string{
		"Authorization": {"Bearer token1", "Bearer token2"},
		"Content-Type":  {"application/json"},
		"Cookie":        {"session=abc", "user=xyz"},
	}

	result := masker.MaskHeaderSlice(headers)

	assert.Equal(t, []string{"[MASKED]", "[MASKED]"}, result["Authorization"])
	assert.Equal(t, []string{"application/json"}, result["Content-Type"])
	assert.Equal(t, []string{"[MASKED]", "[MASKED]"}, result["Cookie"])
}

func TestGlobalMasker_Functions(t *testing.T) {
	// Initialize global masker
	cfg := SensitiveDataConfig{
		Enabled:   true,
		MaskValue: "[MASKED]",
		Fields:    []string{"password", "secret"},
		Headers:   []string{"Authorization"},
		MaskJWT:   true,
	}
	InitMasker(cfg)

	t.Run("MaskSensitive", func(t *testing.T) {
		result := MaskSensitive("secret-value")
		assert.Equal(t, "[MASKED]", result)
	})

	t.Run("MaskJWTToken", func(t *testing.T) {
		result := MaskJWTToken("header.payload.signature")
		assert.Contains(t, result, "header.")
		assert.Contains(t, result, "[MASKED]")
	})

	t.Run("SensitiveString - sensitive field", func(t *testing.T) {
		field := SensitiveString("password", "my-secret")
		assert.Equal(t, "password", field.Key)
		assert.Equal(t, "[MASKED]", field.String)
	})

	t.Run("SensitiveString - non-sensitive field", func(t *testing.T) {
		field := SensitiveString("username", "john")
		assert.Equal(t, "username", field.Key)
		assert.Equal(t, "john", field.String)
	})

	t.Run("SensitiveHeader - sensitive", func(t *testing.T) {
		field := SensitiveHeader("Authorization", "Bearer token")
		assert.Equal(t, "Authorization", field.Key)
		assert.Equal(t, "[MASKED]", field.String)
	})

	t.Run("SensitiveHeader - non-sensitive", func(t *testing.T) {
		field := SensitiveHeader("Content-Type", "application/json")
		assert.Equal(t, "Content-Type", field.Key)
		assert.Equal(t, "application/json", field.String)
	})

	t.Run("Token - JWT format", func(t *testing.T) {
		field := Token("access_token", "header.payload.signature")
		assert.Equal(t, "access_token", field.Key)
		assert.Contains(t, field.String, "header.")
	})

	t.Run("Token - non-JWT format", func(t *testing.T) {
		field := Token("api_key", "simple-token")
		assert.Equal(t, "api_key", field.Key)
		assert.Equal(t, "[MASKED]", field.String)
	})
}

func TestGlobalMasker_NilMasker(t *testing.T) {
	// Reset global masker
	globalMasker = nil

	t.Run("MaskSensitive returns original", func(t *testing.T) {
		result := MaskSensitive("value")
		assert.Equal(t, "value", result)
	})

	t.Run("MaskJWTToken returns original", func(t *testing.T) {
		result := MaskJWTToken("token")
		assert.Equal(t, "token", result)
	})

	t.Run("SensitiveString returns unmasked", func(t *testing.T) {
		field := SensitiveString("password", "secret")
		assert.Equal(t, "secret", field.String)
	})

	t.Run("Token returns unmasked", func(t *testing.T) {
		field := Token("token", "value")
		assert.Equal(t, "value", field.String)
	})
}

func BenchmarkMaskString(b *testing.B) {
	cfg := SensitiveDataConfig{
		Enabled:   true,
		MaskValue: "[MASKED]",
	}
	masker := NewSensitiveMasker(cfg)
	value := "sensitive-data-to-mask"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		masker.MaskString(value)
	}
}

func BenchmarkMaskJWT(b *testing.B) {
	cfg := SensitiveDataConfig{
		Enabled:   true,
		MaskJWT:   true,
		MaskValue: "[MASKED]",
	}
	masker := NewSensitiveMasker(cfg)
	token := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		masker.MaskJWT(token)
	}
}

func BenchmarkIsSensitiveField(b *testing.B) {
	cfg := SensitiveDataConfig{
		Enabled: true,
		Fields:  []string{"password", "secret", "token", "key", "credential"},
	}
	masker := NewSensitiveMasker(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		masker.IsSensitiveField("user_password")
	}
}

func BenchmarkIsSensitiveHeader(b *testing.B) {
	cfg := SensitiveDataConfig{
		Enabled: true,
		Headers: []string{"Authorization", "X-API-Key", "Cookie", "X-Auth-Token"},
	}
	masker := NewSensitiveMasker(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		masker.IsSensitiveHeader("Authorization")
	}
}
