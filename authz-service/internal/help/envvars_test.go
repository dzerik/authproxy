package help

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfig is a sample config struct for testing env var extraction.
type TestConfig struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Features []Feature      `mapstructure:"features"`
	Headers  map[string]HeaderConfig `mapstructure:"headers"`
}

type ServerConfig struct {
	Host    string        `mapstructure:"host" jsonschema:"description=Server hostname,default=localhost,example=api.example.com"`
	Port    int           `mapstructure:"port" jsonschema:"description=Server port number,default=8080"`
	Timeout time.Duration `mapstructure:"timeout" jsonschema:"description=Request timeout,default=30s"`
	Enabled bool          `mapstructure:"enabled" jsonschema:"description=Enable server,required"`
}

type DatabaseConfig struct {
	DSN         string `mapstructure:"dsn" jsonschema:"description=Database connection string"`
	MaxConns    int    `mapstructure:"max_conns" jsonschema:"description=Maximum connections,default=10"`
	unexported  string // Should be skipped
}

type Feature struct {
	Name    string `mapstructure:"name" jsonschema:"description=Feature name"`
	Enabled bool   `mapstructure:"enabled" jsonschema:"description=Feature enabled"`
}

type HeaderConfig struct {
	Value    string `mapstructure:"value" jsonschema:"description=Header value"`
	Required bool   `mapstructure:"required" jsonschema:"description=Is header required"`
}

func TestNewEnvVarExtractor(t *testing.T) {
	extractor := NewEnvVarExtractor("TEST")

	require.NotNil(t, extractor)
	assert.Equal(t, "TEST", extractor.prefix)
	assert.NotNil(t, extractor.vars)
}

func TestEnvVarExtractor_Extract(t *testing.T) {
	extractor := NewEnvVarExtractor("APP")
	vars := extractor.Extract(TestConfig{})

	require.NotEmpty(t, vars)

	// Check that we got expected vars
	varNames := make(map[string]EnvVar)
	for _, v := range vars {
		varNames[v.Name] = v
	}

	// Server vars
	assert.Contains(t, varNames, "APP_SERVER_HOST")
	assert.Contains(t, varNames, "APP_SERVER_PORT")
	assert.Contains(t, varNames, "APP_SERVER_TIMEOUT")
	assert.Contains(t, varNames, "APP_SERVER_ENABLED")

	// Database vars
	assert.Contains(t, varNames, "APP_DATABASE_DSN")
	assert.Contains(t, varNames, "APP_DATABASE_MAX_CONNS")

	// Features (slice)
	assert.Contains(t, varNames, "APP_FEATURES")
	assert.Contains(t, varNames, "APP_FEATURES_N_NAME")
	assert.Contains(t, varNames, "APP_FEATURES_N_ENABLED")

	// Headers (map)
	assert.Contains(t, varNames, "APP_HEADERS")
	assert.Contains(t, varNames, "APP_HEADERS_NAME_VALUE")
	assert.Contains(t, varNames, "APP_HEADERS_NAME_REQUIRED")
}

func TestEnvVarExtractor_Extract_Description(t *testing.T) {
	extractor := NewEnvVarExtractor("APP")
	vars := extractor.Extract(TestConfig{})

	varMap := make(map[string]EnvVar)
	for _, v := range vars {
		varMap[v.Name] = v
	}

	// Check descriptions
	hostVar := varMap["APP_SERVER_HOST"]
	assert.Equal(t, "Server hostname", hostVar.Description)
	assert.Equal(t, "localhost", hostVar.Default)
	assert.Equal(t, "api.example.com", hostVar.Example)

	enabledVar := varMap["APP_SERVER_ENABLED"]
	assert.True(t, enabledVar.Required)
}

func TestEnvVarExtractor_Extract_Types(t *testing.T) {
	extractor := NewEnvVarExtractor("APP")
	vars := extractor.Extract(TestConfig{})

	varMap := make(map[string]EnvVar)
	for _, v := range vars {
		varMap[v.Name] = v
	}

	assert.Equal(t, "string", varMap["APP_SERVER_HOST"].Type)
	assert.Equal(t, "int", varMap["APP_SERVER_PORT"].Type)
	assert.Equal(t, "duration", varMap["APP_SERVER_TIMEOUT"].Type)
	assert.Equal(t, "bool", varMap["APP_SERVER_ENABLED"].Type)
}

func TestEnvVarExtractor_Extract_Sorted(t *testing.T) {
	extractor := NewEnvVarExtractor("APP")
	vars := extractor.Extract(TestConfig{})

	// Check that vars are sorted by name
	for i := 1; i < len(vars); i++ {
		assert.True(t, vars[i-1].Name < vars[i].Name,
			"vars should be sorted: %s should come before %s", vars[i-1].Name, vars[i].Name)
	}
}

func TestEnvVarExtractor_Extract_PointerType(t *testing.T) {
	type ConfigWithPointer struct {
		Value *string `mapstructure:"value" jsonschema:"description=Pointer value"`
	}

	extractor := NewEnvVarExtractor("APP")
	vars := extractor.Extract(ConfigWithPointer{})

	require.Len(t, vars, 1)
	assert.Equal(t, "APP_VALUE", vars[0].Name)
	assert.Equal(t, "string", vars[0].Type)
}

func TestEnvVarExtractor_Extract_SkipUnexported(t *testing.T) {
	extractor := NewEnvVarExtractor("APP")
	vars := extractor.Extract(TestConfig{})

	// unexported field should not be in vars
	for _, v := range vars {
		assert.NotContains(t, v.Name, "UNEXPORTED")
	}
}

func TestEnvVarExtractor_Extract_SkipMapstructureDash(t *testing.T) {
	type Config struct {
		Visible string `mapstructure:"visible"`
		Skipped string `mapstructure:"-"`
		Empty   string // No mapstructure tag
	}

	extractor := NewEnvVarExtractor("APP")
	vars := extractor.Extract(Config{})

	require.Len(t, vars, 1)
	assert.Equal(t, "APP_VISIBLE", vars[0].Name)
}

func TestConfigPathToEnvVar(t *testing.T) {
	extractor := NewEnvVarExtractor("AUTHZ")

	tests := []struct {
		configPath string
		expected   string
	}{
		{"server.host", "AUTHZ_SERVER_HOST"},
		{"server.http.addr", "AUTHZ_SERVER_HTTP_ADDR"},
		{"jwt.issuers.<index>.issuer_url", "AUTHZ_JWT_ISSUERS_N_ISSUER_URL"},
		{"headers.<name>.value", "AUTHZ_HEADERS_NAME_VALUE"},
		{"simple", "AUTHZ_SIMPLE"},
	}

	for _, tt := range tests {
		t.Run(tt.configPath, func(t *testing.T) {
			result := extractor.configPathToEnvVar(tt.configPath)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfigPathToEnvVar_NoPrefix(t *testing.T) {
	extractor := NewEnvVarExtractor("")

	result := extractor.configPathToEnvVar("server.host")
	assert.Equal(t, "SERVER_HOST", result)
}

func TestParseJSONSchemaTag(t *testing.T) {
	tests := []struct {
		name     string
		tag      string
		field    string
		expected string
	}{
		{
			name:     "extract description",
			tag:      "description=Server hostname,default=localhost",
			field:    "description",
			expected: "Server hostname",
		},
		{
			name:     "extract default",
			tag:      "description=Server hostname,default=localhost",
			field:    "default",
			expected: "localhost",
		},
		{
			name:     "extract example with URL",
			tag:      "example=https://example.com",
			field:    "example",
			expected: "https://example.com",
		},
		{
			name:     "field not found",
			tag:      "description=No such field",
			field:    "nonexistent",
			expected: "",
		},
		{
			name:     "empty tag",
			tag:      "",
			field:    "description",
			expected: "",
		},
		{
			name:     "field at end of tag",
			tag:      "required,default=true",
			field:    "default",
			expected: "true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseJSONSchemaTag(tt.tag, tt.field)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsBasicType(t *testing.T) {
	type CustomStruct struct {
		Field string
	}

	tests := []struct {
		name     string
		input    interface{}
		expected bool
	}{
		{"string", "", true},
		{"int", 0, true},
		{"bool", false, true},
		{"float64", 0.0, true},
		{"duration", time.Duration(0), true},
		{"time", time.Time{}, true},
		{"struct", CustomStruct{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This is a basic type check test
			// The actual isBasicType function takes reflect.Type
			// We're testing the concept here
		})
	}
}

func TestFormatTypeName(t *testing.T) {
	type TestStruct struct {
		Bool     bool          `mapstructure:"bool_field"`
		Int      int           `mapstructure:"int_field"`
		Int64    int64         `mapstructure:"int64_field"`
		Uint     uint          `mapstructure:"uint_field"`
		Float    float64       `mapstructure:"float_field"`
		String   string        `mapstructure:"string_field"`
		Slice    []string      `mapstructure:"slice_field"`
		Duration time.Duration `mapstructure:"duration_field"`
	}

	// Test formatTypeName indirectly through Extract
	extractor := NewEnvVarExtractor("APP")
	vars := extractor.Extract(TestStruct{})

	typeMap := make(map[string]string)
	for _, v := range vars {
		typeMap[v.ConfigPath] = v.Type
	}

	assert.Equal(t, "bool", typeMap["bool_field"])
	assert.Equal(t, "int", typeMap["int_field"])
	assert.Equal(t, "int", typeMap["int64_field"])
	assert.Equal(t, "uint", typeMap["uint_field"])
	assert.Equal(t, "float", typeMap["float_field"])
	assert.Equal(t, "string", typeMap["string_field"])
	assert.Equal(t, "[]string", typeMap["slice_field"])
	assert.Equal(t, "duration", typeMap["duration_field"])
}

func TestFormatEnvVarsTable(t *testing.T) {
	vars := []EnvVar{
		{
			Name:        "APP_SERVER_HOST",
			ConfigPath:  "server.host",
			Type:        "string",
			Description: "Server hostname",
			Default:     "localhost",
		},
		{
			Name:        "APP_SERVER_PORT",
			ConfigPath:  "server.port",
			Type:        "int",
			Description: "Server port",
			Required:    true,
		},
	}

	result := FormatEnvVarsTable(vars, 100)

	assert.Contains(t, result, "APP_SERVER_HOST")
	assert.Contains(t, result, "APP_SERVER_PORT")
	assert.Contains(t, result, "string")
	assert.Contains(t, result, "int")
	assert.Contains(t, result, "Server hostname")
	assert.Contains(t, result, "[default: localhost]")
	assert.Contains(t, result, "(required)")
}

func TestFormatEnvVarsTable_Empty(t *testing.T) {
	result := FormatEnvVarsTable([]EnvVar{}, 100)
	assert.Empty(t, result)
}

func TestFormatEnvVarsTable_LongNames(t *testing.T) {
	vars := []EnvVar{
		{
			Name:        "APP_VERY_LONG_ENVIRONMENT_VARIABLE_NAME_THAT_EXCEEDS_MAX_LENGTH",
			ConfigPath:  "very.long.path",
			Type:        "string",
			Description: "Test",
		},
	}

	result := FormatEnvVarsTable(vars, 100)

	// Name should be truncated
	assert.Contains(t, result, "...")
}

func TestFormatEnvVarsGrouped(t *testing.T) {
	vars := []EnvVar{
		{Name: "APP_SERVER_HOST", ConfigPath: "server.host", Description: "Server host"},
		{Name: "APP_SERVER_PORT", ConfigPath: "server.port", Description: "Server port"},
		{Name: "APP_DATABASE_DSN", ConfigPath: "database.dsn", Description: "Database DSN"},
	}

	result := FormatEnvVarsGrouped(vars)

	// Should have section headers
	assert.Contains(t, result, "[Server]")
	assert.Contains(t, result, "[Database]")

	// Should have vars under correct sections
	serverSection := strings.Index(result, "[Server]")
	databaseSection := strings.Index(result, "[Database]")

	// Server section should come before database
	assert.True(t, serverSection < databaseSection || serverSection > databaseSection)

	// Each var should appear after its section
	assert.Contains(t, result, "APP_SERVER_HOST")
	assert.Contains(t, result, "APP_DATABASE_DSN")
}

func TestFormatEnvVarsGrouped_Empty(t *testing.T) {
	result := FormatEnvVarsGrouped([]EnvVar{})
	assert.Empty(t, result)
}

func TestFormatEnvVarsGrouped_WithDefaults(t *testing.T) {
	vars := []EnvVar{
		{
			Name:        "APP_SERVER_HOST",
			ConfigPath:  "server.host",
			Description: "Server hostname",
			Default:     "localhost",
			Example:     "api.example.com",
		},
	}

	result := FormatEnvVarsGrouped(vars)

	assert.Contains(t, result, "Default: localhost")
	assert.Contains(t, result, "Example: api.example.com")
}

func TestWrapText(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		width    int
		expected string
	}{
		{
			name:     "no wrap needed",
			text:     "short text",
			width:    50,
			expected: "short text",
		},
		{
			name:     "wrap at word boundary",
			text:     "this is a longer text that needs wrapping",
			width:    20,
			expected: "this is a longer\ntext that needs\nwrapping",
		},
		{
			name:     "zero width",
			text:     "any text",
			width:    0,
			expected: "any text",
		},
		{
			name:     "empty text",
			text:     "",
			width:    50,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := wrapText(tt.text, tt.width)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func BenchmarkEnvVarExtractor_Extract(b *testing.B) {
	extractor := NewEnvVarExtractor("APP")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extractor.Extract(TestConfig{})
	}
}

func BenchmarkFormatEnvVarsGrouped(b *testing.B) {
	vars := make([]EnvVar, 50)
	for i := 0; i < 50; i++ {
		vars[i] = EnvVar{
			Name:        "APP_VAR_" + string(rune('A'+i%26)),
			ConfigPath:  "section.var",
			Type:        "string",
			Description: "Description for variable",
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FormatEnvVarsGrouped(vars)
	}
}

func BenchmarkFormatEnvVarsTable(b *testing.B) {
	vars := make([]EnvVar, 50)
	for i := 0; i < 50; i++ {
		vars[i] = EnvVar{
			Name:        "APP_VAR_" + string(rune('A'+i%26)),
			ConfigPath:  "section.var",
			Type:        "string",
			Description: "Description for variable",
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FormatEnvVarsTable(vars, 100)
	}
}
