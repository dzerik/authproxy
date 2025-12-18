package schema

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGenerator(t *testing.T) {
	gen := NewGenerator()

	require.NotNil(t, gen)
	require.NotNil(t, gen.reflector)
}

func TestGenerator_Generate_ConfigSchema(t *testing.T) {
	gen := NewGenerator()

	data, err := gen.Generate(SchemaTypeConfig)

	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Verify it's valid JSON
	var schema map[string]interface{}
	err = json.Unmarshal(data, &schema)
	require.NoError(t, err)

	// Check required schema fields
	assert.Contains(t, schema, "$schema")
	assert.Contains(t, schema, "title")
	assert.Equal(t, "Authz Service Configuration", schema["title"])

	// Check description contains env var info
	desc, ok := schema["description"].(string)
	require.True(t, ok)
	assert.Contains(t, desc, "AUTHZ_")
}

func TestGenerator_Generate_RulesSchema(t *testing.T) {
	gen := NewGenerator()

	data, err := gen.Generate(SchemaTypeRules)

	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Verify it's valid JSON
	var schema map[string]interface{}
	err = json.Unmarshal(data, &schema)
	require.NoError(t, err)

	// Check required schema fields
	assert.Contains(t, schema, "title")
	assert.Equal(t, "Authz Service Rules", schema["title"])

	// Check for examples
	assert.Contains(t, schema, "examples")
}

func TestGenerator_Generate_DefaultType(t *testing.T) {
	gen := NewGenerator()

	// Empty schema type should default to config
	data, err := gen.Generate("")

	require.NoError(t, err)
	require.NotEmpty(t, data)

	var schema map[string]interface{}
	err = json.Unmarshal(data, &schema)
	require.NoError(t, err)

	// Should be config schema
	assert.Equal(t, "Authz Service Configuration", schema["title"])
}

func TestToSnakeCase(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Config", "config"},
		{"ServerConfig", "server_config"},
		{"HTTPServerConfig", "http_server_config"},
		{"GRPCServerConfig", "grpc_server_config"},
		{"OPAConfig", "opa_config"},
		{"OPAEmbedded", "opa_embedded"},
		{"JWKSURL", "jwks_url"},
		{"SourceIPs", "source_ips"},
		{"SourceIDs", "source_ids"},
		{"UserIDs", "user_ids"},
		{"ClientIDs", "client_ids"},
		{"ResourceIDs", "resource_ids"},
		{"JWKSCache", "jwks_cache"},
		{"TTL", "ttl"},
		{"URL", "url"},
		{"ID", "id"},
		{"JWT", "jwt"},
		{"OTLP", "otlp"},
		{"CamelCase", "camel_case"},
		{"simpleword", "simpleword"},
		{"XMLParser", "xml_parser"},
		{"JSONData", "json_data"},
		{"myVar", "my_var"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := toSnakeCase(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseSchemaType(t *testing.T) {
	tests := []struct {
		input       string
		expected    SchemaType
		expectValid bool
	}{
		{"config", SchemaTypeConfig, true},
		{"CONFIG", SchemaTypeConfig, true},
		{"Config", SchemaTypeConfig, true},
		{"rules", SchemaTypeRules, true},
		{"RULES", SchemaTypeRules, true},
		{"Rules", SchemaTypeRules, true},
		{"invalid", "", false},
		{"", "", false},
		{"unknown", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, valid := ParseSchemaType(tt.input)
			assert.Equal(t, tt.expectValid, valid)
			if tt.expectValid {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestGetAvailableSchemas(t *testing.T) {
	schemas := GetAvailableSchemas()

	require.Len(t, schemas, 2)
	assert.Contains(t, schemas, SchemaTypeConfig)
	assert.Contains(t, schemas, SchemaTypeRules)
}

func TestConfigTypeNames(t *testing.T) {
	names := configTypeNames()

	require.NotEmpty(t, names)
	assert.Contains(t, names, "Config")
	assert.Contains(t, names, "ServerConfig")
	assert.Contains(t, names, "HTTPServerConfig")
	assert.Contains(t, names, "JWTConfig")
}

func TestRulesTypeNames(t *testing.T) {
	names := rulesTypeNames()

	require.NotEmpty(t, names)
	assert.Contains(t, names, "RuleSet")
	assert.Contains(t, names, "Rule")
	assert.Contains(t, names, "Conditions")
}

func TestGenerator_PostProcessJSON(t *testing.T) {
	gen := NewGenerator()

	input := `{"$ref": "#/$defs/ServerConfig", "ServerConfig": {}}`
	result := gen.postProcessJSON(input, SchemaTypeConfig)

	assert.Contains(t, result, "server_config")
	assert.NotContains(t, result, "ServerConfig")
}

func TestGenerator_ConfigSchema_HasSnakeCaseProperties(t *testing.T) {
	gen := NewGenerator()

	data, err := gen.Generate(SchemaTypeConfig)
	require.NoError(t, err)

	jsonStr := string(data)

	// Should have snake_case properties, not PascalCase
	// Check for some common snake_case property names
	assert.Contains(t, jsonStr, `"server"`)
	assert.Contains(t, jsonStr, `"http"`)

	// Should not have PascalCase in property names
	// (Note: $defs keys are converted to snake_case in postProcessJSON)
	assert.NotContains(t, jsonStr, `"Server":`)
	assert.NotContains(t, jsonStr, `"Http":`)
}

func TestGenerator_RulesSchema_HasExamples(t *testing.T) {
	gen := NewGenerator()

	data, err := gen.Generate(SchemaTypeRules)
	require.NoError(t, err)

	var schema map[string]interface{}
	err = json.Unmarshal(data, &schema)
	require.NoError(t, err)

	examples, ok := schema["examples"].([]interface{})
	require.True(t, ok)
	require.NotEmpty(t, examples)

	// First example should have the expected structure
	example := examples[0].(map[string]interface{})
	assert.Contains(t, example, "version")
	assert.Contains(t, example, "rules")
}

func TestGenerator_DurationPattern(t *testing.T) {
	gen := NewGenerator()

	data, err := gen.Generate(SchemaTypeConfig)
	require.NoError(t, err)

	jsonStr := string(data)

	// Should contain duration pattern for duration fields
	assert.Contains(t, jsonStr, `"pattern"`)
	// The pattern for durations
	assert.Contains(t, jsonStr, "ns|us|µs|ms|s|m|h")
}

func TestSchemaType_Constants(t *testing.T) {
	assert.Equal(t, SchemaType("config"), SchemaTypeConfig)
	assert.Equal(t, SchemaType("rules"), SchemaTypeRules)
}

func BenchmarkGenerator_Generate_Config(b *testing.B) {
	gen := NewGenerator()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gen.Generate(SchemaTypeConfig)
	}
}

func BenchmarkGenerator_Generate_Rules(b *testing.B) {
	gen := NewGenerator()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gen.Generate(SchemaTypeRules)
	}
}

func BenchmarkToSnakeCase(b *testing.B) {
	inputs := []string{
		"HTTPServerConfig",
		"SimpleWord",
		"CamelCase",
		"XMLParser",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		toSnakeCase(inputs[i%len(inputs)])
	}
}

func BenchmarkParseSchemaType(b *testing.B) {
	inputs := []string{"config", "rules", "CONFIG", "invalid"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseSchemaType(inputs[i%len(inputs)])
	}
}

func TestGenerator_HasValidReferences(t *testing.T) {
	gen := NewGenerator()

	data, err := gen.Generate(SchemaTypeConfig)
	require.NoError(t, err)

	jsonStr := string(data)

	// Schema should contain $ref references
	assert.Contains(t, jsonStr, "$ref")

	// References should point to $defs (valid JSON schema structure)
	assert.Regexp(t, `"\$ref":\s*"#/\$defs/`, jsonStr)
}
