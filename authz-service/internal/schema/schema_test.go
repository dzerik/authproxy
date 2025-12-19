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

func TestGenerator_Generate_EnvironmentSchema(t *testing.T) {
	gen := NewGenerator()

	data, err := gen.Generate(SchemaTypeEnvironment)

	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Verify it's valid JSON
	var schema map[string]interface{}
	err = json.Unmarshal(data, &schema)
	require.NoError(t, err)

	// Check required schema fields
	assert.Contains(t, schema, "$schema")
	assert.Contains(t, schema, "title")
	assert.Equal(t, "Authz Service Environment Configuration", schema["title"])

	// Check for x-runtime-updatable marker
	extras, ok := schema["x-runtime-updatable"]
	require.True(t, ok, "should have x-runtime-updatable at root")
	assert.Equal(t, false, extras, "environment config should not be runtime updatable")
}

func TestGenerator_Generate_ServicesSchema(t *testing.T) {
	gen := NewGenerator()

	data, err := gen.Generate(SchemaTypeServices)

	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Verify it's valid JSON
	var schema map[string]interface{}
	err = json.Unmarshal(data, &schema)
	require.NoError(t, err)

	// Check required schema fields
	assert.Contains(t, schema, "$schema")
	assert.Contains(t, schema, "title")
	assert.Equal(t, "Authz Service Services Configuration", schema["title"])

	// Check for x-runtime-updatable marker
	extras, ok := schema["x-runtime-updatable"]
	require.True(t, ok, "should have x-runtime-updatable at root")
	assert.Equal(t, true, extras, "services config should be runtime updatable")
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

	// Check for x-runtime-updatable marker
	extras, ok := schema["x-runtime-updatable"]
	require.True(t, ok, "should have x-runtime-updatable at root")
	assert.Equal(t, true, extras, "rules config should be runtime updatable")
}

func TestGenerator_Generate_DefaultType(t *testing.T) {
	gen := NewGenerator()

	// Empty schema type should default to environment
	data, err := gen.Generate("")

	require.NoError(t, err)
	require.NotEmpty(t, data)

	var schema map[string]interface{}
	err = json.Unmarshal(data, &schema)
	require.NoError(t, err)

	// Should be environment schema
	assert.Equal(t, "Authz Service Environment Configuration", schema["title"])
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
		{"environment", SchemaTypeEnvironment, true},
		{"ENVIRONMENT", SchemaTypeEnvironment, true},
		{"Environment", SchemaTypeEnvironment, true},
		{"services", SchemaTypeServices, true},
		{"SERVICES", SchemaTypeServices, true},
		{"Services", SchemaTypeServices, true},
		{"rules", SchemaTypeRules, true},
		{"RULES", SchemaTypeRules, true},
		{"Rules", SchemaTypeRules, true},
		{"invalid", "", false},
		{"", "", false},
		{"unknown", "", false},
		{"config", "", false}, // old type, no longer valid
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

	require.Len(t, schemas, 3)
	assert.Contains(t, schemas, SchemaTypeEnvironment)
	assert.Contains(t, schemas, SchemaTypeServices)
	assert.Contains(t, schemas, SchemaTypeRules)
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
	result := gen.postProcessJSON(input, SchemaTypeEnvironment)

	assert.Contains(t, result, "server_config")
	assert.NotContains(t, result, "ServerConfig")
}

func TestGenerator_EnvironmentSchema_HasSnakeCaseProperties(t *testing.T) {
	gen := NewGenerator()

	data, err := gen.Generate(SchemaTypeEnvironment)
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

func TestGenerator_ServicesSchema_HasSnakeCaseProperties(t *testing.T) {
	gen := NewGenerator()

	data, err := gen.Generate(SchemaTypeServices)
	require.NoError(t, err)

	jsonStr := string(data)

	// Should have snake_case properties
	assert.Contains(t, jsonStr, `"jwt"`)
	assert.Contains(t, jsonStr, `"policy"`)
	assert.Contains(t, jsonStr, `"cache"`)
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

	data, err := gen.Generate(SchemaTypeEnvironment)
	require.NoError(t, err)

	jsonStr := string(data)

	// Should contain duration pattern for duration fields
	assert.Contains(t, jsonStr, `"pattern"`)
	// The pattern for durations
	assert.Contains(t, jsonStr, "ns|us|µs|ms|s|m|h")
}

func TestSchemaType_Constants(t *testing.T) {
	assert.Equal(t, SchemaType("environment"), SchemaTypeEnvironment)
	assert.Equal(t, SchemaType("services"), SchemaTypeServices)
	assert.Equal(t, SchemaType("rules"), SchemaTypeRules)
}

func BenchmarkGenerator_Generate_Environment(b *testing.B) {
	gen := NewGenerator()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gen.Generate(SchemaTypeEnvironment)
	}
}

func BenchmarkGenerator_Generate_Services(b *testing.B) {
	gen := NewGenerator()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gen.Generate(SchemaTypeServices)
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
	inputs := []string{"environment", "services", "rules", "invalid"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseSchemaType(inputs[i%len(inputs)])
	}
}

func TestGenerator_HasValidReferences(t *testing.T) {
	gen := NewGenerator()

	data, err := gen.Generate(SchemaTypeEnvironment)
	require.NoError(t, err)

	jsonStr := string(data)

	// Schema should contain $ref references
	assert.Contains(t, jsonStr, "$ref")

	// References should point to $defs (valid JSON schema structure)
	assert.Regexp(t, `"\$ref":\s*"#/\$defs/`, jsonStr)
}

func TestGenerator_RuntimeUpdatable_InSchema(t *testing.T) {
	gen := NewGenerator()

	// Check environment schema has x-runtime-updatable=false
	envData, err := gen.Generate(SchemaTypeEnvironment)
	require.NoError(t, err)
	assert.Contains(t, string(envData), "x-runtime-updatable")

	// Check services schema has x-runtime-updatable=true
	svcData, err := gen.Generate(SchemaTypeServices)
	require.NoError(t, err)
	assert.Contains(t, string(svcData), "x-runtime-updatable")

	// Check rules schema has x-runtime-updatable=true
	rulesData, err := gen.Generate(SchemaTypeRules)
	require.NoError(t, err)
	assert.Contains(t, string(rulesData), "x-runtime-updatable")
}
