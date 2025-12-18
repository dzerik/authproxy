// Package schema provides JSON Schema generation for configuration and rules.
package schema

import (
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"github.com/invopop/jsonschema"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/internal/service/policy"
)

// SchemaType represents the type of schema to generate.
type SchemaType string

const (
	SchemaTypeConfig SchemaType = "config"
	SchemaTypeRules  SchemaType = "rules"
)

// Generator generates JSON schemas for authz-service configuration files.
type Generator struct {
	reflector *jsonschema.Reflector
}

// NewGenerator creates a new schema generator.
func NewGenerator() *Generator {
	r := &jsonschema.Reflector{
		ExpandedStruct: false,
		// Only mark fields as required if they have explicit jsonschema:"required" tag
		// This makes all fields optional by default (they have defaults in setDefaults)
		RequiredFromJSONSchemaTags: true,
		Mapper: func(t reflect.Type) *jsonschema.Schema {
			// Handle time.Duration
			if t == reflect.TypeOf(time.Duration(0)) {
				return &jsonschema.Schema{
					Type:        "string",
					Pattern:     `^([0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$`,
					Description: "Duration string (e.g., '30s', '5m', '1h')",
					Examples:    []interface{}{"10s", "5m", "1h", "30s"},
				}
			}
			return nil
		},
	}

	return &Generator{reflector: r}
}

// Generate generates a JSON schema for the specified type.
func (g *Generator) Generate(schemaType SchemaType) ([]byte, error) {
	var schema *jsonschema.Schema

	switch schemaType {
	case SchemaTypeConfig:
		schema = g.generateConfigSchema()
	case SchemaTypeRules:
		schema = g.generateRulesSchema()
	default:
		schema = g.generateConfigSchema()
	}

	// Marshal with indentation
	data, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return nil, err
	}

	// Post-process to fix naming
	output := g.postProcessJSON(string(data), schemaType)

	return []byte(output), nil
}

// generateConfigSchema generates schema for config.yaml.
func (g *Generator) generateConfigSchema() *jsonschema.Schema {
	schema := g.reflector.Reflect(&config.Config{})
	g.processSchema(schema)

	schema.Title = "Authz Service Configuration"
	schema.Description = "Configuration schema for the authorization service.\n\n" +
		"Configuration can be provided via:\n" +
		"- YAML file (--config flag)\n" +
		"- Environment variables (AUTHZ_ prefix)\n\n" +
		"Environment variable naming: AUTHZ_<SECTION>_<KEY>\n" +
		"Example: AUTHZ_SERVER_HTTP_ADDR=:8080"
	schema.ID = "https://github.com/your-org/authz-service/schemas/config.schema.json"

	return schema
}

// generateRulesSchema generates schema for rules.yaml.
func (g *Generator) generateRulesSchema() *jsonschema.Schema {
	schema := g.reflector.Reflect(&policy.RuleSet{})
	g.processSchema(schema)

	schema.Title = "Authz Service Rules"
	schema.Description = "Policy rules schema for the builtin authorization engine.\n\n" +
		"Rules are evaluated in priority order (higher priority first).\n" +
		"First matching rule determines the authorization decision."
	schema.ID = "https://github.com/your-org/authz-service/schemas/rules.schema.json"

	// Add examples
	schema.Examples = []interface{}{
		map[string]interface{}{
			"version":      "1.0",
			"description":  "Example authorization rules",
			"default_deny": true,
			"rules": []interface{}{
				map[string]interface{}{
					"name":        "allow-health",
					"description": "Allow health check endpoints",
					"priority":    1000,
					"enabled":     true,
					"conditions": map[string]interface{}{
						"paths":   []string{"/health", "/ready", "/live"},
						"methods": []string{"GET"},
					},
					"effect": "allow",
				},
				map[string]interface{}{
					"name":        "api-read-access",
					"description": "Allow read access to API for authenticated users",
					"priority":    100,
					"enabled":     true,
					"conditions": map[string]interface{}{
						"path_templates": []string{"/api/v1/{resource_type}/{resource_id}"},
						"methods":        []string{"GET"},
						"roles":          []string{"user", "admin"},
						"actions":        []string{"read"},
					},
					"effect": "allow",
				},
			},
		},
	}

	return schema
}

// processSchema recursively processes schema definitions.
func (g *Generator) processSchema(schema *jsonschema.Schema) {
	if schema == nil {
		return
	}

	if schema.Definitions != nil {
		for _, def := range schema.Definitions {
			g.processSchemaProperties(def)
		}
	}

	g.processSchemaProperties(schema)
}

func (g *Generator) processSchemaProperties(schema *jsonschema.Schema) {
	if schema == nil || schema.Properties == nil {
		return
	}

	newProps := jsonschema.NewProperties()
	for pair := schema.Properties.Oldest(); pair != nil; pair = pair.Next() {
		key := pair.Key
		value := pair.Value

		snakeKey := toSnakeCase(key)
		newProps.Set(snakeKey, value)

		if value != nil {
			g.processSchemaProperties(value)
		}
	}
	schema.Properties = newProps

	if len(schema.Required) > 0 {
		newRequired := make([]string, len(schema.Required))
		for i, req := range schema.Required {
			newRequired[i] = toSnakeCase(req)
		}
		schema.Required = newRequired
	}
}

// postProcessJSON fixes PascalCase references in the JSON.
func (g *Generator) postProcessJSON(jsonStr string, schemaType SchemaType) string {
	var typeNames []string

	switch schemaType {
	case SchemaTypeConfig:
		typeNames = configTypeNames()
	case SchemaTypeRules:
		typeNames = rulesTypeNames()
	}

	result := jsonStr

	for _, name := range typeNames {
		snake := toSnakeCase(name)
		result = strings.ReplaceAll(result, `"#/$defs/`+name+`"`, `"#/$defs/`+snake+`"`)
		result = strings.ReplaceAll(result, `"`+name+`":`, `"`+snake+`":`)
	}

	// Handle external package types
	result = strings.ReplaceAll(result,
		`"#/$defs/github.com/your-org/authz-service/pkg/logger.Config"`,
		`"#/$defs/logger_config"`)
	result = strings.ReplaceAll(result,
		`"github.com/your-org/authz-service/pkg/logger.Config":`,
		`"logger_config":`)

	return result
}

func configTypeNames() []string {
	return []string{
		"Config", "ServerConfig", "ProxyConfig", "EgressConfig", "JWTConfig",
		"PolicyConfig", "CacheConfig", "AuditConfig", "HealthConfig",
		"TokenExchangeConfig", "EndpointsConfig", "HTTPServerConfig",
		"GRPCServerConfig", "UpstreamConfig", "UpstreamTLSConfig",
		"UpstreamHealthConfig", "RouteConfig", "IssuerConfig", "OPAConfig",
		"OPAEmbeddedConfig", "BuiltinPolicyConfig", "RedisCacheConfig",
		"L1CacheConfig", "L2CacheConfig", "EgressTargetConfig",
		"EgressAuthConfig", "EgressTLSConfig", "EgressRouteConfig",
		"EgressRetryConfig", "EgressDefaultsConfig", "EgressTokenStoreConfig",
		"EgressRedisConfig", "ProxyHeadersConfig", "ProxyRetryConfig",
		"JWKSCacheConfig", "ValidationConfig", "RetryConfig",
		"FallbackConfig", "CacheTTLConfig", "ExportConfig", "EnrichConfig",
		"OTLPExportConfig", "StdoutExportConfig", "CheckConfig",
		"KeepaliveConfig",
	}
}

func rulesTypeNames() []string {
	return []string{
		"RuleSet", "Rule", "Conditions", "Constraints",
	}
}

// toSnakeCase converts PascalCase/camelCase to snake_case.
// Handles special cases like IPs, IDs, URLs correctly.
func toSnakeCase(s string) string {
	// Special cases mapping
	special := map[string]string{
		"SourceIPs":        "source_ips",
		"SourceIDs":        "source_ids",
		"ResourceIDs":      "resource_ids",
		"UserIDs":          "user_ids",
		"ClientIDs":        "client_ids",
		"HTTPServerConfig": "http_server_config",
		"GRPCServerConfig": "grpc_server_config",
		"HTTPServer":       "http_server",
		"GRPCServer":       "grpc_server",
		"JWKSURL":          "jwks_url",
		"JWKSCache":        "jwks_cache",
		"JWKS":             "jwks",
		"OPAConfig":        "opa_config",
		"OPAEmbedded":      "opa_embedded",
		"OPA":              "opa",
		"OTLP":             "otlp",
		"TTL":              "ttl",
		"URL":              "url",
		"ID":               "id",
		"JWT":              "jwt",
	}

	// Check for special cases first
	if val, ok := special[s]; ok {
		return val
	}

	// Standard conversion
	var result strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			prev := rune(s[i-1])
			// Add underscore before uppercase if previous was lowercase
			// or if this starts a new word (uppercase followed by lowercase)
			if prev >= 'a' && prev <= 'z' {
				result.WriteByte('_')
			} else if i+1 < len(s) {
				next := rune(s[i+1])
				if next >= 'a' && next <= 'z' && prev >= 'A' && prev <= 'Z' {
					result.WriteByte('_')
				}
			}
		}
		if r >= 'A' && r <= 'Z' {
			result.WriteRune(r + 32) // toLower
		} else {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// GetAvailableSchemas returns list of available schema types.
func GetAvailableSchemas() []SchemaType {
	return []SchemaType{SchemaTypeConfig, SchemaTypeRules}
}

// ParseSchemaType parses a string to SchemaType.
func ParseSchemaType(s string) (SchemaType, bool) {
	switch strings.ToLower(s) {
	case "config":
		return SchemaTypeConfig, true
	case "rules":
		return SchemaTypeRules, true
	default:
		return "", false
	}
}
