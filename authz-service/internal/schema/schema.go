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
	SchemaTypeRules       SchemaType = "rules"
	SchemaTypeEnvironment SchemaType = "environment"
	SchemaTypeServices    SchemaType = "services"
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
	case SchemaTypeRules:
		schema = g.generateRulesSchema()
	case SchemaTypeEnvironment:
		schema = g.generateEnvironmentSchema()
	case SchemaTypeServices:
		schema = g.generateServicesSchema()
	default:
		schema = g.generateEnvironmentSchema()
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

// generateRulesSchema generates schema for rules.yaml.
func (g *Generator) generateRulesSchema() *jsonschema.Schema {
	schema := g.reflector.Reflect(&policy.RuleSet{})
	g.processSchema(schema)

	schema.Title = "Authz Service Rules"
	schema.Description = "Policy rules schema for the builtin authorization engine.\n\n" +
		"Rules are evaluated in priority order (higher priority first).\n" +
		"First matching rule determines the authorization decision.\n" +
		"This configuration is runtime-updatable (x-runtime-updatable: true)."
	schema.ID = "https://github.com/your-org/authz-service/schemas/rules.schema.json"

	// Add x-runtime-updatable to root
	if schema.Extras == nil {
		schema.Extras = make(map[string]interface{})
	}
	schema.Extras["x-runtime-updatable"] = true

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

// generateEnvironmentSchema generates schema for environment.yaml.
func (g *Generator) generateEnvironmentSchema() *jsonschema.Schema {
	schema := g.reflector.Reflect(&config.EnvironmentConfig{})
	g.processSchema(schema)

	schema.Title = "Authz Service Environment Configuration"
	schema.Description = "Static environment configuration that requires service restart to change.\n\n" +
		"This configuration includes server settings, logging, tracing, and config source settings.\n" +
		"All properties are marked as x-runtime-updatable: false."
	schema.ID = "https://github.com/your-org/authz-service/schemas/environment.schema.json"

	// Add x-runtime-updatable to root
	if schema.Extras == nil {
		schema.Extras = make(map[string]interface{})
	}
	schema.Extras["x-runtime-updatable"] = false

	return schema
}

// generateServicesSchema generates schema for services.yaml.
func (g *Generator) generateServicesSchema() *jsonschema.Schema {
	schema := g.reflector.Reflect(&config.ServicesConfig{})
	g.processSchema(schema)

	schema.Title = "Authz Service Services Configuration"
	schema.Description = "Dynamic services configuration that can be updated at runtime without restart.\n\n" +
		"This configuration includes JWT, policy, cache, proxy, egress, and other service settings.\n" +
		"Properties marked with x-runtime-updatable: true can be changed without restart."
	schema.ID = "https://github.com/your-org/authz-service/schemas/services.schema.json"

	// Add x-runtime-updatable to root
	if schema.Extras == nil {
		schema.Extras = make(map[string]interface{})
	}
	schema.Extras["x-runtime-updatable"] = true

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
	case SchemaTypeRules:
		typeNames = rulesTypeNames()
	case SchemaTypeEnvironment:
		typeNames = environmentTypeNames()
	case SchemaTypeServices:
		typeNames = servicesTypeNames()
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

func rulesTypeNames() []string {
	return []string{
		"RuleSet", "Rule", "Conditions", "Constraints",
	}
}

func environmentTypeNames() []string {
	return []string{
		"EnvironmentConfig", "EnvConfig", "ServerConfig", "HTTPServerConfig",
		"GRPCServerConfig", "KeepaliveConfig", "ManagementServerConfig",
		"LoggingConfig", "TracingConfig", "ConfigSourceSettings",
		"FileSourceSettings", "RemoteSourceSettings", "RemoteAuthSettings",
		"RemotePathSettings", "PollingSettings", "RetrySettings",
		"PushSettings", "FallbackSourceSettings",
	}
}

func servicesTypeNames() []string {
	return []string{
		"ServicesConfig", "JWTConfig", "IssuerConfig", "JWKSCacheConfig",
		"ValidationConfig", "TokenExchangeConfig", "PolicyConfig",
		"OPAConfig", "OPAEmbeddedConfig", "BuiltinPolicyConfig",
		"FallbackConfig", "RetryConfig", "CacheConfig", "L1CacheConfig",
		"L2CacheConfig", "RedisCacheConfig", "CacheTTLConfig",
		"AuditConfig", "ExportConfig", "OTLPExportConfig", "StdoutExportConfig",
		"EnrichConfig", "HealthConfig", "CheckConfig", "ResilienceConfig",
		"RateLimitConfig", "RateLimitHeadersConfig", "CircuitBreakerConfig",
		"CircuitBreakerSettings", "SensitiveDataConfig", "PartialMaskConfig",
		"TLSClientCertConfig", "TLSCertSourcesConfig", "XFCCConfig",
		"CertHeadersConfig", "RequestBodyConfig", "RequestBodySchemaConfig",
		"ProxyListenersConfig", "ProxyListenerConfig", "ProxyDefaultsConfig",
		"UpstreamConfig", "UpstreamTLSConfig", "UpstreamHealthConfig",
		"RouteConfig", "ProxyHeadersConfig", "ProxyRetryConfig",
		"EgressListenersConfig", "EgressListenerConfig", "EgressDefaultsConfig",
		"EgressTargetConfig", "EgressAuthConfig", "EgressTLSConfig",
		"EgressRetryConfig", "EgressRouteConfig", "EgressTokenStoreConfig",
		"EgressRedisConfig", "LegacyEgressEndpoint",
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
	return []SchemaType{
		SchemaTypeEnvironment,
		SchemaTypeServices,
		SchemaTypeRules,
	}
}

// ParseSchemaType parses a string to SchemaType.
func ParseSchemaType(s string) (SchemaType, bool) {
	switch strings.ToLower(s) {
	case "rules":
		return SchemaTypeRules, true
	case "environment":
		return SchemaTypeEnvironment, true
	case "services":
		return SchemaTypeServices, true
	default:
		return "", false
	}
}
