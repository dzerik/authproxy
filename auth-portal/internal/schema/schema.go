// Package schema provides JSON Schema generation for configuration.
package schema

import (
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"github.com/invopop/jsonschema"

	"github.com/dzerik/auth-portal/internal/config"
)

// SchemaType represents the type of schema to generate.
type SchemaType string

const (
	SchemaTypeConfig SchemaType = "config"
)

// Generator generates JSON schemas for auth-portal configuration files.
type Generator struct {
	reflector *jsonschema.Reflector
}

// NewGenerator creates a new schema generator.
func NewGenerator() *Generator {
	r := &jsonschema.Reflector{
		ExpandedStruct:             false,
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

// Generate generates a JSON schema for the config.
func (g *Generator) Generate() ([]byte, error) {
	schema := g.reflector.Reflect(&config.Config{})
	g.processSchema(schema)

	schema.Title = "Auth-Portal Configuration"
	schema.Description = "Configuration schema for auth-portal service.\n\n" +
		"Auth-portal provides authentication and authorization for web services."
	schema.ID = "https://github.com/dzerik/auth-portal/schemas/config.schema.json"

	// Add examples
	schema.Examples = []interface{}{
		map[string]interface{}{
			"mode": "portal",
			"server": map[string]interface{}{
				"http_port": 8080,
			},
			"auth": map[string]interface{}{
				"keycloak": map[string]interface{}{
					"issuer_url":    "https://keycloak.example.com/realms/main",
					"client_id":     "auth-portal",
					"client_secret": "${KC_CLIENT_SECRET}",
					"redirect_url":  "https://auth.example.com/callback",
				},
			},
			"session": map[string]interface{}{
				"store":       "cookie",
				"cookie_name": "_auth_session",
				"ttl":         "24h",
			},
		},
	}

	// Marshal with indentation
	data, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return nil, err
	}

	// Post-process to fix naming
	output := g.postProcessJSON(string(data))

	return []byte(output), nil
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
func (g *Generator) postProcessJSON(jsonStr string) string {
	typeNames := []string{
		"Config", "ServerConfig", "TLSConfig", "AutoCertConfig",
		"SingleServiceConfig", "AuthConfig", "KeycloakConfig", "SocialProvider",
		"SessionConfig", "EncryptionConfig", "CookieStoreConfig",
		"JWTStoreConfig", "RedisStoreConfig", "RedisTLSConfig",
		"TokenConfig", "ServiceConfig", "HeadersConfig",
		"DevModeConfig", "NginxConfig", "RateLimitConfig",
		"ObservabilityConfig", "MetricsConfig", "TracingConfig",
		"HealthConfig", "ReadyConfig", "LogConfig",
		"ResilienceConfig", "HTTPRateLimitConfig", "HTTPRateLimitHeadersConfig",
		"CircuitBreakerConfig", "CircuitBreakerSettings",
	}

	result := jsonStr

	for _, name := range typeNames {
		snake := toSnakeCase(name)
		result = strings.ReplaceAll(result, `"#/$defs/`+name+`"`, `"#/$defs/`+snake+`"`)
		result = strings.ReplaceAll(result, `"`+name+`":`, `"`+snake+`":`)
	}

	return result
}

// toSnakeCase converts PascalCase/camelCase to snake_case.
func toSnakeCase(s string) string {
	special := map[string]string{
		"HTTPServerConfig":  "http_server_config",
		"HTTPSPort":         "https_port",
		"HTTPPort":          "http_port",
		"TLSConfig":         "tls_config",
		"JWTStoreConfig":    "jwt_store_config",
		"RedisTLSConfig":    "redis_tls_config",
		"TTL":               "ttl",
		"URL":               "url",
		"ID":                "id",
		"JWT":               "jwt",
		"OIDC":              "oidc",
	}

	if val, ok := special[s]; ok {
		return val
	}

	var result strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			prev := rune(s[i-1])
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
			result.WriteRune(r + 32)
		} else {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// GetAvailableSchemas returns list of available schema types.
func GetAvailableSchemas() []SchemaType {
	return []SchemaType{
		SchemaTypeConfig,
	}
}

// ParseSchemaType parses a string to SchemaType.
func ParseSchemaType(s string) (SchemaType, bool) {
	switch strings.ToLower(s) {
	case "config":
		return SchemaTypeConfig, true
	default:
		return "", false
	}
}
