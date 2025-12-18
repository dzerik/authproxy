// Package help provides help text generation including environment variable documentation.
package help

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

// EnvVar represents a single environment variable with its documentation.
type EnvVar struct {
	Name        string // Full env var name (e.g., AUTHZ_SERVER_HTTP_ADDR)
	ConfigPath  string // Config path (e.g., server.http.addr)
	Type        string // Go type name
	Description string // Description from jsonschema tag
	Default     string // Default value if specified
	Required    bool   // Whether the field is required
	Example     string // Example value if specified
}

// EnvVarExtractor extracts environment variables documentation from config structs.
type EnvVarExtractor struct {
	prefix string
	vars   []EnvVar
}

// NewEnvVarExtractor creates a new extractor with the given env var prefix.
func NewEnvVarExtractor(prefix string) *EnvVarExtractor {
	return &EnvVarExtractor{
		prefix: prefix,
		vars:   make([]EnvVar, 0),
	}
}

// Extract extracts environment variables from a config struct.
func (e *EnvVarExtractor) Extract(cfg interface{}) []EnvVar {
	e.vars = make([]EnvVar, 0)
	e.extractFromType(reflect.TypeOf(cfg), "")

	// Sort by name for consistent output
	sort.Slice(e.vars, func(i, j int) bool {
		return e.vars[i].Name < e.vars[j].Name
	})

	return e.vars
}

// extractFromType recursively extracts env vars from a struct type.
func (e *EnvVarExtractor) extractFromType(t reflect.Type, prefix string) {
	// Handle pointer types
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	if t.Kind() != reflect.Struct {
		return
	}

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		// Skip unexported fields
		if !field.IsExported() {
			continue
		}

		// Get mapstructure tag for config path
		mapTag := field.Tag.Get("mapstructure")
		if mapTag == "" || mapTag == "-" {
			continue
		}

		// Build full config path
		configPath := mapTag
		if prefix != "" {
			configPath = prefix + "." + mapTag
		}

		// Get jsonschema tag for description
		jsonSchemaTag := field.Tag.Get("jsonschema")

		fieldType := field.Type
		// Handle pointer types
		if fieldType.Kind() == reflect.Ptr {
			fieldType = fieldType.Elem()
		}

		// For nested structs, recurse
		if fieldType.Kind() == reflect.Struct && !isBasicType(fieldType) {
			e.extractFromType(fieldType, configPath)
			continue
		}

		// For maps with struct values, recurse into the value type
		if fieldType.Kind() == reflect.Map {
			valueType := fieldType.Elem()
			if valueType.Kind() == reflect.Ptr {
				valueType = valueType.Elem()
			}
			if valueType.Kind() == reflect.Struct && !isBasicType(valueType) {
				// Add a note that this is a map
				e.addEnvVar(configPath, fieldType, jsonSchemaTag, true)
				// Extract from the value struct type with placeholder
				e.extractFromType(valueType, configPath+".<name>")
				continue
			}
		}

		// For slices of structs, recurse
		if fieldType.Kind() == reflect.Slice {
			elemType := fieldType.Elem()
			if elemType.Kind() == reflect.Ptr {
				elemType = elemType.Elem()
			}
			if elemType.Kind() == reflect.Struct && !isBasicType(elemType) {
				e.addEnvVar(configPath, fieldType, jsonSchemaTag, true)
				e.extractFromType(elemType, configPath+".<index>")
				continue
			}
		}

		// Add the env var
		e.addEnvVar(configPath, fieldType, jsonSchemaTag, false)
	}
}

// addEnvVar adds an environment variable to the list.
func (e *EnvVarExtractor) addEnvVar(configPath string, fieldType reflect.Type, jsonSchemaTag string, isCollection bool) {
	envName := e.configPathToEnvVar(configPath)

	ev := EnvVar{
		Name:       envName,
		ConfigPath: configPath,
		Type:       formatTypeName(fieldType, isCollection),
	}

	// Parse jsonschema tag
	if jsonSchemaTag != "" {
		ev.Description = parseJSONSchemaTag(jsonSchemaTag, "description")
		ev.Default = parseJSONSchemaTag(jsonSchemaTag, "default")
		ev.Example = parseJSONSchemaTag(jsonSchemaTag, "example")
		ev.Required = strings.Contains(jsonSchemaTag, "required")
	}

	e.vars = append(e.vars, ev)
}

// configPathToEnvVar converts a config path to an environment variable name.
func (e *EnvVarExtractor) configPathToEnvVar(configPath string) string {
	// Replace dots and special chars with underscores
	envName := strings.ReplaceAll(configPath, ".", "_")
	envName = strings.ReplaceAll(envName, "<name>", "NAME")
	envName = strings.ReplaceAll(envName, "<index>", "N")
	envName = strings.ToUpper(envName)

	if e.prefix != "" {
		return e.prefix + "_" + envName
	}
	return envName
}

// parseJSONSchemaTag extracts a specific field from jsonschema tag.
func parseJSONSchemaTag(tag, field string) string {
	// Pattern: field=value or field=value,
	pattern := regexp.MustCompile(field + `=([^,]+)`)
	matches := pattern.FindStringSubmatch(tag)
	if len(matches) > 1 {
		// Unescape commas
		value := strings.ReplaceAll(matches[1], `\,`, ",")
		return strings.TrimSpace(value)
	}
	return ""
}

// isBasicType checks if a type is a basic/primitive type (not a custom struct).
func isBasicType(t reflect.Type) bool {
	// time.Duration and time.Time are considered basic types
	if t.PkgPath() == "time" {
		return true
	}
	// Check for basic kinds
	switch t.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64, reflect.String:
		return true
	}
	return false
}

// formatTypeName returns a human-readable type name.
func formatTypeName(t reflect.Type, isCollection bool) string {
	switch t.Kind() {
	case reflect.Bool:
		return "bool"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if t.String() == "time.Duration" {
			return "duration"
		}
		return "int"
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "uint"
	case reflect.Float32, reflect.Float64:
		return "float"
	case reflect.String:
		return "string"
	case reflect.Slice:
		elemType := formatTypeName(t.Elem(), false)
		return "[]" + elemType
	case reflect.Map:
		return "map"
	default:
		return t.String()
	}
}

// FormatEnvVarsTable formats environment variables as a table.
func FormatEnvVarsTable(vars []EnvVar, maxWidth int) string {
	if len(vars) == 0 {
		return ""
	}

	var sb strings.Builder

	// Calculate column widths
	maxEnvLen := 0
	maxTypeLen := 0
	for _, v := range vars {
		if len(v.Name) > maxEnvLen {
			maxEnvLen = len(v.Name)
		}
		if len(v.Type) > maxTypeLen {
			maxTypeLen = len(v.Type)
		}
	}

	// Cap max lengths
	if maxEnvLen > 45 {
		maxEnvLen = 45
	}
	if maxTypeLen > 10 {
		maxTypeLen = 10
	}

	// Header
	sb.WriteString(fmt.Sprintf("    %-*s  %-*s  %s\n", maxEnvLen, "Environment Variable", maxTypeLen, "Type", "Description"))
	sb.WriteString(fmt.Sprintf("    %s  %s  %s\n", strings.Repeat("-", maxEnvLen), strings.Repeat("-", maxTypeLen), strings.Repeat("-", 40)))

	// Rows
	for _, v := range vars {
		envName := v.Name
		if len(envName) > maxEnvLen {
			envName = envName[:maxEnvLen-3] + "..."
		}

		typeName := v.Type
		if len(typeName) > maxTypeLen {
			typeName = typeName[:maxTypeLen-3] + "..."
		}

		desc := v.Description
		if v.Default != "" {
			desc += fmt.Sprintf(" [default: %s]", v.Default)
		}
		if v.Required {
			desc += " (required)"
		}

		// Wrap description if needed
		descWidth := maxWidth - maxEnvLen - maxTypeLen - 8
		if descWidth < 20 {
			descWidth = 40
		}
		wrappedDesc := wrapText(desc, descWidth)
		descLines := strings.Split(wrappedDesc, "\n")

		sb.WriteString(fmt.Sprintf("    %-*s  %-*s  %s\n", maxEnvLen, envName, maxTypeLen, typeName, descLines[0]))
		for i := 1; i < len(descLines); i++ {
			sb.WriteString(fmt.Sprintf("    %-*s  %-*s  %s\n", maxEnvLen, "", maxTypeLen, "", descLines[i]))
		}
	}

	return sb.String()
}

// FormatEnvVarsGrouped formats environment variables grouped by section.
func FormatEnvVarsGrouped(vars []EnvVar) string {
	if len(vars) == 0 {
		return ""
	}

	// Group by top-level section
	groups := make(map[string][]EnvVar)
	groupOrder := make([]string, 0)

	for _, v := range vars {
		// Extract top-level section from config path
		section := strings.Split(v.ConfigPath, ".")[0]
		if _, exists := groups[section]; !exists {
			groupOrder = append(groupOrder, section)
		}
		groups[section] = append(groups[section], v)
	}

	var sb strings.Builder

	for _, section := range groupOrder {
		sectionVars := groups[section]
		sectionTitle := strings.ToUpper(section[:1]) + section[1:]

		sb.WriteString(fmt.Sprintf("\n    [%s]\n", sectionTitle))

		for _, v := range sectionVars {
			sb.WriteString(fmt.Sprintf("      %s\n", v.Name))
			if v.Description != "" {
				// Indent description
				desc := wrapText(v.Description, 70)
				for _, line := range strings.Split(desc, "\n") {
					sb.WriteString(fmt.Sprintf("        %s\n", line))
				}
			}
			if v.Default != "" {
				sb.WriteString(fmt.Sprintf("        Default: %s\n", v.Default))
			}
			if v.Example != "" {
				sb.WriteString(fmt.Sprintf("        Example: %s\n", v.Example))
			}
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

// wrapText wraps text at the specified width.
func wrapText(text string, width int) string {
	if width <= 0 || len(text) <= width {
		return text
	}

	var result strings.Builder
	words := strings.Fields(text)
	lineLen := 0

	for i, word := range words {
		if i > 0 {
			if lineLen+1+len(word) > width {
				result.WriteString("\n")
				lineLen = 0
			} else {
				result.WriteString(" ")
				lineLen++
			}
		}
		result.WriteString(word)
		lineLen += len(word)
	}

	return result.String()
}
