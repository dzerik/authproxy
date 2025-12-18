// Package body provides request body extraction and validation for authorization rules.
// WARNING: This feature has security and performance implications.
// Body is buffered in memory and requires JSON validation.
package body

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/pkg/logger"
)

// Common errors for body extraction.
var (
	ErrBodyTooLarge       = errors.New("request body exceeds maximum size")
	ErrInvalidContentType = errors.New("invalid or missing content type")
	ErrInvalidJSON        = errors.New("request body is not valid JSON")
	ErrMethodNotAllowed   = errors.New("body access not allowed for this method")
	ErrPathNotAllowed     = errors.New("body access not allowed for this path")
	ErrSchemaValidation   = errors.New("request body does not match schema")
)

// Extractor extracts and validates request body for authorization rules.
type Extractor struct {
	cfg           config.RequestBodyConfig
	schemaCache   map[string]*jsonSchema
	schemaCacheMu sync.RWMutex
}

// jsonSchema represents a loaded JSON Schema for validation.
type jsonSchema struct {
	raw      map[string]any
	required []string
	notFound bool // true if schema file was not found (negative cache)
}

// NewExtractor creates a new body extractor.
func NewExtractor(cfg config.RequestBodyConfig) *Extractor {
	e := &Extractor{
		cfg:         cfg,
		schemaCache: make(map[string]*jsonSchema),
	}

	return e
}

// Extract reads and validates the request body.
// Returns the parsed JSON as map[string]any, or nil if body access is not applicable.
// The body is restored to the request so it can be read again by downstream handlers.
func (e *Extractor) Extract(r *http.Request) (map[string]any, error) {
	if !e.cfg.Enabled {
		return nil, nil
	}

	// Check if method is allowed
	if !e.isMethodAllowed(r.Method) {
		return nil, nil // Not an error, just skip body access
	}

	// Check if path is allowed
	if !e.isPathAllowed(r.URL.Path) {
		return nil, nil // Not an error, just skip body access
	}

	// Check if body is present
	if r.Body == nil || r.ContentLength == 0 {
		return nil, nil
	}

	// Validate content type
	contentType := r.Header.Get("Content-Type")
	if e.cfg.RequireContentType && contentType == "" {
		return nil, ErrInvalidContentType
	}

	if !e.isContentTypeAllowed(contentType) {
		return nil, ErrInvalidContentType
	}

	// Check body size
	if r.ContentLength > e.cfg.MaxSize {
		return nil, ErrBodyTooLarge
	}

	// Read body with size limit
	limitedReader := io.LimitReader(r.Body, e.cfg.MaxSize+1)
	bodyBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	// Check if we hit the limit
	if int64(len(bodyBytes)) > e.cfg.MaxSize {
		return nil, ErrBodyTooLarge
	}

	// Restore body for downstream handlers
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Parse JSON
	var body map[string]any
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		// Try to parse as array - if it's an array, wrap it
		var bodyArray []any
		if arrErr := json.Unmarshal(bodyBytes, &bodyArray); arrErr == nil {
			body = map[string]any{
				"_array": bodyArray,
				"_type":  "array",
			}
		} else {
			logger.Debug("failed to parse body as JSON",
				logger.String("error", err.Error()),
				logger.String("path", r.URL.Path),
			)
			return nil, ErrInvalidJSON
		}
	}

	// Validate against schema if enabled
	if e.cfg.Schema.Enabled {
		if err := e.validateSchema(r.Method, r.URL.Path, body); err != nil {
			return nil, err
		}
	}

	return body, nil
}

// isMethodAllowed checks if body access is allowed for this HTTP method.
func (e *Extractor) isMethodAllowed(method string) bool {
	if len(e.cfg.Methods) == 0 {
		// Default: POST, PUT, PATCH
		return method == "POST" || method == "PUT" || method == "PATCH"
	}

	for _, m := range e.cfg.Methods {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

// isPathAllowed checks if body access is allowed for this path.
func (e *Extractor) isPathAllowed(path string) bool {
	if len(e.cfg.Paths) == 0 {
		return true // All paths allowed
	}

	for _, pattern := range e.cfg.Paths {
		if matched, _ := filepath.Match(pattern, path); matched {
			return true
		}
		// Try glob-style matching with ** support
		if matchGlob(pattern, path) {
			return true
		}
	}
	return false
}

// isContentTypeAllowed checks if the content type is allowed.
func (e *Extractor) isContentTypeAllowed(contentType string) bool {
	if contentType == "" {
		return !e.cfg.RequireContentType
	}

	// Extract media type (ignore parameters like charset)
	mediaType := strings.Split(contentType, ";")[0]
	mediaType = strings.TrimSpace(strings.ToLower(mediaType))

	allowedTypes := e.cfg.AllowedContentTypes
	if len(allowedTypes) == 0 {
		allowedTypes = []string{"application/json"}
	}

	for _, allowed := range allowedTypes {
		if strings.EqualFold(strings.TrimSpace(allowed), mediaType) {
			return true
		}
	}
	return false
}

// validateSchema validates the body against JSON Schema.
func (e *Extractor) validateSchema(method, path string, body map[string]any) error {
	schema, err := e.getSchema(method, path)
	if err != nil {
		if e.cfg.Schema.StrictValidation {
			return fmt.Errorf("%w: %v", ErrSchemaValidation, err)
		}
		// No schema found, pass validation
		return nil
	}

	if schema == nil {
		return nil
	}

	// Basic schema validation
	if err := e.validateAgainstSchema(body, schema); err != nil {
		return fmt.Errorf("%w: %v", ErrSchemaValidation, err)
	}

	return nil
}

// getSchema loads schema from cache or file.
// Uses negative caching to avoid repeated file reads for non-existent schemas.
func (e *Extractor) getSchema(method, path string) (*jsonSchema, error) {
	// Build schema key: path/method.json
	// /api/v1/users POST -> /api/v1/users/POST.json
	cleanPath := strings.Trim(path, "/")
	schemaKey := fmt.Sprintf("%s/%s", cleanPath, strings.ToUpper(method))

	// Check cache (including negative cache)
	e.schemaCacheMu.RLock()
	if schema, ok := e.schemaCache[schemaKey]; ok {
		e.schemaCacheMu.RUnlock()
		if schema.notFound {
			// Negative cache hit - schema file doesn't exist
			return nil, fmt.Errorf("schema not found (cached): %s", schemaKey)
		}
		return schema, nil
	}
	e.schemaCacheMu.RUnlock()

	// Load from file
	schemaPath := filepath.Join(e.cfg.Schema.SchemaDir, cleanPath, strings.ToUpper(method)+".json")
	schema, err := loadSchemaFile(schemaPath)
	if err != nil {
		// Try without method suffix
		schemaPath = filepath.Join(e.cfg.Schema.SchemaDir, cleanPath+".json")
		schema, err = loadSchemaFile(schemaPath)
		if err != nil {
			// Cache negative result to avoid repeated file reads
			e.schemaCacheMu.Lock()
			e.schemaCache[schemaKey] = &jsonSchema{notFound: true}
			e.schemaCacheMu.Unlock()
			return nil, err
		}
	}

	// Cache positive result
	e.schemaCacheMu.Lock()
	e.schemaCache[schemaKey] = schema
	e.schemaCacheMu.Unlock()

	return schema, nil
}

// loadSchemaFile loads a JSON Schema from file.
func loadSchemaFile(path string) (*jsonSchema, error) {
	// For simplicity, we just load the raw JSON
	// In production, you might want to use a proper JSON Schema library
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid schema JSON: %w", err)
	}

	schema := &jsonSchema{raw: raw}

	// Extract required fields
	if required, ok := raw["required"].([]any); ok {
		for _, r := range required {
			if s, ok := r.(string); ok {
				schema.required = append(schema.required, s)
			}
		}
	}

	return schema, nil
}

// validateAgainstSchema performs basic JSON Schema validation.
// This is a simplified implementation. For full JSON Schema support,
// use a library like github.com/santhosh-tekuri/jsonschema.
func (e *Extractor) validateAgainstSchema(body map[string]any, schema *jsonSchema) error {
	// Check required fields
	for _, field := range schema.required {
		if _, ok := body[field]; !ok {
			return fmt.Errorf("missing required field: %s", field)
		}
	}

	// Check properties if defined
	if properties, ok := schema.raw["properties"].(map[string]any); ok {
		for key, value := range body {
			propSchema, exists := properties[key]
			if !exists && !e.cfg.Schema.AllowAdditionalProperties {
				// Check additionalProperties in schema
				if ap, ok := schema.raw["additionalProperties"].(bool); ok && !ap {
					return fmt.Errorf("additional property not allowed: %s", key)
				}
			}

			if exists {
				if err := e.validateProperty(key, value, propSchema); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// validateProperty validates a single property against its schema.
func (e *Extractor) validateProperty(name string, value any, propSchema any) error {
	schema, ok := propSchema.(map[string]any)
	if !ok {
		return nil
	}

	expectedType, _ := schema["type"].(string)
	if expectedType == "" {
		return nil
	}

	// Type validation
	switch expectedType {
	case "string":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("field %s: expected string, got %T", name, value)
		}
	case "number", "integer":
		switch value.(type) {
		case float64, int, int64:
			// OK
		default:
			return fmt.Errorf("field %s: expected number, got %T", name, value)
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("field %s: expected boolean, got %T", name, value)
		}
	case "array":
		if _, ok := value.([]any); !ok {
			return fmt.Errorf("field %s: expected array, got %T", name, value)
		}
	case "object":
		if _, ok := value.(map[string]any); !ok {
			return fmt.Errorf("field %s: expected object, got %T", name, value)
		}
	}

	return nil
}

// matchGlob matches a path against a glob pattern with ** support.
func matchGlob(pattern, path string) bool {
	// Simple ** support
	if strings.Contains(pattern, "**") {
		// Split by **
		parts := strings.Split(pattern, "**")
		if len(parts) == 2 {
			prefix := strings.TrimSuffix(parts[0], "/")
			suffix := strings.TrimPrefix(parts[1], "/")

			hasPrefix := prefix == "" || strings.HasPrefix(path, prefix)
			hasSuffix := suffix == "" || strings.HasSuffix(path, suffix)

			return hasPrefix && hasSuffix
		}
	}

	// Try standard glob
	matched, _ := filepath.Match(pattern, path)
	return matched
}

// readFile reads a file - abstracted for testing.
var readFile = func(path string) ([]byte, error) {
	return readFileFromDisk(path)
}

func readFileFromDisk(path string) ([]byte, error) {
	file, err := openFile(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return io.ReadAll(file)
}

// openFile is a variable for testing.
var openFile = func(path string) (io.ReadCloser, error) {
	return os.Open(path)
}

// Enabled returns true if body extraction is enabled.
func (e *Extractor) Enabled() bool {
	return e.cfg.Enabled
}

// Config returns the extractor configuration.
func (e *Extractor) Config() config.RequestBodyConfig {
	return e.cfg
}

// ClearSchemaCache clears the schema cache.
func (e *Extractor) ClearSchemaCache() {
	e.schemaCacheMu.Lock()
	e.schemaCache = make(map[string]*jsonSchema)
	e.schemaCacheMu.Unlock()
}
