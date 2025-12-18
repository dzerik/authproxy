package body

import (
	"bytes"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/your-org/authz-service/internal/config"
)

func TestExtractor_Extract(t *testing.T) {
	tests := []struct {
		name        string
		cfg         config.RequestBodyConfig
		method      string
		path        string
		contentType string
		body        string
		wantBody    map[string]any
		wantErr     error
	}{
		{
			name: "disabled returns nil",
			cfg: config.RequestBodyConfig{
				Enabled: false,
			},
			method:      "POST",
			path:        "/api/users",
			contentType: "application/json",
			body:        `{"name": "test"}`,
			wantBody:    nil,
			wantErr:     nil,
		},
		{
			name: "GET method skipped by default",
			cfg: config.RequestBodyConfig{
				Enabled: true,
				MaxSize: 1024,
			},
			method:      "GET",
			path:        "/api/users",
			contentType: "application/json",
			body:        `{"name": "test"}`,
			wantBody:    nil,
			wantErr:     nil,
		},
		{
			name: "POST method allowed by default",
			cfg: config.RequestBodyConfig{
				Enabled:             true,
				MaxSize:             1024,
				AllowedContentTypes: []string{"application/json"},
			},
			method:      "POST",
			path:        "/api/users",
			contentType: "application/json",
			body:        `{"name": "test", "age": 25}`,
			wantBody:    map[string]any{"name": "test", "age": float64(25)},
			wantErr:     nil,
		},
		{
			name: "PUT method allowed by default",
			cfg: config.RequestBodyConfig{
				Enabled:             true,
				MaxSize:             1024,
				AllowedContentTypes: []string{"application/json"},
			},
			method:      "PUT",
			path:        "/api/users/123",
			contentType: "application/json",
			body:        `{"name": "updated"}`,
			wantBody:    map[string]any{"name": "updated"},
			wantErr:     nil,
		},
		{
			name: "PATCH method allowed by default",
			cfg: config.RequestBodyConfig{
				Enabled:             true,
				MaxSize:             1024,
				AllowedContentTypes: []string{"application/json"},
			},
			method:      "PATCH",
			path:        "/api/users/123",
			contentType: "application/json",
			body:        `{"name": "patched"}`,
			wantBody:    map[string]any{"name": "patched"},
			wantErr:     nil,
		},
		{
			name: "custom method list",
			cfg: config.RequestBodyConfig{
				Enabled:             true,
				MaxSize:             1024,
				Methods:             []string{"POST", "DELETE"},
				AllowedContentTypes: []string{"application/json"},
			},
			method:      "DELETE",
			path:        "/api/users/123",
			contentType: "application/json",
			body:        `{"reason": "test"}`,
			wantBody:    map[string]any{"reason": "test"},
			wantErr:     nil,
		},
		{
			name: "method not in custom list",
			cfg: config.RequestBodyConfig{
				Enabled:             true,
				MaxSize:             1024,
				Methods:             []string{"POST"},
				AllowedContentTypes: []string{"application/json"},
			},
			method:      "PUT",
			path:        "/api/users/123",
			contentType: "application/json",
			body:        `{"name": "test"}`,
			wantBody:    nil,
			wantErr:     nil,
		},
		{
			name: "path not allowed",
			cfg: config.RequestBodyConfig{
				Enabled:             true,
				MaxSize:             1024,
				Paths:               []string{"/api/admin/**"},
				AllowedContentTypes: []string{"application/json"},
			},
			method:      "POST",
			path:        "/api/users",
			contentType: "application/json",
			body:        `{"name": "test"}`,
			wantBody:    nil,
			wantErr:     nil,
		},
		{
			name: "path allowed with glob",
			cfg: config.RequestBodyConfig{
				Enabled:             true,
				MaxSize:             1024,
				Paths:               []string{"/api/**"},
				AllowedContentTypes: []string{"application/json"},
			},
			method:      "POST",
			path:        "/api/users/create",
			contentType: "application/json",
			body:        `{"name": "test"}`,
			wantBody:    map[string]any{"name": "test"},
			wantErr:     nil,
		},
		{
			name: "invalid JSON returns error",
			cfg: config.RequestBodyConfig{
				Enabled:             true,
				MaxSize:             1024,
				AllowedContentTypes: []string{"application/json"},
			},
			method:      "POST",
			path:        "/api/users",
			contentType: "application/json",
			body:        `{invalid json}`,
			wantBody:    nil,
			wantErr:     ErrInvalidJSON,
		},
		{
			name: "body too large",
			cfg: config.RequestBodyConfig{
				Enabled:             true,
				MaxSize:             10,
				AllowedContentTypes: []string{"application/json"},
			},
			method:      "POST",
			path:        "/api/users",
			contentType: "application/json",
			body:        `{"name": "this is a very long string that exceeds the limit"}`,
			wantBody:    nil,
			wantErr:     ErrBodyTooLarge,
		},
		{
			name: "wrong content type",
			cfg: config.RequestBodyConfig{
				Enabled:             true,
				MaxSize:             1024,
				AllowedContentTypes: []string{"application/json"},
			},
			method:      "POST",
			path:        "/api/users",
			contentType: "text/plain",
			body:        `{"name": "test"}`,
			wantBody:    nil,
			wantErr:     ErrInvalidContentType,
		},
		{
			name: "missing content type when required",
			cfg: config.RequestBodyConfig{
				Enabled:            true,
				MaxSize:            1024,
				RequireContentType: true,
			},
			method:   "POST",
			path:     "/api/users",
			body:     `{"name": "test"}`,
			wantBody: nil,
			wantErr:  ErrInvalidContentType,
		},
		{
			name: "content type with charset",
			cfg: config.RequestBodyConfig{
				Enabled:             true,
				MaxSize:             1024,
				AllowedContentTypes: []string{"application/json"},
			},
			method:      "POST",
			path:        "/api/users",
			contentType: "application/json; charset=utf-8",
			body:        `{"name": "test"}`,
			wantBody:    map[string]any{"name": "test"},
			wantErr:     nil,
		},
		{
			name: "array body wrapped",
			cfg: config.RequestBodyConfig{
				Enabled:             true,
				MaxSize:             1024,
				AllowedContentTypes: []string{"application/json"},
			},
			method:      "POST",
			path:        "/api/users/batch",
			contentType: "application/json",
			body:        `[{"name": "user1"}, {"name": "user2"}]`,
			wantBody: map[string]any{
				"_array": []any{
					map[string]any{"name": "user1"},
					map[string]any{"name": "user2"},
				},
				"_type": "array",
			},
			wantErr: nil,
		},
		{
			name: "empty body returns nil",
			cfg: config.RequestBodyConfig{
				Enabled:             true,
				MaxSize:             1024,
				AllowedContentTypes: []string{"application/json"},
			},
			method:      "POST",
			path:        "/api/users",
			contentType: "application/json",
			body:        "",
			wantBody:    nil,
			wantErr:     nil,
		},
		{
			name: "nested JSON object",
			cfg: config.RequestBodyConfig{
				Enabled:             true,
				MaxSize:             1024,
				AllowedContentTypes: []string{"application/json"},
			},
			method:      "POST",
			path:        "/api/users",
			contentType: "application/json",
			body:        `{"user": {"name": "test", "address": {"city": "Moscow"}}}`,
			wantBody: map[string]any{
				"user": map[string]any{
					"name": "test",
					"address": map[string]any{
						"city": "Moscow",
					},
				},
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := NewExtractor(tt.cfg)

			req := httptest.NewRequest(tt.method, tt.path, bytes.NewBufferString(tt.body))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			if tt.body != "" {
				req.ContentLength = int64(len(tt.body))
			}

			gotBody, err := extractor.Extract(req)

			// Check error
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("Extract() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("Extract() unexpected error = %v", err)
				return
			}

			// Check body
			if tt.wantBody == nil {
				if gotBody != nil {
					t.Errorf("Extract() = %v, want nil", gotBody)
				}
				return
			}

			// Deep compare body values
			if !compareBody(gotBody, tt.wantBody) {
				t.Errorf("Extract() = %v, want %v", gotBody, tt.wantBody)
			}

			// Verify body is restored for downstream handlers
			if tt.body != "" && gotBody != nil {
				restoredBody, _ := io.ReadAll(req.Body)
				if string(restoredBody) != tt.body {
					t.Errorf("Body not restored: got %q, want %q", string(restoredBody), tt.body)
				}
			}
		})
	}
}

func TestExtractor_Enabled(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
		want    bool
	}{
		{"enabled", true, true},
		{"disabled", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewExtractor(config.RequestBodyConfig{Enabled: tt.enabled})
			if got := e.Enabled(); got != tt.want {
				t.Errorf("Enabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractor_Config(t *testing.T) {
	cfg := config.RequestBodyConfig{
		Enabled: true,
		MaxSize: 2048,
	}
	e := NewExtractor(cfg)

	got := e.Config()
	if got.Enabled != cfg.Enabled || got.MaxSize != cfg.MaxSize {
		t.Errorf("Config() returned wrong config")
	}
}

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"/api/**", "/api/users", true},
		{"/api/**", "/api/users/123", true},
		{"/api/**", "/other/path", false},
		{"**/users", "/api/v1/users", true},
		{"/api/*/users", "/api/v1/users", true},
		{"/api/*/users", "/api/v1/v2/users", false},
		{"/exact/path", "/exact/path", true},
		{"/exact/path", "/exact/other", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.path, func(t *testing.T) {
			if got := matchGlob(tt.pattern, tt.path); got != tt.want {
				t.Errorf("matchGlob(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
			}
		})
	}
}

func TestExtractor_isMethodAllowed(t *testing.T) {
	tests := []struct {
		name    string
		methods []string
		method  string
		want    bool
	}{
		{"default POST allowed", nil, "POST", true},
		{"default PUT allowed", nil, "PUT", true},
		{"default PATCH allowed", nil, "PATCH", true},
		{"default GET not allowed", nil, "GET", false},
		{"default DELETE not allowed", nil, "DELETE", false},
		{"custom list includes", []string{"GET", "DELETE"}, "DELETE", true},
		{"custom list excludes", []string{"GET"}, "POST", false},
		{"case insensitive", []string{"post"}, "POST", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewExtractor(config.RequestBodyConfig{Methods: tt.methods})
			if got := e.isMethodAllowed(tt.method); got != tt.want {
				t.Errorf("isMethodAllowed(%q) = %v, want %v", tt.method, got, tt.want)
			}
		})
	}
}

func TestExtractor_isContentTypeAllowed(t *testing.T) {
	tests := []struct {
		name         string
		allowedTypes []string
		contentType  string
		require      bool
		want         bool
	}{
		{"default json allowed", nil, "application/json", false, true},
		{"default other not allowed", nil, "text/plain", false, false},
		{"empty when not required", nil, "", false, true},
		{"empty when required", nil, "", true, false},
		{"with charset", nil, "application/json; charset=utf-8", false, true},
		{"custom type allowed", []string{"text/plain"}, "text/plain", false, true},
		{"custom type not allowed", []string{"text/plain"}, "application/json", false, false},
		{"multiple custom types", []string{"application/json", "text/plain"}, "text/plain", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewExtractor(config.RequestBodyConfig{
				AllowedContentTypes: tt.allowedTypes,
				RequireContentType:  tt.require,
			})
			if got := e.isContentTypeAllowed(tt.contentType); got != tt.want {
				t.Errorf("isContentTypeAllowed(%q) = %v, want %v", tt.contentType, got, tt.want)
			}
		})
	}
}

func TestExtractor_ClearSchemaCache(t *testing.T) {
	e := NewExtractor(config.RequestBodyConfig{Enabled: true})

	// Add something to cache manually
	e.schemaCacheMu.Lock()
	e.schemaCache["test"] = &jsonSchema{}
	e.schemaCacheMu.Unlock()

	// Clear cache
	e.ClearSchemaCache()

	// Check it's empty
	e.schemaCacheMu.RLock()
	if len(e.schemaCache) != 0 {
		t.Errorf("ClearSchemaCache() did not clear cache, got %d items", len(e.schemaCache))
	}
	e.schemaCacheMu.RUnlock()
}

func TestExtractor_SchemaNegativeCache(t *testing.T) {
	// Test that non-existent schemas are cached (negative caching)
	cfg := config.RequestBodyConfig{
		Enabled: true,
		Schema: config.RequestBodySchemaConfig{
			Enabled:   true,
			SchemaDir: "/nonexistent/schemas",
		},
	}
	e := NewExtractor(cfg)

	// First call should try to load file (and fail)
	schema1, err1 := e.getSchema("POST", "/api/test")
	if err1 == nil {
		t.Error("Expected error for non-existent schema")
	}
	if schema1 != nil {
		t.Error("Expected nil schema for non-existent file")
	}

	// Check that negative result was cached
	e.schemaCacheMu.RLock()
	cachedSchema, exists := e.schemaCache["api/test/POST"]
	e.schemaCacheMu.RUnlock()

	if !exists {
		t.Error("Expected schema to be in cache")
	}
	if cachedSchema != nil && !cachedSchema.notFound {
		t.Error("Expected notFound flag to be true in cached schema")
	}

	// Second call should return cached negative result
	schema2, err2 := e.getSchema("POST", "/api/test")
	if err2 == nil {
		t.Error("Expected error from negative cache")
	}
	if schema2 != nil {
		t.Error("Expected nil schema from negative cache")
	}
}

// compareBody performs a deep comparison of two body maps
func compareBody(got, want map[string]any) bool {
	if len(got) != len(want) {
		return false
	}
	for k, wantV := range want {
		gotV, ok := got[k]
		if !ok {
			return false
		}

		switch wv := wantV.(type) {
		case map[string]any:
			gv, ok := gotV.(map[string]any)
			if !ok || !compareBody(gv, wv) {
				return false
			}
		case []any:
			gv, ok := gotV.([]any)
			if !ok || len(gv) != len(wv) {
				return false
			}
			for i := range wv {
				wItem, wIsMap := wv[i].(map[string]any)
				gItem, gIsMap := gv[i].(map[string]any)
				if wIsMap && gIsMap {
					if !compareBody(gItem, wItem) {
						return false
					}
				} else if wv[i] != gv[i] {
					return false
				}
			}
		default:
			if gotV != wantV {
				return false
			}
		}
	}
	return true
}
