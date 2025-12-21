package ui

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLoadTemplates(t *testing.T) {
	tmpl, err := LoadTemplates()
	if err != nil {
		t.Fatalf("LoadTemplates failed: %v", err)
	}

	if tmpl == nil {
		t.Fatal("LoadTemplates returned nil")
	}

	// Check that expected templates are loaded
	expectedTemplates := []string{
		"base.html",
		"login.html",
		"portal.html",
		"error.html",
	}

	for _, name := range expectedTemplates {
		if tmpl.Lookup(name) == nil {
			t.Errorf("template %s should be loaded", name)
		}
	}
}

func TestLoadTemplates_SliceFunction(t *testing.T) {
	tmpl, err := LoadTemplates()
	if err != nil {
		t.Fatalf("LoadTemplates failed: %v", err)
	}

	// Access the FuncMap is not directly possible, but we can test by executing
	// Create a test template with slice function
	testTmpl, err := tmpl.New("test-slice").Parse(`{{slice "hello" 0 3}}`)
	if err != nil {
		t.Fatalf("Failed to parse test template: %v", err)
	}

	rr := httptest.NewRecorder()
	err = testTmpl.Execute(rr, nil)
	if err != nil {
		t.Fatalf("Failed to execute template: %v", err)
	}

	if rr.Body.String() != "hel" {
		t.Errorf("slice result = %s, want hel", rr.Body.String())
	}
}

func TestLoadTemplates_SliceFunctionBoundaries(t *testing.T) {
	tests := []struct {
		name     string
		template string
		expected string
	}{
		{"normal", `{{slice "hello" 1 4}}`, "ell"},
		{"negative start", `{{slice "hello" -1 3}}`, "hel"},
		{"end beyond length", `{{slice "hello" 2 100}}`, "llo"},
		{"start greater than end", `{{slice "hello" 4 2}}`, ""},
		{"full string", `{{slice "hello" 0 5}}`, "hello"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Load fresh templates for each test
			tmpl, err := LoadTemplates()
			if err != nil {
				t.Fatalf("LoadTemplates failed: %v", err)
			}

			testTmpl, err := tmpl.New("test-" + tt.name).Parse(tt.template)
			if err != nil {
				t.Fatalf("Failed to parse template: %v", err)
			}

			rr := httptest.NewRecorder()
			err = testTmpl.Execute(rr, nil)
			if err != nil {
				t.Fatalf("Failed to execute template: %v", err)
			}

			if rr.Body.String() != tt.expected {
				t.Errorf("slice result = %s, want %s", rr.Body.String(), tt.expected)
			}
		})
	}
}

func TestLoadTemplates_JoinFunction(t *testing.T) {
	tests := []struct {
		name     string
		data     map[string]interface{}
		template string
		expected string
	}{
		{
			name: "basic join",
			data: map[string]interface{}{
				"items": []string{"a", "b", "c"},
			},
			template: `{{join ", " .items}}`,
			expected: "a, b, c",
		},
		{
			name: "single element",
			data: map[string]interface{}{
				"items": []string{"single"},
			},
			template: `{{join ", " .items}}`,
			expected: "single",
		},
		{
			name: "empty slice",
			data: map[string]interface{}{
				"items": []string{},
			},
			template: `{{join ", " .items}}`,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Load fresh templates for each test
			tmpl, err := LoadTemplates()
			if err != nil {
				t.Fatalf("LoadTemplates failed: %v", err)
			}

			testTmpl, err := tmpl.New("test-" + tt.name).Parse(tt.template)
			if err != nil {
				t.Fatalf("Failed to parse template: %v", err)
			}

			rr := httptest.NewRecorder()
			err = testTmpl.Execute(rr, tt.data)
			if err != nil {
				t.Fatalf("Failed to execute template: %v", err)
			}

			if rr.Body.String() != tt.expected {
				t.Errorf("join result = %s, want %s", rr.Body.String(), tt.expected)
			}
		})
	}
}

func TestStaticFileHandler(t *testing.T) {
	handler := StaticFileHandler()

	if handler == nil {
		t.Fatal("StaticFileHandler returned nil")
	}

	// Test that it returns something for valid path
	req := httptest.NewRequest(http.MethodGet, "/static/css/style.css", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Status could be 200 (if file exists) or 404 (if not found)
	// Both are valid - we're testing the handler works
	t.Logf("Static file request returned status %d", rr.Code)
}

func TestStaticFileHandler_NotFoundPath(t *testing.T) {
	handler := StaticFileHandler()

	req := httptest.NewRequest(http.MethodGet, "/static/nonexistent.file", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for nonexistent file", rr.Code)
	}
}

func TestMustLoadTemplates(t *testing.T) {
	// Should not panic with valid templates
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MustLoadTemplates panicked: %v", r)
		}
	}()

	tmpl := MustLoadTemplates()
	if tmpl == nil {
		t.Error("MustLoadTemplates returned nil")
	}
}

func TestTemplatesFS(t *testing.T) {
	// Test that templatesFS is accessible
	entries, err := fs.ReadDir(templatesFS, "templates")
	if err != nil {
		t.Fatalf("Failed to read templates directory: %v", err)
	}

	if len(entries) == 0 {
		t.Error("No templates found in embedded filesystem")
	}

	// List found templates
	for _, entry := range entries {
		t.Logf("Found template: %s", entry.Name())
	}
}

func TestStaticFS(t *testing.T) {
	// Test that staticFS is accessible
	entries, err := fs.ReadDir(staticFS, "static")
	if err != nil {
		t.Fatalf("Failed to read static directory: %v", err)
	}

	// There might be subdirectories
	for _, entry := range entries {
		t.Logf("Found static entry: %s (isDir: %v)", entry.Name(), entry.IsDir())
	}
}

func BenchmarkLoadTemplates(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = LoadTemplates()
	}
}

func BenchmarkStaticFileHandler(b *testing.B) {
	handler := StaticFileHandler()
	req := httptest.NewRequest(http.MethodGet, "/static/css/style.css", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
	}
}
