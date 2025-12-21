package nginx

import (
	"bytes"
	"embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/dzerik/auth-portal/internal/config"
)

//go:embed templates/*
var templatesFS embed.FS

// Generator generates nginx configuration from templates
type Generator struct {
	config    *config.Config
	templates *template.Template
	outputDir string
}

// NewGenerator creates a new nginx config generator
func NewGenerator(cfg *config.Config, outputDir string) (*Generator, error) {
	// Create template with custom functions
	tmpl := template.New("nginx").Funcs(templateFuncs())

	// Load embedded templates
	entries, err := templatesFS.ReadDir("templates")
	if err != nil {
		return nil, fmt.Errorf("failed to read templates directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		content, err := templatesFS.ReadFile("templates/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("failed to read template %s: %w", entry.Name(), err)
		}

		_, err = tmpl.New(entry.Name()).Parse(string(content))
		if err != nil {
			return nil, fmt.Errorf("failed to parse template %s: %w", entry.Name(), err)
		}
	}

	return &Generator{
		config:    cfg,
		templates: tmpl,
		outputDir: outputDir,
	}, nil
}

// templateFuncs returns custom template functions
func templateFuncs() template.FuncMap {
	return template.FuncMap{
		// Default value
		"default": func(def interface{}, val interface{}) interface{} {
			if val == nil || val == "" || val == 0 {
				return def
			}
			return val
		},

		// String replace
		"replace": func(old, new, s string) string {
			return strings.ReplaceAll(s, old, new)
		},

		// Join strings
		"join": func(sep string, s []string) string {
			return strings.Join(s, sep)
		},

		// Contains check
		"contains": func(s, substr string) bool {
			return strings.Contains(s, substr)
		},

		// HasPrefix check
		"hasPrefix": func(s, prefix string) bool {
			return strings.HasPrefix(s, prefix)
		},

		// HasSuffix check
		"hasSuffix": func(s, suffix string) bool {
			return strings.HasSuffix(s, suffix)
		},

		// ToLower
		"lower": strings.ToLower,

		// ToUpper
		"upper": strings.ToUpper,

		// Trim whitespace
		"trim": strings.TrimSpace,

		// Quote string
		"quote": func(s string) string {
			return fmt.Sprintf("%q", s)
		},

		// Printf
		"printf": fmt.Sprintf,
	}
}

// TemplateData represents data passed to templates
type TemplateData struct {
	*config.Config
}

// AuthRequired checks if auth is required (helper for templates)
func (t TemplateData) AuthRequired(serviceAuthRequired bool) bool {
	return serviceAuthRequired
}

// Generate generates the nginx configuration
func (g *Generator) Generate() (string, error) {
	data := TemplateData{Config: g.config}

	var buf bytes.Buffer
	if err := g.templates.ExecuteTemplate(&buf, "nginx.conf.tmpl", data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// GenerateToFile generates nginx config and writes to file
func (g *Generator) GenerateToFile(filename string) error {
	content, err := g.Generate()
	if err != nil {
		return err
	}

	// Ensure output directory exists
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Write to file
	if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write file %s: %w", filename, err)
	}

	return nil
}

// GenerateAndValidate generates config and validates with nginx -t
func (g *Generator) GenerateAndValidate(filename string) error {
	if err := g.GenerateToFile(filename); err != nil {
		return err
	}

	return g.Validate(filename)
}

// Validate validates nginx configuration file
func (g *Generator) Validate(filename string) error {
	cmd := exec.Command("nginx", "-t", "-c", filename)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx config validation failed: %s\n%s", err, string(output))
	}
	return nil
}

// GetOutputPath returns the default output path for nginx config
func (g *Generator) GetOutputPath() string {
	if g.outputDir != "" {
		return filepath.Join(g.outputDir, "nginx.conf")
	}
	return "/etc/nginx/nginx.conf"
}

// MustGenerate generates config or panics
func (g *Generator) MustGenerate() string {
	content, err := g.Generate()
	if err != nil {
		panic(err)
	}
	return content
}
