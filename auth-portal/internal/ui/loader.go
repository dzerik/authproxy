package ui

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"path/filepath"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

// LoadTemplates loads all HTML templates from embedded filesystem
func LoadTemplates() (*template.Template, error) {
	tmpl := template.New("")

	// Add custom template functions
	tmpl = tmpl.Funcs(template.FuncMap{
		"slice": func(s string, start, end int) string {
			if start < 0 {
				start = 0
			}
			if end > len(s) {
				end = len(s)
			}
			if start > end {
				return ""
			}
			return s[start:end]
		},
		"join": func(sep string, s []string) string {
			result := ""
			for i, v := range s {
				if i > 0 {
					result += sep
				}
				result += v
			}
			return result
		},
	})

	// Parse all templates
	entries, err := fs.ReadDir(templatesFS, "templates")
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		ext := filepath.Ext(name)
		if ext != ".html" {
			continue
		}

		content, err := fs.ReadFile(templatesFS, "templates/"+name)
		if err != nil {
			return nil, err
		}

		_, err = tmpl.New(name).Parse(string(content))
		if err != nil {
			return nil, err
		}
	}

	return tmpl, nil
}

// StaticFileHandler returns an HTTP handler for static files
func StaticFileHandler() http.Handler {
	// Strip the "static" prefix from the embedded filesystem
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return http.NotFoundHandler()
	}

	return http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
}

// MustLoadTemplates loads templates or panics
func MustLoadTemplates() *template.Template {
	tmpl, err := LoadTemplates()
	if err != nil {
		panic(err)
	}
	return tmpl
}
