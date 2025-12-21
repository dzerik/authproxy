package nginx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dzerik/auth-portal/internal/config"
)

func TestTemplateFuncs(t *testing.T) {
	funcs := templateFuncs()

	t.Run("default", func(t *testing.T) {
		defFunc := funcs["default"].(func(interface{}, interface{}) interface{})

		// Return default when value is nil
		if result := defFunc("default", nil); result != "default" {
			t.Errorf("default(\"default\", nil) = %v, want \"default\"", result)
		}

		// Return default when value is empty string
		if result := defFunc("default", ""); result != "default" {
			t.Errorf("default(\"default\", \"\") = %v, want \"default\"", result)
		}

		// Return default when value is 0
		if result := defFunc("default", 0); result != "default" {
			t.Errorf("default(\"default\", 0) = %v, want \"default\"", result)
		}

		// Return value when value is set
		if result := defFunc("default", "actual"); result != "actual" {
			t.Errorf("default(\"default\", \"actual\") = %v, want \"actual\"", result)
		}

		// Return value when value is non-zero number
		if result := defFunc(10, 42); result != 42 {
			t.Errorf("default(10, 42) = %v, want 42", result)
		}
	})

	t.Run("replace", func(t *testing.T) {
		replaceFunc := funcs["replace"].(func(string, string, string) string)

		result := replaceFunc("-", "_", "my-service-name")
		if result != "my_service_name" {
			t.Errorf("replace(\"-\", \"_\", \"my-service-name\") = %s, want \"my_service_name\"", result)
		}

		result = replaceFunc("old", "new", "old value old")
		if result != "new value new" {
			t.Errorf("replace(\"old\", \"new\", \"old value old\") = %s, want \"new value new\"", result)
		}
	})

	t.Run("join", func(t *testing.T) {
		joinFunc := funcs["join"].(func(string, []string) string)

		result := joinFunc(",", []string{"a", "b", "c"})
		if result != "a,b,c" {
			t.Errorf("join(\",\", [\"a\", \"b\", \"c\"]) = %s, want \"a,b,c\"", result)
		}

		result = joinFunc(" ", []string{"hello", "world"})
		if result != "hello world" {
			t.Errorf("join(\" \", [\"hello\", \"world\"]) = %s, want \"hello world\"", result)
		}

		result = joinFunc(",", []string{})
		if result != "" {
			t.Errorf("join(\",\", []) = %s, want \"\"", result)
		}
	})

	t.Run("contains", func(t *testing.T) {
		containsFunc := funcs["contains"].(func(string, string) bool)

		if !containsFunc("hello world", "world") {
			t.Error("contains(\"hello world\", \"world\") should be true")
		}

		if containsFunc("hello world", "foo") {
			t.Error("contains(\"hello world\", \"foo\") should be false")
		}

		if !containsFunc("hello", "") {
			t.Error("contains(\"hello\", \"\") should be true")
		}
	})

	t.Run("hasPrefix", func(t *testing.T) {
		hasPrefixFunc := funcs["hasPrefix"].(func(string, string) bool)

		if !hasPrefixFunc("hello world", "hello") {
			t.Error("hasPrefix(\"hello world\", \"hello\") should be true")
		}

		if hasPrefixFunc("hello world", "world") {
			t.Error("hasPrefix(\"hello world\", \"world\") should be false")
		}
	})

	t.Run("hasSuffix", func(t *testing.T) {
		hasSuffixFunc := funcs["hasSuffix"].(func(string, string) bool)

		if !hasSuffixFunc("hello world", "world") {
			t.Error("hasSuffix(\"hello world\", \"world\") should be true")
		}

		if hasSuffixFunc("hello world", "hello") {
			t.Error("hasSuffix(\"hello world\", \"hello\") should be false")
		}
	})

	t.Run("lower", func(t *testing.T) {
		lowerFunc := funcs["lower"].(func(string) string)

		result := lowerFunc("HELLO World")
		if result != "hello world" {
			t.Errorf("lower(\"HELLO World\") = %s, want \"hello world\"", result)
		}
	})

	t.Run("upper", func(t *testing.T) {
		upperFunc := funcs["upper"].(func(string) string)

		result := upperFunc("hello World")
		if result != "HELLO WORLD" {
			t.Errorf("upper(\"hello World\") = %s, want \"HELLO WORLD\"", result)
		}
	})

	t.Run("trim", func(t *testing.T) {
		trimFunc := funcs["trim"].(func(string) string)

		result := trimFunc("  hello world  ")
		if result != "hello world" {
			t.Errorf("trim(\"  hello world  \") = %s, want \"hello world\"", result)
		}

		result = trimFunc("\t\nhello\n\t")
		if result != "hello" {
			t.Errorf("trim(\"\\t\\nhello\\n\\t\") = %s, want \"hello\"", result)
		}
	})

	t.Run("quote", func(t *testing.T) {
		quoteFunc := funcs["quote"].(func(string) string)

		result := quoteFunc("hello")
		if result != "\"hello\"" {
			t.Errorf("quote(\"hello\") = %s, want \"\\\"hello\\\"\"", result)
		}

		result = quoteFunc("hello \"world\"")
		if !strings.Contains(result, "\\\"") {
			t.Errorf("quote should escape inner quotes: %s", result)
		}
	})

	t.Run("printf", func(t *testing.T) {
		printfFunc := funcs["printf"].(func(string, ...interface{}) string)

		result := printfFunc("Hello, %s!", "World")
		if result != "Hello, World!" {
			t.Errorf("printf(\"Hello, %%s!\", \"World\") = %s, want \"Hello, World!\"", result)
		}

		result = printfFunc("%d + %d = %d", 1, 2, 3)
		if result != "1 + 2 = 3" {
			t.Errorf("printf(\"%%d + %%d = %%d\", 1, 2, 3) = %s, want \"1 + 2 = 3\"", result)
		}
	})
}

func TestNewGenerator(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTPPort: 8080,
		},
		Nginx: config.NginxConfig{
			WorkerProcesses:   "auto",
			WorkerConnections: 1024,
			KeepaliveTimeout:  65,
		},
	}

	t.Run("valid config", func(t *testing.T) {
		g, err := NewGenerator(cfg, "/tmp/nginx")
		if err != nil {
			t.Fatalf("NewGenerator failed: %v", err)
		}
		if g == nil {
			t.Fatal("NewGenerator returned nil")
		}
		if g.config != cfg {
			t.Error("config not set correctly")
		}
		if g.outputDir != "/tmp/nginx" {
			t.Errorf("outputDir = %s, want /tmp/nginx", g.outputDir)
		}
	})

	t.Run("empty output dir", func(t *testing.T) {
		g, err := NewGenerator(cfg, "")
		if err != nil {
			t.Fatalf("NewGenerator failed: %v", err)
		}
		if g.outputDir != "" {
			t.Errorf("outputDir = %s, want empty", g.outputDir)
		}
	})
}

func TestGenerator_Generate(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTPPort: 8081,
		},
		Nginx: config.NginxConfig{
			WorkerProcesses:   "auto",
			WorkerConnections: 1024,
			KeepaliveTimeout:  65,
			ClientMaxBodySize: "10m",
		},
		Services: []config.ServiceConfig{
			{
				Name:         "grafana",
				Location:     "/grafana/",
				Upstream:     "grafana:3000",
				AuthRequired: true,
			},
		},
	}

	g, err := NewGenerator(cfg, "")
	if err != nil {
		t.Fatalf("NewGenerator failed: %v", err)
	}

	content, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Check that essential parts are present
	checks := []struct {
		name     string
		expected string
	}{
		{"worker_processes", "worker_processes auto"},
		{"worker_connections", "worker_connections 1024"},
		{"keepalive_timeout", "keepalive_timeout 65"},
		{"client_max_body_size", "client_max_body_size 10m"},
		{"auth_portal upstream", "upstream auth_portal"},
		{"server 127.0.0.1:8081", "server 127.0.0.1:8081"},
		{"grafana upstream", "upstream grafana_backend"},
		{"grafana location", "location /grafana/"},
		{"auth_request", "auth_request /_auth"},
	}

	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if !strings.Contains(content, check.expected) {
				t.Errorf("Generated config should contain %q", check.expected)
			}
		})
	}
}

func TestGenerator_Generate_WithServices(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTPPort: 8081,
		},
		Services: []config.ServiceConfig{
			{
				Name:         "service-one",
				Location:     "/one/",
				Upstream:     "service-one:8080",
				AuthRequired: true,
				Rewrite:      "^/one/(.*) /$1 break",
				Headers: config.HeadersConfig{
					Add:    map[string]string{"X-Custom": "value"},
					Remove: []string{"Cookie"},
				},
				NginxExtra: "proxy_buffering off;",
			},
			{
				Name:         "public-service",
				Location:     "/public/",
				Upstream:     "public:80",
				AuthRequired: false,
			},
		},
	}

	g, err := NewGenerator(cfg, "")
	if err != nil {
		t.Fatalf("NewGenerator failed: %v", err)
	}

	content, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Check service-specific configurations
	t.Run("service with auth", func(t *testing.T) {
		if !strings.Contains(content, "service_one_backend") {
			t.Error("should contain service_one_backend upstream")
		}
		if !strings.Contains(content, "location /one/") {
			t.Error("should contain /one/ location")
		}
		if !strings.Contains(content, "auth_request /_auth") {
			t.Error("should contain auth_request for authenticated service")
		}
	})

	t.Run("service with rewrite", func(t *testing.T) {
		if !strings.Contains(content, "rewrite ^/one/(.*) /$1 break") {
			t.Error("should contain rewrite rule")
		}
	})

	t.Run("service with custom headers", func(t *testing.T) {
		if !strings.Contains(content, "proxy_set_header X-Custom") {
			t.Error("should contain custom header")
		}
	})

	t.Run("service with removed headers", func(t *testing.T) {
		// Check for Cookie header removal (set to empty)
		if !strings.Contains(content, "proxy_set_header Cookie \"\"") {
			t.Error("should contain Cookie header removal")
		}
	})

	t.Run("service with nginx extra", func(t *testing.T) {
		if !strings.Contains(content, "proxy_buffering off") {
			t.Error("should contain nginx extra config")
		}
	})

	t.Run("public service without auth", func(t *testing.T) {
		if !strings.Contains(content, "location /public/") {
			t.Error("should contain /public/ location")
		}
	})
}

func TestGenerator_Generate_WithTLS(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTPPort: 8081,
			TLS: config.TLSConfig{
				Enabled: true,
				Cert:    "/etc/ssl/cert.pem",
				Key:     "/etc/ssl/key.pem",
			},
		},
	}

	g, err := NewGenerator(cfg, "")
	if err != nil {
		t.Fatalf("NewGenerator failed: %v", err)
	}

	content, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	checks := []string{
		"listen 443 ssl http2",
		"ssl_certificate /etc/ssl/cert.pem",
		"ssl_certificate_key /etc/ssl/key.pem",
		"ssl_protocols TLSv1.2 TLSv1.3",
	}

	for _, check := range checks {
		if !strings.Contains(content, check) {
			t.Errorf("TLS config should contain %q", check)
		}
	}
}

func TestGenerator_Generate_WithRateLimit(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTPPort: 8081,
		},
		Nginx: config.NginxConfig{
			RateLimit: config.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				ZoneSize:          "20m",
			},
		},
	}

	g, err := NewGenerator(cfg, "")
	if err != nil {
		t.Fatalf("NewGenerator failed: %v", err)
	}

	content, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if !strings.Contains(content, "limit_req_zone") {
		t.Error("should contain limit_req_zone")
	}
	if !strings.Contains(content, "zone=auth_limit:20m") {
		t.Error("should contain zone size 20m")
	}
	if !strings.Contains(content, "rate=100r/s") {
		t.Error("should contain rate 100r/s")
	}
}

func TestGenerator_Generate_WithMetrics(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTPPort: 8081,
		},
		Observability: config.ObservabilityConfig{
			Metrics: config.MetricsConfig{
				Enabled: true,
				Path:    "/custom-metrics",
			},
		},
	}

	g, err := NewGenerator(cfg, "")
	if err != nil {
		t.Fatalf("NewGenerator failed: %v", err)
	}

	content, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if !strings.Contains(content, "location /custom-metrics") {
		t.Error("should contain custom metrics path")
	}
}

func TestGenerator_GenerateToFile(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTPPort: 8081,
		},
	}

	tmpDir := t.TempDir()
	g, err := NewGenerator(cfg, tmpDir)
	if err != nil {
		t.Fatalf("NewGenerator failed: %v", err)
	}

	outputPath := filepath.Join(tmpDir, "nginx.conf")
	err = g.GenerateToFile(outputPath)
	if err != nil {
		t.Fatalf("GenerateToFile failed: %v", err)
	}

	// Check file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("output file should exist")
	}

	// Check file content
	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	if !strings.Contains(string(content), "worker_processes") {
		t.Error("file should contain valid nginx config")
	}
}

func TestGenerator_GenerateToFile_CreatesDirectory(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTPPort: 8081,
		},
	}

	tmpDir := t.TempDir()
	nestedDir := filepath.Join(tmpDir, "nested", "dir")
	g, err := NewGenerator(cfg, nestedDir)
	if err != nil {
		t.Fatalf("NewGenerator failed: %v", err)
	}

	outputPath := filepath.Join(nestedDir, "nginx.conf")
	err = g.GenerateToFile(outputPath)
	if err != nil {
		t.Fatalf("GenerateToFile failed: %v", err)
	}

	// Check nested directory was created
	if _, err := os.Stat(nestedDir); os.IsNotExist(err) {
		t.Error("nested directory should be created")
	}

	// Check file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("output file should exist")
	}
}

func TestGenerator_GetOutputPath(t *testing.T) {
	cfg := &config.Config{}

	t.Run("with custom output dir", func(t *testing.T) {
		g, err := NewGenerator(cfg, "/custom/path")
		if err != nil {
			t.Fatalf("NewGenerator failed: %v", err)
		}

		path := g.GetOutputPath()
		expected := "/custom/path/nginx.conf"
		if path != expected {
			t.Errorf("GetOutputPath() = %s, want %s", path, expected)
		}
	})

	t.Run("with empty output dir", func(t *testing.T) {
		g, err := NewGenerator(cfg, "")
		if err != nil {
			t.Fatalf("NewGenerator failed: %v", err)
		}

		path := g.GetOutputPath()
		expected := "/etc/nginx/nginx.conf"
		if path != expected {
			t.Errorf("GetOutputPath() = %s, want %s", path, expected)
		}
	})
}

func TestTemplateData_AuthRequired(t *testing.T) {
	data := TemplateData{Config: &config.Config{}}

	if !data.AuthRequired(true) {
		t.Error("AuthRequired(true) should return true")
	}

	if data.AuthRequired(false) {
		t.Error("AuthRequired(false) should return false")
	}
}

func TestGenerator_MustGenerate(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTPPort: 8081,
		},
	}

	g, err := NewGenerator(cfg, "")
	if err != nil {
		t.Fatalf("NewGenerator failed: %v", err)
	}

	// Should not panic with valid config
	content := g.MustGenerate()
	if content == "" {
		t.Error("MustGenerate should return non-empty content")
	}

	if !strings.Contains(content, "worker_processes") {
		t.Error("MustGenerate should return valid nginx config")
	}
}

func TestGenerator_Generate_DefaultValues(t *testing.T) {
	// Minimal config to test default values
	cfg := &config.Config{}

	g, err := NewGenerator(cfg, "")
	if err != nil {
		t.Fatalf("NewGenerator failed: %v", err)
	}

	content, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Check default values are applied
	defaults := []struct {
		name     string
		expected string
	}{
		{"worker_processes", "worker_processes auto"},
		{"worker_connections", "worker_connections 1024"},
		{"keepalive_timeout", "keepalive_timeout 65"},
		{"client_max_body_size", "client_max_body_size 10m"},
		{"error_log", "/var/log/nginx/error.log"},
		{"access_log", "/var/log/nginx/access.log"},
	}

	for _, d := range defaults {
		t.Run(d.name, func(t *testing.T) {
			if !strings.Contains(content, d.expected) {
				t.Errorf("config should contain default %s: %s", d.name, d.expected)
			}
		})
	}
}

func TestGenerator_Generate_CustomLogFormat(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTPPort: 8081,
		},
		Nginx: config.NginxConfig{
			LogFormat: "$remote_addr - $request",
		},
	}

	g, err := NewGenerator(cfg, "")
	if err != nil {
		t.Fatalf("NewGenerator failed: %v", err)
	}

	content, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if !strings.Contains(content, "log_format custom") {
		t.Error("should contain custom log format")
	}
}

func BenchmarkGenerator_Generate(b *testing.B) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTPPort: 8081,
		},
		Nginx: config.NginxConfig{
			WorkerProcesses:   "auto",
			WorkerConnections: 1024,
		},
		Services: []config.ServiceConfig{
			{Name: "service1", Location: "/s1/", Upstream: "s1:8080", AuthRequired: true},
			{Name: "service2", Location: "/s2/", Upstream: "s2:8080", AuthRequired: true},
			{Name: "service3", Location: "/s3/", Upstream: "s3:8080", AuthRequired: false},
		},
	}

	g, _ := NewGenerator(cfg, "")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = g.Generate()
	}
}
