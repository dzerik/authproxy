package nginx

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTemplateFuncs(t *testing.T) {
	funcs := templateFuncs()

	t.Run("default", func(t *testing.T) {
		defFunc := funcs["default"].(func(interface{}, interface{}) interface{})

		// Return default when value is nil
		result := defFunc("default", nil)
		assert.Equal(t, "default", result)

		// Return default when value is empty string
		result = defFunc("default", "")
		assert.Equal(t, "default", result)

		// Return default when value is 0
		result = defFunc("default", 0)
		assert.Equal(t, "default", result)

		// Return value when value is set
		result = defFunc("default", "actual")
		assert.Equal(t, "actual", result)

		// Return value when value is non-zero number
		result = defFunc(10, 42)
		assert.Equal(t, 42, result)
	})

	t.Run("replace", func(t *testing.T) {
		replaceFunc := funcs["replace"].(func(string, string, string) string)

		result := replaceFunc("-", "_", "my-service-name")
		assert.Equal(t, "my_service_name", result)

		result = replaceFunc("old", "new", "old value old")
		assert.Equal(t, "new value new", result)
	})

	t.Run("join", func(t *testing.T) {
		joinFunc := funcs["join"].(func(string, []string) string)

		result := joinFunc(",", []string{"a", "b", "c"})
		assert.Equal(t, "a,b,c", result)

		result = joinFunc(" ", []string{"hello", "world"})
		assert.Equal(t, "hello world", result)

		result = joinFunc(",", []string{})
		assert.Equal(t, "", result)
	})

	t.Run("contains", func(t *testing.T) {
		containsFunc := funcs["contains"].(func(string, string) bool)

		assert.True(t, containsFunc("hello world", "world"))
		assert.False(t, containsFunc("hello world", "foo"))
		assert.True(t, containsFunc("hello", ""))
	})

	t.Run("hasPrefix", func(t *testing.T) {
		hasPrefixFunc := funcs["hasPrefix"].(func(string, string) bool)

		assert.True(t, hasPrefixFunc("hello world", "hello"))
		assert.False(t, hasPrefixFunc("hello world", "world"))
	})

	t.Run("hasSuffix", func(t *testing.T) {
		hasSuffixFunc := funcs["hasSuffix"].(func(string, string) bool)

		assert.True(t, hasSuffixFunc("hello world", "world"))
		assert.False(t, hasSuffixFunc("hello world", "hello"))
	})

	t.Run("lower", func(t *testing.T) {
		lowerFunc := funcs["lower"].(func(string) string)

		result := lowerFunc("HELLO World")
		assert.Equal(t, "hello world", result)
	})

	t.Run("upper", func(t *testing.T) {
		upperFunc := funcs["upper"].(func(string) string)

		result := upperFunc("hello World")
		assert.Equal(t, "HELLO WORLD", result)
	})

	t.Run("trim", func(t *testing.T) {
		trimFunc := funcs["trim"].(func(string) string)

		result := trimFunc("  hello world  ")
		assert.Equal(t, "hello world", result)

		result = trimFunc("\t\nhello\n\t")
		assert.Equal(t, "hello", result)
	})

	t.Run("quote", func(t *testing.T) {
		quoteFunc := funcs["quote"].(func(string) string)

		result := quoteFunc("hello")
		assert.Equal(t, "\"hello\"", result)

		result = quoteFunc("hello \"world\"")
		assert.Contains(t, result, "\\\"")
	})

	t.Run("printf", func(t *testing.T) {
		printfFunc := funcs["printf"].(func(string, ...interface{}) string)

		result := printfFunc("Hello, %s!", "World")
		assert.Equal(t, "Hello, World!", result)

		result = printfFunc("%d + %d = %d", 1, 2, 3)
		assert.Equal(t, "1 + 2 = 3", result)
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
		require.NoError(t, err)
		require.NotNil(t, g)
		assert.Equal(t, cfg, g.config)
		assert.Equal(t, "/tmp/nginx", g.outputDir)
	})

	t.Run("empty output dir", func(t *testing.T) {
		g, err := NewGenerator(cfg, "")
		require.NoError(t, err)
		assert.Equal(t, "", g.outputDir)
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
	require.NoError(t, err)

	content, err := g.Generate()
	require.NoError(t, err)

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
			assert.Contains(t, content, check.expected)
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
	require.NoError(t, err)

	content, err := g.Generate()
	require.NoError(t, err)

	// Check service-specific configurations
	t.Run("service with auth", func(t *testing.T) {
		assert.Contains(t, content, "service_one_backend")
		assert.Contains(t, content, "location /one/")
		assert.Contains(t, content, "auth_request /_auth")
	})

	t.Run("service with rewrite", func(t *testing.T) {
		assert.Contains(t, content, "rewrite ^/one/(.*) /$1 break")
	})

	t.Run("service with custom headers", func(t *testing.T) {
		assert.Contains(t, content, "proxy_set_header X-Custom")
	})

	t.Run("service with removed headers", func(t *testing.T) {
		// Check for Cookie header removal (set to empty)
		assert.Contains(t, content, "proxy_set_header Cookie \"\"")
	})

	t.Run("service with nginx extra", func(t *testing.T) {
		assert.Contains(t, content, "proxy_buffering off")
	})

	t.Run("public service without auth", func(t *testing.T) {
		assert.Contains(t, content, "location /public/")
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
	require.NoError(t, err)

	content, err := g.Generate()
	require.NoError(t, err)

	checks := []string{
		"listen 443 ssl http2",
		"ssl_certificate /etc/ssl/cert.pem",
		"ssl_certificate_key /etc/ssl/key.pem",
		"ssl_protocols TLSv1.2 TLSv1.3",
	}

	for _, check := range checks {
		assert.Contains(t, content, check)
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
	require.NoError(t, err)

	content, err := g.Generate()
	require.NoError(t, err)

	assert.Contains(t, content, "limit_req_zone")
	assert.Contains(t, content, "zone=auth_limit:20m")
	assert.Contains(t, content, "rate=100r/s")
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
	require.NoError(t, err)

	content, err := g.Generate()
	require.NoError(t, err)

	assert.Contains(t, content, "location /custom-metrics")
}

func TestGenerator_GenerateToFile(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTPPort: 8081,
		},
	}

	tmpDir := t.TempDir()
	g, err := NewGenerator(cfg, tmpDir)
	require.NoError(t, err)

	outputPath := filepath.Join(tmpDir, "nginx.conf")
	err = g.GenerateToFile(outputPath)
	require.NoError(t, err)

	// Check file exists
	_, err = os.Stat(outputPath)
	assert.False(t, os.IsNotExist(err))

	// Check file content
	content, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	assert.Contains(t, string(content), "worker_processes")
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
	require.NoError(t, err)

	outputPath := filepath.Join(nestedDir, "nginx.conf")
	err = g.GenerateToFile(outputPath)
	require.NoError(t, err)

	// Check nested directory was created
	_, err = os.Stat(nestedDir)
	assert.False(t, os.IsNotExist(err))

	// Check file exists
	_, err = os.Stat(outputPath)
	assert.False(t, os.IsNotExist(err))
}

func TestGenerator_GetOutputPath(t *testing.T) {
	cfg := &config.Config{}

	t.Run("with custom output dir", func(t *testing.T) {
		g, err := NewGenerator(cfg, "/custom/path")
		require.NoError(t, err)

		path := g.GetOutputPath()
		assert.Equal(t, "/custom/path/nginx.conf", path)
	})

	t.Run("with empty output dir", func(t *testing.T) {
		g, err := NewGenerator(cfg, "")
		require.NoError(t, err)

		path := g.GetOutputPath()
		assert.Equal(t, "/etc/nginx/nginx.conf", path)
	})
}

func TestTemplateData_AuthRequired(t *testing.T) {
	data := TemplateData{Config: &config.Config{}}

	assert.True(t, data.AuthRequired(true))
	assert.False(t, data.AuthRequired(false))
}

func TestGenerator_MustGenerate(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTPPort: 8081,
		},
	}

	g, err := NewGenerator(cfg, "")
	require.NoError(t, err)

	// Should not panic with valid config
	content := g.MustGenerate()
	assert.NotEmpty(t, content)
	assert.Contains(t, content, "worker_processes")
}

func TestGenerator_Generate_DefaultValues(t *testing.T) {
	// Minimal config to test default values
	cfg := &config.Config{}

	g, err := NewGenerator(cfg, "")
	require.NoError(t, err)

	content, err := g.Generate()
	require.NoError(t, err)

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
			assert.Contains(t, content, d.expected)
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
	require.NoError(t, err)

	content, err := g.Generate()
	require.NoError(t, err)

	assert.Contains(t, content, "log_format custom")
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
