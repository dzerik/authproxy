package config

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidationError_Error(t *testing.T) {
	err := ValidationError{
		Field:   "test.field",
		Message: "test message",
	}

	expected := "test.field: test message"
	assert.Equal(t, expected, err.Error())
}

func TestValidationErrors_Error(t *testing.T) {
	t.Run("empty errors", func(t *testing.T) {
		var errs ValidationErrors
		assert.Equal(t, "", errs.Error())
	})

	t.Run("single error", func(t *testing.T) {
		errs := ValidationErrors{
			{Field: "field1", Message: "message1"},
		}
		result := errs.Error()
		assert.Contains(t, result, "field1: message1")
	})

	t.Run("multiple errors", func(t *testing.T) {
		errs := ValidationErrors{
			{Field: "field1", Message: "message1"},
			{Field: "field2", Message: "message2"},
		}
		result := errs.Error()
		assert.Contains(t, result, "field1: message1")
		assert.Contains(t, result, "field2: message2")
	})
}

func TestValidate_Mode(t *testing.T) {
	tests := []struct {
		name      string
		mode      string
		expectErr bool
	}{
		{"valid portal", "portal", false},
		{"valid single-service", "single-service", false},
		{"invalid mode", "invalid", true},
		{"empty mode", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Mode = tt.mode

			// Set target_url for single-service mode
			if tt.mode == "single-service" {
				cfg.SingleService.TargetURL = "https://app.example.com"
			}

			err := Validate(cfg)
			hasErr := err != nil && containsField(err, "mode")

			if tt.expectErr {
				assert.True(t, hasErr, "expected mode validation error")
			} else {
				assert.False(t, hasErr, "unexpected mode validation error: %v", err)
			}
		})
	}
}

func TestValidate_SingleService(t *testing.T) {
	t.Run("single-service mode without target_url", func(t *testing.T) {
		cfg := validConfig()
		cfg.Mode = "single-service"
		cfg.SingleService.TargetURL = ""

		err := Validate(cfg)
		require.Error(t, err)
		assert.True(t, containsField(err, "single_service.target_url"), "expected single_service.target_url validation error")
	})

	t.Run("single-service mode with target_url", func(t *testing.T) {
		cfg := validConfig()
		cfg.Mode = "single-service"
		cfg.SingleService.TargetURL = "https://app.example.com"

		err := Validate(cfg)
		assert.False(t, containsField(err, "single_service.target_url"), "unexpected single_service.target_url validation error")
	})

	t.Run("portal mode without target_url is valid", func(t *testing.T) {
		cfg := validConfig()
		cfg.Mode = "portal"
		cfg.SingleService.TargetURL = ""

		err := Validate(cfg)
		assert.False(t, containsField(err, "single_service.target_url"), "single_service.target_url should not be required in portal mode")
	})
}

func TestValidate_Auth(t *testing.T) {
	t.Run("missing issuer_url", func(t *testing.T) {
		cfg := validConfig()
		cfg.Auth.Keycloak.IssuerURL = ""

		err := Validate(cfg)
		require.Error(t, err)
		assert.True(t, containsField(err, "auth.keycloak.issuer_url"), "expected auth.keycloak.issuer_url validation error")
	})

	t.Run("invalid issuer_url", func(t *testing.T) {
		cfg := validConfig()
		cfg.Auth.Keycloak.IssuerURL = "://invalid-url"

		err := Validate(cfg)
		require.Error(t, err)
		assert.True(t, containsField(err, "auth.keycloak.issuer_url"), "expected auth.keycloak.issuer_url validation error")
	})

	t.Run("missing client_id", func(t *testing.T) {
		cfg := validConfig()
		cfg.Auth.Keycloak.ClientID = ""

		err := Validate(cfg)
		require.Error(t, err)
		assert.True(t, containsField(err, "auth.keycloak.client_id"), "expected auth.keycloak.client_id validation error")
	})

	t.Run("missing client_secret", func(t *testing.T) {
		cfg := validConfig()
		cfg.Auth.Keycloak.ClientSecret = ""

		err := Validate(cfg)
		require.Error(t, err)
		assert.True(t, containsField(err, "auth.keycloak.client_secret"), "expected auth.keycloak.client_secret validation error")
	})

	t.Run("missing redirect_url", func(t *testing.T) {
		cfg := validConfig()
		cfg.Auth.Keycloak.RedirectURL = ""

		err := Validate(cfg)
		require.Error(t, err)
		assert.True(t, containsField(err, "auth.keycloak.redirect_url"), "expected auth.keycloak.redirect_url validation error")
	})

	t.Run("dev mode skips auth validation", func(t *testing.T) {
		cfg := validConfig()
		cfg.DevMode.Enabled = true
		cfg.DevMode.ProfilesDir = "./profiles"
		cfg.Auth.Keycloak.IssuerURL = ""
		cfg.Auth.Keycloak.ClientID = ""
		cfg.Auth.Keycloak.ClientSecret = ""
		cfg.Auth.Keycloak.RedirectURL = ""

		err := Validate(cfg)
		assert.False(t, containsField(err, "auth.keycloak"), "auth validation should be skipped in dev mode")
	})
}

func TestValidate_SessionStore(t *testing.T) {
	tests := []struct {
		name      string
		store     string
		expectErr bool
	}{
		{"valid cookie", "cookie", false},
		{"valid jwt", "jwt", false},
		{"valid redis", "redis", false},
		{"invalid store", "memcache", true},
		{"empty store", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Session.Store = tt.store

			// Add required fields for specific stores
			if tt.store == "jwt" {
				cfg.Session.JWT.SigningKey = "test-key"
			}
			if tt.store == "redis" {
				cfg.Session.Redis.Addresses = []string{"redis:6379"}
				cfg.Session.Encryption.Enabled = false
			}

			err := Validate(cfg)
			hasErr := containsField(err, "session.store")

			if tt.expectErr {
				assert.True(t, hasErr, "expected session.store validation error")
			} else {
				assert.False(t, hasErr, "unexpected session.store validation error: %v", err)
			}
		})
	}
}

func TestValidate_Encryption(t *testing.T) {
	t.Run("missing encryption key when enabled", func(t *testing.T) {
		cfg := validConfig()
		cfg.Session.Store = "cookie"
		cfg.Session.Encryption.Enabled = true
		cfg.Session.Encryption.Key = ""

		err := Validate(cfg)
		require.Error(t, err)
		assert.True(t, containsField(err, "session.encryption.key"), "expected session.encryption.key validation error")
	})

	t.Run("wrong key length", func(t *testing.T) {
		cfg := validConfig()
		cfg.Session.Store = "cookie"
		cfg.Session.Encryption.Enabled = true
		cfg.Session.Encryption.Key = "short-key"

		err := Validate(cfg)
		require.Error(t, err)
		assert.True(t, containsField(err, "session.encryption.key"), "expected session.encryption.key validation error for wrong length")
	})

	t.Run("valid 32-byte key", func(t *testing.T) {
		cfg := validConfig()
		cfg.Session.Store = "cookie"
		cfg.Session.Encryption.Enabled = true
		cfg.Session.Encryption.Key = "abcdefghijklmnopqrstuvwxyz!@#$%^" // 32 bytes, not valid base64

		err := Validate(cfg)
		assert.False(t, containsField(err, "session.encryption.key"), "unexpected session.encryption.key validation error: %v", err)
	})

	t.Run("encryption disabled skips key validation", func(t *testing.T) {
		cfg := validConfig()
		cfg.Session.Store = "cookie"
		cfg.Session.Encryption.Enabled = false
		cfg.Session.Encryption.Key = ""

		err := Validate(cfg)
		assert.False(t, containsField(err, "session.encryption.key"), "encryption.key should not be required when disabled")
	})

	t.Run("valid base64-encoded 32-byte key", func(t *testing.T) {
		cfg := validConfig()
		cfg.Session.Store = "cookie"
		cfg.Session.Encryption.Enabled = true
		// Generate a proper 32-byte key and encode as base64 (44 chars)
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i)
		}
		cfg.Session.Encryption.Key = base64.StdEncoding.EncodeToString(key)

		err := Validate(cfg)
		assert.False(t, containsField(err, "session.encryption.key"), "base64-encoded 32-byte key should be valid: %v", err)
	})

	t.Run("invalid base64-encoded key - wrong length after decoding", func(t *testing.T) {
		cfg := validConfig()
		cfg.Session.Store = "cookie"
		cfg.Session.Encryption.Enabled = true
		// 24-byte key encoded as base64 (decodes to 24 bytes, not 32)
		key := make([]byte, 24)
		cfg.Session.Encryption.Key = base64.StdEncoding.EncodeToString(key)

		err := Validate(cfg)
		require.Error(t, err)
		assert.True(t, containsField(err, "session.encryption.key"), "base64 key decoding to wrong length should fail validation")
	})
}

func TestValidateEncryptionKeyLength(t *testing.T) {
	t.Run("raw 32-byte string", func(t *testing.T) {
		// Use string with chars not valid in base64 to force raw interpretation
		keyStr := "abcdefghijklmnopqrstuvwxyz!@#$%^" // 32 chars, !@#$%^ not valid base64
		length, err := validateEncryptionKeyLength(keyStr)
		require.NoError(t, err)
		assert.Equal(t, 32, length)
	})

	t.Run("base64-encoded 32-byte key", func(t *testing.T) {
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i)
		}
		keyStr := base64.StdEncoding.EncodeToString(key) // 44 chars

		length, err := validateEncryptionKeyLength(keyStr)
		require.NoError(t, err)
		assert.Equal(t, 32, length)
	})

	t.Run("base64-encoded 24-byte key", func(t *testing.T) {
		key := make([]byte, 24)
		keyStr := base64.StdEncoding.EncodeToString(key)

		length, err := validateEncryptionKeyLength(keyStr)
		require.NoError(t, err)
		assert.Equal(t, 24, length)
	})

	t.Run("invalid base64 falls back to string length", func(t *testing.T) {
		// String with characters not valid in base64
		keyStr := "not-valid-base64!@#$%^&*()_+====" // 32 chars but not valid base64

		length, err := validateEncryptionKeyLength(keyStr)
		require.NoError(t, err)
		assert.Equal(t, 32, length, "expected length 32 (raw string)")
	})
}

func TestValidate_JWTStore(t *testing.T) {
	t.Run("missing signing_key", func(t *testing.T) {
		cfg := validConfig()
		cfg.Session.Store = "jwt"
		cfg.Session.JWT.SigningKey = ""
		cfg.Session.JWT.PrivateKey = ""

		err := Validate(cfg)
		require.Error(t, err)
		assert.True(t, containsField(err, "session.jwt.signing_key"), "expected session.jwt.signing_key validation error")
	})

	t.Run("valid with signing_key", func(t *testing.T) {
		cfg := validConfig()
		cfg.Session.Store = "jwt"
		cfg.Session.JWT.SigningKey = "my-secret-key"
		cfg.Session.JWT.Algorithm = "HS256"

		err := Validate(cfg)
		assert.False(t, containsField(err, "session.jwt.signing_key"), "unexpected session.jwt.signing_key validation error: %v", err)
	})

	t.Run("valid with private_key", func(t *testing.T) {
		cfg := validConfig()
		cfg.Session.Store = "jwt"
		cfg.Session.JWT.PrivateKey = "/path/to/private.pem"
		cfg.Session.JWT.Algorithm = "RS256"

		err := Validate(cfg)
		assert.False(t, containsField(err, "session.jwt.signing_key"), "unexpected validation error when private_key is set: %v", err)
	})

	t.Run("invalid algorithm", func(t *testing.T) {
		cfg := validConfig()
		cfg.Session.Store = "jwt"
		cfg.Session.JWT.SigningKey = "my-secret-key"
		cfg.Session.JWT.Algorithm = "invalid"

		err := Validate(cfg)
		require.Error(t, err)
		assert.True(t, containsField(err, "session.jwt.algorithm"), "expected session.jwt.algorithm validation error")
	})
}

func TestValidate_RedisStore(t *testing.T) {
	t.Run("missing addresses", func(t *testing.T) {
		cfg := validConfig()
		cfg.Session.Store = "redis"
		cfg.Session.Redis.Addresses = nil
		cfg.Session.Encryption.Enabled = false

		err := Validate(cfg)
		require.Error(t, err)
		assert.True(t, containsField(err, "session.redis.addresses"), "expected session.redis.addresses validation error")
	})

	t.Run("empty addresses", func(t *testing.T) {
		cfg := validConfig()
		cfg.Session.Store = "redis"
		cfg.Session.Redis.Addresses = []string{}
		cfg.Session.Encryption.Enabled = false

		err := Validate(cfg)
		require.Error(t, err)
		assert.True(t, containsField(err, "session.redis.addresses"), "expected session.redis.addresses validation error")
	})

	t.Run("valid addresses", func(t *testing.T) {
		cfg := validConfig()
		cfg.Session.Store = "redis"
		cfg.Session.Redis.Addresses = []string{"redis:6379"}
		cfg.Session.Encryption.Enabled = false

		err := Validate(cfg)
		assert.False(t, containsField(err, "session.redis.addresses"), "unexpected session.redis.addresses validation error: %v", err)
	})
}

func TestValidate_Services(t *testing.T) {
	t.Run("missing service name", func(t *testing.T) {
		cfg := validConfig()
		cfg.Services = []ServiceConfig{
			{Name: "", Location: "/test", Upstream: "http://test:8080"},
		}

		err := Validate(cfg)
		require.Error(t, err)
		assert.True(t, containsField(err, "services[0].name"), "expected services[0].name validation error")
	})

	t.Run("duplicate service name", func(t *testing.T) {
		cfg := validConfig()
		cfg.Services = []ServiceConfig{
			{Name: "test", Location: "/test1", Upstream: "http://test1:8080"},
			{Name: "test", Location: "/test2", Upstream: "http://test2:8080"},
		}

		err := Validate(cfg)
		require.Error(t, err)
		assert.True(t, containsField(err, "services[1].name"), "expected duplicate name validation error")
	})

	t.Run("missing service location", func(t *testing.T) {
		cfg := validConfig()
		cfg.Services = []ServiceConfig{
			{Name: "test", Location: "", Upstream: "http://test:8080"},
		}

		err := Validate(cfg)
		require.Error(t, err)
		assert.True(t, containsField(err, "services[0].location"), "expected services[0].location validation error")
	})

	t.Run("duplicate service location", func(t *testing.T) {
		cfg := validConfig()
		cfg.Services = []ServiceConfig{
			{Name: "test1", Location: "/test", Upstream: "http://test1:8080"},
			{Name: "test2", Location: "/test", Upstream: "http://test2:8080"},
		}

		err := Validate(cfg)
		require.Error(t, err)
		assert.True(t, containsField(err, "services[1].location"), "expected duplicate location validation error")
	})

	t.Run("missing service upstream", func(t *testing.T) {
		cfg := validConfig()
		cfg.Services = []ServiceConfig{
			{Name: "test", Location: "/test", Upstream: ""},
		}

		err := Validate(cfg)
		require.Error(t, err)
		assert.True(t, containsField(err, "services[0].upstream"), "expected services[0].upstream validation error")
	})

	t.Run("invalid service upstream URL", func(t *testing.T) {
		cfg := validConfig()
		cfg.Services = []ServiceConfig{
			{Name: "test", Location: "/test", Upstream: "://invalid"},
		}

		err := Validate(cfg)
		require.Error(t, err)
		assert.True(t, containsField(err, "services[0].upstream"), "expected services[0].upstream validation error for invalid URL")
	})

	t.Run("valid services", func(t *testing.T) {
		cfg := validConfig()
		cfg.Services = []ServiceConfig{
			{Name: "test1", Location: "/test1", Upstream: "http://test1:8080"},
			{Name: "test2", Location: "/test2", Upstream: "http://test2:8080"},
		}

		err := Validate(cfg)
		assert.False(t, containsField(err, "services"), "unexpected services validation error: %v", err)
	})
}

func TestValidate_DevMode(t *testing.T) {
	t.Run("dev mode without profiles_dir", func(t *testing.T) {
		cfg := validConfig()
		cfg.DevMode.Enabled = true
		cfg.DevMode.ProfilesDir = ""

		err := Validate(cfg)
		require.Error(t, err)
		assert.True(t, containsField(err, "dev_mode.profiles_dir"), "expected dev_mode.profiles_dir validation error")
	})

	t.Run("dev mode with profiles_dir", func(t *testing.T) {
		cfg := validConfig()
		cfg.DevMode.Enabled = true
		cfg.DevMode.ProfilesDir = "./profiles"

		err := Validate(cfg)
		assert.False(t, containsField(err, "dev_mode.profiles_dir"), "unexpected dev_mode.profiles_dir validation error: %v", err)
	})

	t.Run("dev mode disabled without profiles_dir is valid", func(t *testing.T) {
		cfg := validConfig()
		cfg.DevMode.Enabled = false
		cfg.DevMode.ProfilesDir = ""

		err := Validate(cfg)
		assert.False(t, containsField(err, "dev_mode.profiles_dir"), "dev_mode.profiles_dir should not be required when disabled")
	})
}

func TestValidate_TLS(t *testing.T) {
	t.Run("TLS enabled without cert", func(t *testing.T) {
		cfg := validConfig()
		cfg.Server.TLS.Enabled = true
		cfg.Server.TLS.Cert = ""
		cfg.Server.TLS.Key = "/path/to/key.pem"

		err := Validate(cfg)
		require.Error(t, err)
		assert.True(t, containsField(err, "server.tls.cert"), "expected server.tls.cert validation error")
	})

	t.Run("TLS enabled without key", func(t *testing.T) {
		cfg := validConfig()
		cfg.Server.TLS.Enabled = true
		cfg.Server.TLS.Cert = "/path/to/cert.pem"
		cfg.Server.TLS.Key = ""

		err := Validate(cfg)
		require.Error(t, err)
		assert.True(t, containsField(err, "server.tls.key"), "expected server.tls.key validation error")
	})

	t.Run("TLS enabled with autocert skips cert/key validation", func(t *testing.T) {
		cfg := validConfig()
		cfg.Server.TLS.Enabled = true
		cfg.Server.TLS.AutoCert.Enabled = true
		cfg.Server.TLS.Cert = ""
		cfg.Server.TLS.Key = ""

		err := Validate(cfg)
		assert.False(t, containsField(err, "server.tls.cert"), "cert should not be required when autocert is enabled")
		assert.False(t, containsField(err, "server.tls.key"), "key should not be required when autocert is enabled")
	})

	t.Run("TLS disabled skips cert/key validation", func(t *testing.T) {
		cfg := validConfig()
		cfg.Server.TLS.Enabled = false
		cfg.Server.TLS.Cert = ""
		cfg.Server.TLS.Key = ""

		err := Validate(cfg)
		assert.False(t, containsField(err, "server.tls.cert"), "cert should not be required when TLS is disabled")
		assert.False(t, containsField(err, "server.tls.key"), "key should not be required when TLS is disabled")
	})
}

func TestValidate_FullyValid(t *testing.T) {
	cfg := validConfig()
	err := Validate(cfg)
	require.NoError(t, err, "valid config should pass validation")
}

// Helper functions

func validConfig() *Config {
	return &Config{
		Mode: "portal",
		Server: ServerConfig{
			HTTPPort:  8080,
			HTTPSPort: 443,
		},
		Auth: AuthConfig{
			Keycloak: KeycloakConfig{
				IssuerURL:    "https://keycloak.example.com/realms/main",
				ClientID:     "auth-portal",
				ClientSecret: "secret",
				RedirectURL:  "https://auth.example.com/callback",
				Scopes:       []string{"openid", "profile", "email"},
			},
		},
		Session: SessionConfig{
			Store:      "cookie",
			CookieName: "_auth_session",
			SameSite:   "lax",
			Encryption: EncryptionConfig{
				Enabled: true,
				Key:     "abcdefghijklmnopqrstuvwxyz!@#$%^", // 32 bytes, not valid base64
			},
			Cookie: CookieStoreConfig{
				MaxSize: 4096,
			},
			JWT: JWTStoreConfig{
				Algorithm: "HS256",
			},
		},
		Log: LogConfig{
			Level:  "info",
			Format: "json",
		},
	}
}

func containsField(err error, field string) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, field)
}

// HIGH-05 security fix tests
func TestValidateNginxExtra(t *testing.T) {
	tests := []struct {
		name           string
		nginxExtra     string
		expectedFound  []string
		expectedEmpty  bool
	}{
		{
			name:          "safe config - proxy headers",
			nginxExtra:    "proxy_set_header X-Custom-Header 'value';",
			expectedEmpty: true,
		},
		{
			name:          "safe config - timeouts",
			nginxExtra:    "proxy_read_timeout 30s;\nproxy_connect_timeout 10s;",
			expectedEmpty: true,
		},
		{
			name:          "safe config - buffering",
			nginxExtra:    "proxy_buffering off;",
			expectedEmpty: true,
		},
		{
			name:          "dangerous - proxy_pass",
			nginxExtra:    "proxy_pass http://malicious.example.com;",
			expectedFound: []string{"proxy_pass"},
		},
		{
			name:          "dangerous - lua_code_cache",
			nginxExtra:    "lua_code_cache off;",
			expectedFound: []string{"lua_*"},
		},
		{
			name:          "dangerous - content_by_lua_block",
			nginxExtra:    "content_by_lua_block { ngx.say('hello') }",
			expectedFound: []string{"content_by_lua"},
		},
		{
			name:          "dangerous - access_by_lua",
			nginxExtra:    "access_by_lua 'some code';",
			expectedFound: []string{"access_by_lua"},
		},
		{
			name:          "dangerous - root directive",
			nginxExtra:    "root /etc/passwd;",
			expectedFound: []string{"root"},
		},
		{
			name:          "dangerous - alias directive",
			nginxExtra:    "alias /etc/;",
			expectedFound: []string{"alias"},
		},
		{
			name:          "dangerous - include directive",
			nginxExtra:    "include /etc/nginx/conf.d/*.conf;",
			expectedFound: []string{"include"},
		},
		{
			name:          "dangerous - error_page to external",
			nginxExtra:    "error_page 500 https://evil.com/error;",
			expectedFound: []string{"error_page (external redirect)"},
		},
		{
			name:          "dangerous - error_page to protocol-relative",
			nginxExtra:    "error_page 404 //evil.com/not-found;",
			expectedFound: []string{"error_page (external redirect)"},
		},
		{
			name:          "safe - error_page to local",
			nginxExtra:    "error_page 500 /error.html;",
			expectedEmpty: true,
		},
		{
			name:          "dangerous - fastcgi_pass",
			nginxExtra:    "fastcgi_pass unix:/var/run/php-fpm.sock;",
			expectedFound: []string{"fastcgi_pass"},
		},
		{
			name:          "dangerous - multiple directives",
			nginxExtra:    "proxy_pass http://bad.com;\nroot /tmp;\ncontent_by_lua 'code';",
			expectedFound: []string{"proxy_pass", "root", "content_by_lua"},
		},
		{
			name:          "case insensitive - PROXY_PASS",
			nginxExtra:    "PROXY_PASS http://somewhere;",
			expectedFound: []string{"proxy_pass"},
		},
		{
			name:          "dangerous - init_by_lua",
			nginxExtra:    "init_by_lua 'some_code';",
			expectedFound: []string{"init_by_lua"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateNginxExtra(tt.nginxExtra)

			if tt.expectedEmpty {
				assert.Empty(t, result, "expected no dangerous directives")
				return
			}

			assert.Len(t, result, len(tt.expectedFound), "expected %d dangerous directives, got %d: %v",
				len(tt.expectedFound), len(result), result)

			for _, expected := range tt.expectedFound {
				found := false
				for _, r := range result {
					if r == expected {
						found = true
						break
					}
				}
				assert.True(t, found, "expected to find '%s' in result, got: %v", expected, result)
			}
		})
	}
}

func TestValidate_NginxExtra(t *testing.T) {
	// Test that validation integrates with the main Validate function

	t.Run("service with safe nginx_extra", func(t *testing.T) {
		cfg := validConfig()
		cfg.Services = []ServiceConfig{
			{
				Name:       "test-service",
				Location:   "/test",
				Upstream:   "http://localhost:8080",
				NginxExtra: "proxy_read_timeout 30s;",
			},
		}
		err := Validate(cfg)
		assert.False(t, containsField(err, "nginx_extra"), "expected no nginx_extra error for safe config, got: %v", err)
	})

	t.Run("service with dangerous nginx_extra", func(t *testing.T) {
		cfg := validConfig()
		cfg.Services = []ServiceConfig{
			{
				Name:       "test-service",
				Location:   "/test",
				Upstream:   "http://localhost:8080",
				NginxExtra: "proxy_pass http://evil.com;",
			},
		}
		err := Validate(cfg)
		require.Error(t, err)
		assert.True(t, containsField(err, "nginx_extra"), "expected nginx_extra validation error, got: %v", err)
		assert.Contains(t, err.Error(), "proxy_pass", "expected error to mention 'proxy_pass'")
	})

	t.Run("service with multiple dangerous directives", func(t *testing.T) {
		cfg := validConfig()
		cfg.Services = []ServiceConfig{
			{
				Name:       "test-service",
				Location:   "/test",
				Upstream:   "http://localhost:8080",
				NginxExtra: "root /etc;\nalias /var/;",
			},
		}
		err := Validate(cfg)
		require.Error(t, err)
		assert.True(t, containsField(err, "nginx_extra"), "expected nginx_extra validation error, got: %v", err)
		errStr := err.Error()
		assert.Contains(t, errStr, "root", "expected error to mention 'root'")
		assert.Contains(t, errStr, "alias", "expected error to mention 'alias'")
	})
}
