package config

import (
	"fmt"
	"net/url"
	"strings"
)

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidationErrors represents multiple validation errors
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return ""
	}
	var msgs []string
	for _, err := range e {
		msgs = append(msgs, err.Error())
	}
	return "validation errors:\n  - " + strings.Join(msgs, "\n  - ")
}

// Validate validates the configuration
func Validate(cfg *Config) error {
	var errs ValidationErrors

	// Validate mode
	if cfg.Mode != "portal" && cfg.Mode != "single-service" {
		errs = append(errs, ValidationError{
			Field:   "mode",
			Message: fmt.Sprintf("must be 'portal' or 'single-service', got '%s'", cfg.Mode),
		})
	}

	// Validate single-service mode
	if cfg.Mode == "single-service" && cfg.SingleService.TargetURL == "" {
		errs = append(errs, ValidationError{
			Field:   "single_service.target_url",
			Message: "required when mode is 'single-service'",
		})
	}

	// Validate auth (unless dev mode)
	if !cfg.DevMode.Enabled {
		if cfg.Auth.Keycloak.IssuerURL == "" {
			errs = append(errs, ValidationError{
				Field:   "auth.keycloak.issuer_url",
				Message: "required",
			})
		} else if _, err := url.Parse(cfg.Auth.Keycloak.IssuerURL); err != nil {
			errs = append(errs, ValidationError{
				Field:   "auth.keycloak.issuer_url",
				Message: fmt.Sprintf("invalid URL: %v", err),
			})
		}

		if cfg.Auth.Keycloak.ClientID == "" {
			errs = append(errs, ValidationError{
				Field:   "auth.keycloak.client_id",
				Message: "required",
			})
		}

		if cfg.Auth.Keycloak.ClientSecret == "" {
			errs = append(errs, ValidationError{
				Field:   "auth.keycloak.client_secret",
				Message: "required",
			})
		}

		if cfg.Auth.Keycloak.RedirectURL == "" {
			errs = append(errs, ValidationError{
				Field:   "auth.keycloak.redirect_url",
				Message: "required",
			})
		}
	}

	// Validate session store
	validStores := map[string]bool{"cookie": true, "jwt": true, "redis": true}
	if !validStores[cfg.Session.Store] {
		errs = append(errs, ValidationError{
			Field:   "session.store",
			Message: fmt.Sprintf("must be 'cookie', 'jwt', or 'redis', got '%s'", cfg.Session.Store),
		})
	}

	// Validate encryption key for cookie/redis stores
	if cfg.Session.Store == "cookie" || cfg.Session.Store == "redis" {
		if cfg.Session.Encryption.Enabled && cfg.Session.Encryption.Key == "" {
			errs = append(errs, ValidationError{
				Field:   "session.encryption.key",
				Message: "required when encryption is enabled",
			})
		}
		if cfg.Session.Encryption.Enabled && len(cfg.Session.Encryption.Key) != 32 {
			errs = append(errs, ValidationError{
				Field:   "session.encryption.key",
				Message: fmt.Sprintf("must be 32 bytes for AES-256, got %d bytes", len(cfg.Session.Encryption.Key)),
			})
		}
	}

	// Validate JWT store
	if cfg.Session.Store == "jwt" {
		if cfg.Session.JWT.SigningKey == "" && cfg.Session.JWT.PrivateKey == "" {
			errs = append(errs, ValidationError{
				Field:   "session.jwt.signing_key",
				Message: "required for JWT store (or private_key for RS256)",
			})
		}
		validAlgorithms := map[string]bool{"HS256": true, "RS256": true}
		if !validAlgorithms[cfg.Session.JWT.Algorithm] {
			errs = append(errs, ValidationError{
				Field:   "session.jwt.algorithm",
				Message: fmt.Sprintf("must be 'HS256' or 'RS256', got '%s'", cfg.Session.JWT.Algorithm),
			})
		}
	}

	// Validate Redis store
	if cfg.Session.Store == "redis" {
		if len(cfg.Session.Redis.Addresses) == 0 {
			errs = append(errs, ValidationError{
				Field:   "session.redis.addresses",
				Message: "required for Redis store",
			})
		}
	}

	// Validate services
	serviceNames := make(map[string]bool)
	serviceLocations := make(map[string]bool)
	for i, svc := range cfg.Services {
		prefix := fmt.Sprintf("services[%d]", i)

		if svc.Name == "" {
			errs = append(errs, ValidationError{
				Field:   prefix + ".name",
				Message: "required",
			})
		} else if serviceNames[svc.Name] {
			errs = append(errs, ValidationError{
				Field:   prefix + ".name",
				Message: fmt.Sprintf("duplicate service name '%s'", svc.Name),
			})
		} else {
			serviceNames[svc.Name] = true
		}

		if svc.Location == "" {
			errs = append(errs, ValidationError{
				Field:   prefix + ".location",
				Message: "required",
			})
		} else if serviceLocations[svc.Location] {
			errs = append(errs, ValidationError{
				Field:   prefix + ".location",
				Message: fmt.Sprintf("duplicate location '%s'", svc.Location),
			})
		} else {
			serviceLocations[svc.Location] = true
		}

		if svc.Upstream == "" {
			errs = append(errs, ValidationError{
				Field:   prefix + ".upstream",
				Message: "required",
			})
		} else if _, err := url.Parse(svc.Upstream); err != nil {
			errs = append(errs, ValidationError{
				Field:   prefix + ".upstream",
				Message: fmt.Sprintf("invalid URL: %v", err),
			})
		}
	}

	// Validate dev mode
	if cfg.DevMode.Enabled && cfg.DevMode.ProfilesDir == "" {
		errs = append(errs, ValidationError{
			Field:   "dev_mode.profiles_dir",
			Message: "required when dev mode is enabled",
		})
	}

	// Validate TLS
	if cfg.Server.TLS.Enabled && !cfg.Server.TLS.AutoCert.Enabled {
		if cfg.Server.TLS.Cert == "" {
			errs = append(errs, ValidationError{
				Field:   "server.tls.cert",
				Message: "required when TLS is enabled without auto_cert",
			})
		}
		if cfg.Server.TLS.Key == "" {
			errs = append(errs, ValidationError{
				Field:   "server.tls.key",
				Message: "required when TLS is enabled without auto_cert",
			})
		}
	}

	if len(errs) > 0 {
		return errs
	}
	return nil
}
