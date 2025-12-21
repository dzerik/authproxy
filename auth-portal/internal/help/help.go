// Package help provides help text generation for auth-portal.
package help

import (
	"fmt"
	"strings"
)

// AppInfo contains application metadata.
type AppInfo struct {
	Name        string
	Description string
	Version     string
	BuildTime   string
	DocsURL     string
}

// Generator generates help text for the application.
type Generator struct {
	appInfo      AppInfo
	envVarPrefix string
}

// NewGenerator creates a new help generator.
func NewGenerator(appInfo AppInfo, envVarPrefix string) *Generator {
	return &Generator{
		appInfo:      appInfo,
		envVarPrefix: envVarPrefix,
	}
}

// PrintVersion prints version information.
func (g *Generator) PrintVersion() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s\n", g.appInfo.Name, g.appInfo.Version))
	sb.WriteString(fmt.Sprintf("  Build time: %s\n", g.appInfo.BuildTime))
	return sb.String()
}

// PrintUsage prints basic usage information.
func (g *Generator) PrintUsage() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Usage: %s [OPTIONS]\n\n", g.appInfo.Name))
	sb.WriteString(fmt.Sprintf("%s\n\n", g.appInfo.Description))
	sb.WriteString("Use --help for detailed configuration documentation\n")
	return sb.String()
}

// PrintExtendedHelp prints detailed help with all configuration options.
func (g *Generator) PrintExtendedHelp() string {
	var sb strings.Builder

	// Header
	sb.WriteString(g.header())
	sb.WriteString("\n")

	// Description section
	sb.WriteString("DESCRIPTION\n")
	sb.WriteString(fmt.Sprintf("    %s\n\n", g.appInfo.Description))

	// Usage section
	sb.WriteString("USAGE\n")
	sb.WriteString(fmt.Sprintf("    %s [OPTIONS]\n\n", g.appInfo.Name))

	// Options section
	sb.WriteString("OPTIONS\n")
	sb.WriteString(g.optionsSection())
	sb.WriteString("\n")

	// Separator
	sb.WriteString(g.separator())

	// Configuration section
	sb.WriteString("CONFIGURATION\n\n")
	sb.WriteString(g.configSection())
	sb.WriteString("\n")

	// Separator
	sb.WriteString(g.separator())

	// Environment variables section
	sb.WriteString("ENVIRONMENT VARIABLES\n\n")
	sb.WriteString(g.envVarsSection())
	sb.WriteString("\n")

	// Separator
	sb.WriteString(g.separator())

	// Operation modes section
	sb.WriteString("OPERATION MODES\n\n")
	sb.WriteString(g.operationModesSection())
	sb.WriteString("\n")

	// Separator
	sb.WriteString(g.separator())

	// Nginx integration section
	sb.WriteString("NGINX INTEGRATION\n\n")
	sb.WriteString(g.nginxSection())
	sb.WriteString("\n")

	// Separator
	sb.WriteString(g.separator())

	// Examples section
	sb.WriteString("EXAMPLES\n\n")
	sb.WriteString(g.examplesSection())
	sb.WriteString("\n")

	// Separator
	sb.WriteString(g.separator())

	// Health endpoints section
	sb.WriteString("HEALTH ENDPOINTS\n\n")
	sb.WriteString("    GET /health               Overall health status\n")
	sb.WriteString("    GET /ready                Readiness probe\n")
	sb.WriteString("    GET /metrics              Prometheus metrics\n\n")

	// Separator
	sb.WriteString(g.separator())

	// Version section
	sb.WriteString("VERSION\n")
	sb.WriteString(fmt.Sprintf("    %s\n", g.appInfo.Version))
	sb.WriteString(fmt.Sprintf("    Built: %s\n\n", g.appInfo.BuildTime))

	if g.appInfo.DocsURL != "" {
		sb.WriteString("DOCUMENTATION\n")
		sb.WriteString(fmt.Sprintf("    %s\n\n", g.appInfo.DocsURL))
	}

	return sb.String()
}

// header generates the header box.
func (g *Generator) header() string {
	width := 80
	title := strings.ToUpper(g.appInfo.Name)
	subtitle := g.appInfo.Description

	if len(subtitle) > width-4 {
		subtitle = subtitle[:width-7] + "..."
	}

	var sb strings.Builder
	sb.WriteString("\n")

	// Top border
	sb.WriteString("+" + strings.Repeat("-", width-2) + "+\n")

	// Title centered
	titlePadding := (width - 2 - len(title)) / 2
	sb.WriteString("|" + strings.Repeat(" ", titlePadding) + title + strings.Repeat(" ", width-2-titlePadding-len(title)) + "|\n")

	// Subtitle centered
	subtitlePadding := (width - 2 - len(subtitle)) / 2
	sb.WriteString("|" + strings.Repeat(" ", subtitlePadding) + subtitle + strings.Repeat(" ", width-2-subtitlePadding-len(subtitle)) + "|\n")

	// Bottom border
	sb.WriteString("+" + strings.Repeat("-", width-2) + "+\n")

	return sb.String()
}

// separator generates a section separator line.
func (g *Generator) separator() string {
	return strings.Repeat("-", 80) + "\n\n"
}

// optionsSection generates the options section.
func (g *Generator) optionsSection() string {
	return `    --config <path>       Path to configuration YAML file
                          Default: /etc/auth-portal/config.yaml
                          Env: AUTH_PORTAL_CONFIG

    --generate-nginx      Generate nginx config and exit
    --output <path>       Output path for nginx config
                          Default: /etc/nginx/nginx.conf
                          Env: AUTH_PORTAL_NGINX_CONFIG

    --dev                 Enable development mode (mock auth)
    --version             Show version information
    --help, -h            Show this help message
    --schema              Generate JSON Schema and exit
    --schema-output <file> Output file for schema (default: stdout)
`
}

// configSection generates the configuration section.
func (g *Generator) configSection() string {
	return fmt.Sprintf(`    Configuration is loaded from a YAML file.

    CONFIGURATION FILE STRUCTURE
    ----------------------------
    server:               HTTP server settings (ports, TLS)
    mode:                 portal | single-service
    auth:                 Keycloak OIDC configuration
    session:              Session storage (cookie | jwt | redis)
    services:             Backend services for portal mode
    nginx:                Nginx generation settings
    observability:        Metrics, tracing, health checks
    resilience:           Rate limiting, circuit breaker
    log:                  Logging configuration
    dev_mode:             Development mode settings

    CONFIGURATION SOURCES (in order of priority):

    1. COMMAND LINE FLAGS
       Highest priority. Override all other configuration.

    2. ENVIRONMENT VARIABLES
       Pattern: %s_<SECTION>_<KEY>

       Examples:
         %s_SERVER_HTTP_PORT=8080
         %s_LOG_LEVEL=debug
         %s_SESSION_STORE=redis

    3. CONFIGURATION FILE (YAML)
       Base configuration. Default: /etc/auth-portal/config.yaml

    SECRETS MANAGEMENT
    ------------------
    Use environment variables for secrets:
      KC_CLIENT_SECRET       Keycloak client secret
      ENCRYPTION_KEY         Session encryption key (32 bytes)
      JWT_SIGNING_KEY        JWT signing key
      SESSION_SECRET         Cookie signing secret
      REDIS_PASSWORD         Redis password
`, g.envVarPrefix, g.envVarPrefix, g.envVarPrefix, g.envVarPrefix)
}

// envVarsSection generates the environment variables section.
func (g *Generator) envVarsSection() string {
	return fmt.Sprintf(`    Pattern: %s_<SECTION>_<KEY>

    Notes:
    - All keys are converted to UPPER_SNAKE_CASE
    - Nested keys use underscore as separator
    - Boolean values: true, false, 1, 0
    - Duration values: 10s, 5m, 1h, 100ms

    KEY ENVIRONMENT VARIABLES:
    --------------------------

    [Auth]
      KC_ISSUER_URL              Keycloak issuer URL
      KC_CLIENT_ID               OAuth2 client ID
      KC_CLIENT_SECRET           OAuth2 client secret
      KC_REDIRECT_URL            OAuth2 redirect URL

    [Session]
      ENCRYPTION_KEY             AES-256 encryption key (32 bytes)
      JWT_SIGNING_KEY            JWT HMAC signing key
      SESSION_SECRET             Cookie signing secret
      REDIS_PASSWORD             Redis password

    [Server]
      HTTP_PORT                  HTTP listen port
      HTTPS_PORT                 HTTPS listen port

    [Logging]
      LOG_LEVEL                  Log level (debug, info, warn, error)
      DEV_MODE                   Enable development mode
`, g.envVarPrefix)
}

// operationModesSection generates the operation modes section.
func (g *Generator) operationModesSection() string {
	return `    1. PORTAL MODE (mode=portal)
       User authenticates and sees a list of available services.
       Clicking a service redirects to its URL.

       Config: services[] array with name, url, icon, etc.

    2. SINGLE-SERVICE MODE (mode=single-service)
       User authenticates and is immediately redirected
       to a single configured service.

       Config: single_service.target_url

    3. FORWARD AUTH MODE
       Auth-portal provides /auth endpoint for external proxies
       (Traefik, Nginx) to verify authentication.

       Endpoints:
         GET /auth              Verify session, return 200/401
         GET /auth/redirect     Verify or redirect to login
         GET /auth/verify       Lightweight token verification
         POST /auth/introspect  Token introspection
`
}

// nginxSection generates the nginx integration section.
func (g *Generator) nginxSection() string {
	return fmt.Sprintf(`    Auth-portal can generate nginx configuration for reverse proxying.

    GENERATION:
    -----------
    # Generate nginx config from auth-portal config
    %s --config config.yaml --generate-nginx --output /etc/nginx/nginx.conf

    # Use environment variables
    AUTH_PORTAL_CONFIG=/config/config.yaml \
    AUTH_PORTAL_NGINX_CONFIG=/etc/nginx/nginx.conf \
    %s --generate-nginx

    CONTAINER INTEGRATION:
    ----------------------
    In Docker/Kubernetes, auth-portal generates nginx.conf at startup:
    1. auth-portal reads config.yaml
    2. Generates /etc/nginx/nginx.conf
    3. nginx reads generated config
    4. Both run as services (s6-overlay or supervisord)

    GENERATED CONFIG INCLUDES:
    --------------------------
    - Upstream definitions for each service
    - Forward auth integration with auth-portal
    - Header injection (X-User-*, X-Auth-*)
    - Rate limiting (if configured in nginx section)
    - Access/error logging
`, g.appInfo.Name, g.appInfo.Name)
}

// examplesSection generates the examples section.
func (g *Generator) examplesSection() string {
	return fmt.Sprintf(`    # Start with config file
    %s --config /etc/auth-portal/config.yaml

    # Development mode
    %s --config config.yaml --dev

    # Generate nginx config
    %s --config config.yaml --generate-nginx --output nginx.conf

    # Generate JSON schema
    %s --schema > config.schema.json

    # Environment variable overrides
    KC_CLIENT_SECRET=secret123 \
    LOG_LEVEL=debug \
    %s --config config.yaml

    # Docker with volume mounts
    docker run -v /path/to/config.yaml:/etc/auth-portal/config.yaml \
               -e KC_CLIENT_SECRET=secret123 \
               -p 8080:8080 \
               %s:latest
`, g.appInfo.Name, g.appInfo.Name, g.appInfo.Name, g.appInfo.Name, g.appInfo.Name, g.appInfo.Name)
}
