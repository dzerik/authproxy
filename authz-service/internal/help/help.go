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
	GitCommit   string
	DocsURL     string
}

// Generator generates help text for the application.
type Generator struct {
	appInfo      AppInfo
	envVarPrefix string
	envVars      []EnvVar
}

// NewGenerator creates a new help generator.
func NewGenerator(appInfo AppInfo, envVarPrefix string) *Generator {
	return &Generator{
		appInfo:      appInfo,
		envVarPrefix: envVarPrefix,
	}
}

// SetEnvVars sets the environment variables extracted from config.
func (g *Generator) SetEnvVars(vars []EnvVar) {
	g.envVars = vars
}

// ExtractEnvVars extracts environment variables from a config struct.
func (g *Generator) ExtractEnvVars(cfg interface{}) {
	extractor := NewEnvVarExtractor(g.envVarPrefix)
	g.envVars = extractor.Extract(cfg)
}

// PrintVersion prints version information.
func (g *Generator) PrintVersion() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s\n", g.appInfo.Name, g.appInfo.Version))
	sb.WriteString(fmt.Sprintf("  Build time: %s\n", g.appInfo.BuildTime))
	sb.WriteString(fmt.Sprintf("  Git commit: %s\n", g.appInfo.GitCommit))
	return sb.String()
}

// PrintUsage prints basic usage information.
func (g *Generator) PrintUsage() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Usage: %s [OPTIONS]\n\n", g.appInfo.Name))
	sb.WriteString(fmt.Sprintf("%s\n\n", g.appInfo.Description))
	sb.WriteString("Options:\n")
	sb.WriteString("  See below for available flags.\n\n")
	sb.WriteString("Use --help for detailed configuration documentation\n")
	return sb.String()
}

// PrintEnvVars prints only the environment variables documentation.
func (g *Generator) PrintEnvVars() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("\n%s - Environment Variables\n", strings.ToUpper(g.appInfo.Name)))
	sb.WriteString(strings.Repeat("=", 80) + "\n\n")

	sb.WriteString(fmt.Sprintf("Prefix: %s\n", g.envVarPrefix))
	sb.WriteString(fmt.Sprintf("Total variables: %d\n\n", len(g.envVars)))

	sb.WriteString("Pattern: " + g.envVarPrefix + "_<SECTION>_<SUBSECTION>_<KEY>\n\n")

	sb.WriteString("Notes:\n")
	sb.WriteString("  - All keys are converted to UPPER_SNAKE_CASE\n")
	sb.WriteString("  - Nested keys use underscore as separator\n")
	sb.WriteString("  - Array indices use numeric suffix (0, 1, 2...)\n")
	sb.WriteString("  - Boolean values: true, false, 1, 0\n")
	sb.WriteString("  - Duration values: 10s, 5m, 1h, 100ms\n\n")

	sb.WriteString(strings.Repeat("-", 80) + "\n")

	// Grouped env vars
	if len(g.envVars) > 0 {
		sb.WriteString(FormatEnvVarsGrouped(g.envVars))
	}

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

	// Configuration methods section
	sb.WriteString("CONFIGURATION METHODS\n\n")
	sb.WriteString(g.configMethodsSection())
	sb.WriteString("\n")

	// Separator
	sb.WriteString(g.separator())

	// Environment variables section (brief)
	sb.WriteString("ENVIRONMENT VARIABLES\n\n")
	sb.WriteString("    Pattern: " + g.envVarPrefix + "_<SECTION>_<SUBSECTION>_<KEY>\n\n")
	sb.WriteString("    Notes:\n")
	sb.WriteString("    - All keys are converted to UPPER_SNAKE_CASE\n")
	sb.WriteString("    - Nested keys use underscore as separator\n")
	sb.WriteString("    - Array indices use numeric suffix (0, 1, 2...)\n")
	sb.WriteString("    - Boolean values: true, false, 1, 0\n")
	sb.WriteString("    - Duration values: 10s, 5m, 1h, 100ms\n\n")
	sb.WriteString(fmt.Sprintf("    Use --help-env to see all %d environment variables with descriptions.\n\n", len(g.envVars)))

	// Separator
	sb.WriteString(g.separator())

	// Secrets management section
	sb.WriteString("SECRETS MANAGEMENT\n\n")
	sb.WriteString(g.secretsSection())
	sb.WriteString("\n")

	// Separator
	sb.WriteString(g.separator())

	// Operation modes section
	sb.WriteString("OPERATION MODES\n\n")
	sb.WriteString(g.operationModesSection())
	sb.WriteString("\n")

	// Separator
	sb.WriteString(g.separator())

	// Policy engines section
	sb.WriteString("POLICY ENGINES\n\n")
	sb.WriteString(g.policyEnginesSection())
	sb.WriteString("\n")

	// Separator
	sb.WriteString(g.separator())

	// JSON Schema generation section
	sb.WriteString("JSON SCHEMA GENERATION\n\n")
	sb.WriteString(g.schemaGenerationSection())
	sb.WriteString("\n")

	// Separator
	sb.WriteString(g.separator())

	// Examples section
	sb.WriteString("EXAMPLES\n\n")
	sb.WriteString(g.examplesSection())
	sb.WriteString("\n")

	// Separator
	sb.WriteString(g.separator())

	// Files and signals section
	sb.WriteString("FILES\n\n")
	sb.WriteString(g.filesSection())
	sb.WriteString("\n")

	sb.WriteString("SIGNALS\n\n")
	sb.WriteString("    SIGTERM, SIGINT           Graceful shutdown (configurable timeout)\n\n")

	sb.WriteString("HEALTH ENDPOINTS\n\n")
	sb.WriteString("    GET /health               Overall health status\n")
	sb.WriteString("    GET /ready                Readiness probe\n")
	sb.WriteString("    GET /live                 Liveness probe\n")
	sb.WriteString("    GET /metrics              Prometheus metrics\n\n")

	// Separator
	sb.WriteString(g.separator())

	// Version section
	sb.WriteString("VERSION\n")
	sb.WriteString(fmt.Sprintf("    %s (%s)\n", g.appInfo.Version, g.appInfo.GitCommit))
	sb.WriteString(fmt.Sprintf("    Built: %s\n\n", g.appInfo.BuildTime))

	sb.WriteString("DOCUMENTATION\n")
	sb.WriteString(fmt.Sprintf("    %s\n\n", g.appInfo.DocsURL))

	return sb.String()
}

// header generates the header box.
func (g *Generator) header() string {
	width := 80
	title := strings.ToUpper(g.appInfo.Name)
	subtitle := g.appInfo.Description

	// Truncate if needed
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
	return `    --config <path>       Path to environment.yaml configuration file
    --version             Show version information
    --help, -h            Show this help message
    --help-env            Show all environment variables with descriptions
    --schema <type>       Generate JSON Schema (environment, services, rules)
    --schema-output <file> Output file for schema (default: stdout)
    --validate            Validate configuration and exit
    --dry-run             Validate config, test connections, and exit
`
}

// configMethodsSection generates the configuration methods section.
func (g *Generator) configMethodsSection() string {
	return fmt.Sprintf(`    Configuration is split into 3 files:

    CONFIGURATION STRUCTURE
    -----------------------
    1. environment.yaml   - Static configuration (requires restart)
       - Server ports, addresses, timeouts
       - Logging format and level
       - Tracing endpoint
       - Config source settings

    2. services.yaml      - Dynamic configuration (runtime updatable)
       - JWT issuers and validation
       - Policy engine settings
       - Cache configuration
       - Resilience (rate limiting, circuit breaker)
       - Proxy and egress listeners

    3. rules.yaml         - Authorization rules (runtime updatable)
       - Policy rules with conditions
       - RBAC/ABAC definitions

    CONFIGURATION SOURCES (in order of priority):

    1. COMMAND LINE FLAGS
       Highest priority. Override all other configuration.

       Example:
         %s --config /etc/authz/environment.yaml

    2. ENVIRONMENT VARIABLES
       Middle priority. Override config file values.

       Pattern: %s_<SECTION>_<SUBSECTION>_<KEY>

       Examples:
         %s_SERVER_HTTP_ADDR=:8080
         %s_MANAGEMENT_ADMIN_ADDR=:15000
         %s_LOGGING_LEVEL=debug
         %s_CONFIG_SOURCE_FILE_SERVICES_PATH=/etc/authz/services.yaml

    3. CONFIGURATION FILES (YAML)
       Lowest priority. Base configuration.

       Default paths:
         environment.yaml: ./configs/environment.yaml, /etc/authz/environment.yaml
         services.yaml:    Defined in environment.yaml (config_source.file.services_path)
         rules.yaml:       Defined in environment.yaml (config_source.file.rules_path)

    RUNTIME CONFIGURATION UPDATES
    -----------------------------
    Services and rules can be updated at runtime without restart:
    - File-based: Enable file watching (config_source.file.watch_enabled)
    - Remote: Configure remote config source (config_source.type=remote)

    Fields marked with x-runtime-updatable=true in JSON Schema can be changed dynamically.
`, g.appInfo.Name, g.envVarPrefix, g.envVarPrefix, g.envVarPrefix, g.envVarPrefix, g.envVarPrefix)
}

// operationModesSection generates the operation modes section.
func (g *Generator) operationModesSection() string {
	return `    1. DECISION API MODE (default)
       Service provides authorization API endpoints.
       Backend applications call the API to check permissions.

       Endpoints:
         POST /v1/authorize        - Single authorization check
         POST /v1/authorize/batch  - Batch authorization check
         GET  /v1/token/validate   - Validate JWT token

    2. REVERSE PROXY MODE (proxy.enabled=true, proxy.mode=reverse_proxy)
       Service acts as an authorization proxy.
       All requests pass through, unauthorized requests are rejected.

       Flow: Client -> Authz Proxy -> Backend

    3. EGRESS PROXY MODE (egress.enabled=true)
       Service acts as an outbound proxy.
       Adds credentials to outgoing requests to external services.

       Flow: Backend -> Authz Egress -> External API
`
}

// policyEnginesSection generates the policy engines section.
func (g *Generator) policyEnginesSection() string {
	return `    1. BUILTIN (policy.engine=builtin)
       YAML-based rules. Simple, fast, no dependencies.
       Good for: Simple RBAC, path-based authorization.

       Config: policy.builtin.rules_path

    2. OPA EMBEDDED (policy.engine=opa_embedded)
       Embedded Open Policy Agent. Rego policies, local evaluation.
       Good for: Complex ABAC, fine-grained authorization.

       Config: policy.opa_embedded.policy_dir
               policy.opa_embedded.data_dir

    3. OPA SIDECAR (policy.engine=opa_sidecar)
       External OPA server. HTTP-based evaluation.
       Good for: Shared policies, centralized management.

       Config: policy.opa.url
               policy.opa.policy_path
`
}

// schemaGenerationSection generates the JSON schema generation section.
func (g *Generator) schemaGenerationSection() string {
	return fmt.Sprintf(`    Generate JSON schemas for IDE autocomplete and validation:

    # Generate environment schema (static configuration)
    %s --schema environment > environment.schema.json

    # Generate services schema (dynamic configuration)
    %s --schema services > services.schema.json

    # Generate rules schema (authorization rules)
    %s --schema rules > rules.schema.json

    # Write to specific file
    %s --schema environment --schema-output /etc/authz/environment.schema.json

    Use in YAML files (VS Code, JetBrains):
    # yaml-language-server: $schema=./environment.schema.json

    Schema includes x-runtime-updatable field indicating which settings
    can be changed without restart.
`, g.appInfo.Name, g.appInfo.Name, g.appInfo.Name, g.appInfo.Name)
}

// examplesSection generates the examples section.
func (g *Generator) examplesSection() string {
	return fmt.Sprintf(`    # Start with environment config file
    %s --config /etc/authz/environment.yaml

    # Validate configuration
    %s --config environment.yaml --validate

    # Dry run (validate + test connections)
    %s --config environment.yaml --dry-run

    # Override with environment variables
    %s_SERVER_HTTP_ADDR=:9090 \
    %s_LOGGING_LEVEL=debug \
    %s_MANAGEMENT_ADMIN_ADDR=:15000 \
    %s --config environment.yaml

    # Generate all schemas
    %s --schema environment > environment.schema.json
    %s --schema services > services.schema.json
    %s --schema rules > rules.schema.json

    # Docker with environment variables
    docker run -e %s_SERVER_HTTP_ADDR=:8080 \
               -e %s_MANAGEMENT_ENABLED=true \
               -e %s_CONFIG_SOURCE_FILE_SERVICES_PATH=/config/services.yaml \
               -v /path/to/configs:/config \
               %s:latest

    # Kubernetes ConfigMap setup
    # Mount environment.yaml to /etc/authz/environment.yaml
    # Mount services.yaml to /etc/authz/services.yaml (or configure path)
    # Mount rules.yaml to /etc/authz/rules.yaml
`, g.appInfo.Name, g.appInfo.Name, g.appInfo.Name, g.envVarPrefix, g.envVarPrefix, g.envVarPrefix, g.appInfo.Name,
		g.appInfo.Name, g.appInfo.Name, g.appInfo.Name, g.envVarPrefix, g.envVarPrefix, g.envVarPrefix, g.appInfo.Name)
}

// filesSection generates the files section.
func (g *Generator) filesSection() string {
	return `    CONFIGURATION FILES
    /etc/authz/environment.yaml   Static configuration (requires restart)
    /etc/authz/services.yaml      Dynamic service configuration (runtime updatable)
    /etc/authz/rules.yaml         Authorization rules (runtime updatable)

    POLICY FILES
    /etc/authz/policies/          OPA policy directory (opa_embedded engine)
    /etc/authz/data/              OPA data directory

    CACHE & FALLBACK
    /var/cache/authz/             Fallback configuration cache directory

    MANAGEMENT PORTS (Istio-style)
    :15000                        Admin interface (config dump, stats, logging)
    :15020                        Aggregated health and metrics
    :15021                        Dedicated readiness probe
`
}

// secretsSection generates the secrets management section.
func (g *Generator) secretsSection() string {
	return fmt.Sprintf(`    NEVER store secrets in configuration files! Use environment variables instead.

    SENSITIVE ENVIRONMENT VARIABLES:

    JWT / OAuth2:
      %s_JWT_ISSUERS_0_CLIENT_SECRET       OAuth2 client secret for token exchange
      %s_EGRESS_TARGETS_<NAME>_AUTH_CLIENT_SECRET  Egress target OAuth2 client secret

    Redis (L2 Cache):
      %s_CACHE_L2_REDIS_PASSWORD           Redis password for L2 cache

    Redis (Rate Limiting):
      %s_RESILIENCE_RATE_LIMIT_REDIS_PASSWORD  Redis password for rate limiting

    Redis (Egress Token Store):
      %s_EGRESS_TOKEN_STORE_REDIS_PASSWORD Redis password for token store

    Basic Auth (Egress):
      %s_EGRESS_TARGETS_<NAME>_AUTH_PASSWORD  Basic auth password for egress targets

    API Keys (Egress):
      %s_EGRESS_TARGETS_<NAME>_AUTH_KEY    API key value for egress targets

    SECURITY BEST PRACTICES:

    1. Use Kubernetes secrets mounted as env vars:
       env:
         - name: %s_CACHE_L2_REDIS_PASSWORD
           valueFrom:
             secretKeyRef:
               name: authz-secrets
               key: redis-password

    2. Use Docker secrets:
       docker run -e %s_JWT_ISSUERS_0_CLIENT_SECRET_FILE=/run/secrets/jwt_secret ...

    3. Use HashiCorp Vault or similar secret managers

    4. Rotate secrets regularly and monitor for unauthorized access
`, g.envVarPrefix, g.envVarPrefix, g.envVarPrefix, g.envVarPrefix, g.envVarPrefix, g.envVarPrefix, g.envVarPrefix, g.envVarPrefix, g.envVarPrefix)
}
