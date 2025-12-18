package policy

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/internal/domain"
	"github.com/your-org/authz-service/pkg/errors"
	"github.com/your-org/authz-service/pkg/logger"
)

// BuiltinEngine implements a built-in policy engine with YAML-based rules.
type BuiltinEngine struct {
	mu          sync.RWMutex
	rules       *RuleSet
	rulesPath   string
	version     string
	pathMatcher *PathMatcher
	cidrMatcher *CIDRMatcher
}

// RuleSet contains all authorization rules.
type RuleSet struct {
	// Version of the rule set for tracking changes
	Version string `yaml:"version" jsonschema:"description=Version identifier for this rule set (e.g. '1.0'\\, '2024-01-15'). Used for tracking and cache invalidation.,example=1.0"`
	// Description provides human-readable context for this rule set
	Description string `yaml:"description" jsonschema:"description=Human-readable description of this rule set's purpose and scope."`
	// Rules is the ordered list of authorization rules
	Rules []Rule `yaml:"rules" jsonschema:"description=List of authorization rules. Rules are evaluated in priority order (highest first). First matching rule determines the decision.,required"`
	// DefaultDeny determines behavior when no rules match
	DefaultDeny bool `yaml:"default_deny" jsonschema:"description=Default decision when no rules match. If true\\, requests are denied by default (recommended for security). If false\\, requests are allowed by default.,default=true"`
}

// Rule defines a single authorization rule.
type Rule struct {
	// Name is the unique identifier for this rule
	Name string `yaml:"name" jsonschema:"description=Unique identifier for this rule. Used in logs\\, metrics\\, and decision metadata.,example=allow-admin-access,minLength=1,required"`
	// Description explains what this rule does
	Description string `yaml:"description" jsonschema:"description=Human-readable description explaining the purpose of this rule."`
	// Priority determines evaluation order (higher = evaluated first)
	Priority int `yaml:"priority" jsonschema:"description=Rule priority. Higher values are evaluated first. Use ranges: 1000+ for system rules\\, 100-999 for application rules\\, 1-99 for default rules.,minimum=0,maximum=10000,example=100,default=0"`
	// Enabled allows disabling rules without removing them
	Enabled bool `yaml:"enabled" jsonschema:"description=Whether this rule is active. Disabled rules are skipped during evaluation.,default=true"`
	// Conditions defines when this rule matches
	Conditions Conditions `yaml:"conditions" jsonschema:"description=Conditions that must be satisfied for this rule to match. All specified conditions must match (AND logic)."`
	// Effect is the decision when this rule matches
	Effect string `yaml:"effect" jsonschema:"description=Authorization decision when this rule matches.,enum=allow,enum=deny,required"`
	// Constraints are additional requirements applied when the rule matches
	Constraints Constraints `yaml:"constraints,omitempty" jsonschema:"description=Additional constraints applied when the rule matches (e.g. token age limits\\, required claims)."`
}

// Conditions defines matching conditions for a rule.
type Conditions struct {
	// === Request Conditions ===

	// Methods to match (e.g., GET, POST, PUT, DELETE)
	Methods []string `yaml:"methods,omitempty" jsonschema:"description=HTTP methods to match. Empty means any method.,example=GET,example=POST"`
	// Paths with glob pattern support (*, **)
	Paths []string `yaml:"paths,omitempty" jsonschema:"description=URL paths to match using glob patterns. Supports * (single segment) and ** (multiple segments). Example: '/api/*' matches '/api/users'. '/api/**' matches '/api/v1/users/123'."`
	// Hosts to match (exact match)
	Hosts []string `yaml:"hosts,omitempty" jsonschema:"description=Request hosts to match (exact match). Example: 'api.example.com'."`

	// PathTemplates with named parameter extraction
	PathTemplates []string `yaml:"path_templates,omitempty" jsonschema:"description=URL path templates with parameter extraction. Supports two syntaxes: 1) Simple: '/api/v1/{resource_type}/{resource_id}' - parameters in braces. 2) Regex: '^/api/v1/(?P<resource>\\w+)/(?P<id>[^/]+)$' - named capture groups. Extracted parameters: resource_type\\, resource_id\\, action are used for RBAC."`

	// === Subject (Token) Conditions ===

	// Roles required in the token
	Roles []string `yaml:"roles,omitempty" jsonschema:"description=Required roles from JWT token. User must have at least one of these roles. Roles are extracted from 'realm_access.roles' and 'resource_access.*.roles' claims.,example=admin,example=user"`
	// Scopes required in the token
	Scopes []string `yaml:"scopes,omitempty" jsonschema:"description=Required OAuth2 scopes. User must have at least one of these scopes. Extracted from 'scope' claim (space-separated).,example=read,example=write"`
	// Issuers allowed (exact match on 'iss' claim)
	Issuers []string `yaml:"issuers,omitempty" jsonschema:"description=Allowed token issuers (exact match on 'iss' claim). Use to restrict which identity providers are accepted.,example=https://keycloak.example.com/realms/app"`
	// Subjects patterns to match (glob/regex on 'sub' claim)
	Subjects []string `yaml:"subjects,omitempty" jsonschema:"description=Subject ID patterns to match against 'sub' claim. Supports glob (*) and regex patterns.,example=user-*,example=service-account-*"`
	// Audiences required (at least one must match 'aud' claim)
	Audiences []string `yaml:"audiences,omitempty" jsonschema:"description=Required audiences. At least one must be present in the 'aud' claim.,example=my-api,example=https://api.example.com"`

	// === Resource Conditions ===

	// ResourceTypes to match (from path extraction or input)
	ResourceTypes []string `yaml:"resource_types,omitempty" jsonschema:"description=Resource types to match. Compared against: 1) Values extracted from path_templates ({resource_type}). 2) Input resource.type field. Example: 'users'\\, 'orders'\\, 'documents'."`
	// Actions to match (from path extraction, input, or derived from method)
	Actions []string `yaml:"actions,omitempty" jsonschema:"description=Actions to match. Compared against: 1) Value extracted from path_templates ({action}). 2) Input resource.action field. 3) Derived from HTTP method (GET→read\\, POST→create\\, PUT/PATCH→update\\, DELETE→delete). Example: 'read'\\, 'write'\\, 'delete'\\, 'admin'."`

	// === Source Conditions ===

	// SourceIPs with CIDR support
	SourceIPs []string `yaml:"source_ips,omitempty" jsonschema:"description=Source IP addresses or CIDR ranges to match. Examples: '192.168.1.100'\\, '10.0.0.0/8'\\, '2001:db8::/32'. Use for IP-based access control."`
	// SourcePrincipals for mTLS/SPIFFE identity
	SourcePrincipals []string `yaml:"source_principals,omitempty" jsonschema:"description=Source principals (mTLS/SPIFFE identities) to match. Supports glob patterns. Example: 'spiffe://cluster.local/ns/*/sa/frontend'."`

	// === Extension ===

	// Custom conditions for advanced use cases
	Custom map[string]any `yaml:"custom,omitempty" jsonschema:"description=Custom conditions for extension. Key-value pairs passed to custom evaluators. Structure depends on your custom implementation."`
}

// Constraints defines constraints to be applied when the rule matches.
type Constraints struct {
	// MaxTokenAge limits how old a token can be
	MaxTokenAge string `yaml:"max_token_age,omitempty" jsonschema:"description=Maximum age of the JWT token (time since 'iat' claim). Tokens older than this are rejected even if otherwise valid. Format: Go duration string.,example=1h,example=30m,example=24h"`
	// RequiredClaims that must be present with specific values
	RequiredClaims map[string]string `yaml:"required_claims,omitempty" jsonschema:"description=Claims that must be present in the token with exact values. Key is the claim name (supports dot notation for nested claims)\\, value is the required value. Example: {'email_verified': 'true'\\, 'custom.level': 'premium'}."`
	// AllowedHeaders to forward to upstream
	AllowedHeaders []string `yaml:"allowed_headers,omitempty" jsonschema:"description=HTTP headers allowed to be forwarded to upstream services. Use for header-based authorization or filtering sensitive headers.,example=X-Request-ID,example=X-Correlation-ID"`
}

// NewBuiltinEngine creates a new built-in policy engine.
func NewBuiltinEngine(cfg config.BuiltinPolicyConfig) *BuiltinEngine {
	return &BuiltinEngine{
		rulesPath:   cfg.RulesPath,
		pathMatcher: NewPathMatcher(),
		cidrMatcher: NewCIDRMatcher(),
	}
}

// Name returns the engine name.
func (e *BuiltinEngine) Name() string {
	return "builtin"
}

// Start loads the rules from the configured path.
func (e *BuiltinEngine) Start(ctx context.Context) error {
	if err := e.loadRules(); err != nil {
		// If rules file doesn't exist, create default rules
		if os.IsNotExist(err) {
			logger.Warn("rules file not found, using default rules",
				logger.String("path", e.rulesPath),
			)
			e.mu.Lock()
			e.rules = e.defaultRules()
			e.version = "default"
			e.mu.Unlock()
			return nil
		}
		return err
	}
	return nil
}

// Stop shuts down the engine.
func (e *BuiltinEngine) Stop() error {
	return nil
}

// Healthy returns true if the engine has rules loaded.
func (e *BuiltinEngine) Healthy(ctx context.Context) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.rules != nil
}

// Evaluate evaluates the policy input against loaded rules.
func (e *BuiltinEngine) Evaluate(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
	e.mu.RLock()
	rules := e.rules
	version := e.version
	e.mu.RUnlock()

	if rules == nil {
		return domain.Deny("no rules loaded"), errors.ErrPolicyNotFound
	}

	start := time.Now()

	// Evaluate rules in priority order (rules should be pre-sorted)
	for _, rule := range rules.Rules {
		if !rule.Enabled {
			continue
		}

		if match, reasons, extractedResource := e.matchRule(rule, input); match {
			decision := &domain.Decision{
				Allowed:       rule.Effect == "allow",
				Reasons:       reasons,
				PolicyVersion: version,
				EvaluatedAt:   time.Now(),
				Cached:        false,
			}

			// Build metadata
			metadata := map[string]any{
				"matched_rule": rule.Name,
			}

			// Add extracted resource info to metadata
			if extractedResource != nil {
				metadata["resource"] = extractedResource
				// Also set resource on input for downstream use
				input.SetResource(extractedResource)
			}

			// Add constraints if present
			if rule.Constraints.MaxTokenAge != "" || len(rule.Constraints.RequiredClaims) > 0 {
				metadata["constraints"] = rule.Constraints
			}

			decision.Metadata = metadata

			logger.Debug("rule matched",
				logger.String("rule", rule.Name),
				logger.String("effect", rule.Effect),
				logger.Duration("duration", time.Since(start)),
			)

			return decision, nil
		}
	}

	// No rule matched, apply default
	if rules.DefaultDeny {
		return domain.Deny("no matching rule, default deny").
			WithMetadata("policy_version", version), nil
	}

	return domain.Allow("no matching rule, default allow").
		WithMetadata("policy_version", version), nil
}

// matchRule checks if a rule matches the input and extracts resource information.
func (e *BuiltinEngine) matchRule(rule Rule, input *domain.PolicyInput) (bool, []string, *domain.ResourceInfo) {
	var reasons []string
	var extractedResource *domain.ResourceInfo

	// Check methods
	if len(rule.Conditions.Methods) > 0 {
		if !containsString(rule.Conditions.Methods, input.Request.Method) {
			return false, nil, nil
		}
		reasons = append(reasons, fmt.Sprintf("method %s matched", input.Request.Method))
	}

	// Check path templates (with extraction) first
	if len(rule.Conditions.PathTemplates) > 0 {
		result := e.pathMatcher.MatchAny(rule.Conditions.PathTemplates, input.Request.Path)
		if !result.Matched {
			return false, nil, nil
		}
		reasons = append(reasons, fmt.Sprintf("path template %s matched", result.Pattern))

		// Extract resource info from path parameters
		if len(result.Params) > 0 {
			extractedResource = extractResourceFromParams(result.Params)
		}
	}

	// Check paths (glob patterns) - backward compatible
	if len(rule.Conditions.Paths) > 0 {
		result := e.pathMatcher.MatchWithGlobFallback(rule.Conditions.Paths, input.Request.Path)
		if !result.Matched {
			return false, nil, nil
		}
		reasons = append(reasons, fmt.Sprintf("path %s matched", input.Request.Path))

		// Extract resource if we haven't already and there are params
		if extractedResource == nil && len(result.Params) > 0 {
			extractedResource = extractResourceFromParams(result.Params)
		}
	}

	// Check hosts
	if len(rule.Conditions.Hosts) > 0 {
		if !containsString(rule.Conditions.Hosts, input.Request.Host) {
			return false, nil, nil
		}
	}

	// Derive action from method if not explicitly extracted
	derivedAction := domain.DeriveActionFromMethod(input.Request.Method)
	if extractedResource != nil && extractedResource.Action == "" {
		extractedResource.Action = derivedAction
	}

	// Check resource type conditions
	if len(rule.Conditions.ResourceTypes) > 0 {
		resourceType := ""
		if extractedResource != nil {
			resourceType = extractedResource.Type
		} else if input.Resource != nil {
			resourceType = input.Resource.Type
		}
		if resourceType == "" || !containsString(rule.Conditions.ResourceTypes, resourceType) {
			return false, nil, nil
		}
		reasons = append(reasons, fmt.Sprintf("resource type %s matched", resourceType))
	}

	// Check action conditions
	if len(rule.Conditions.Actions) > 0 {
		action := derivedAction
		if extractedResource != nil && extractedResource.Action != "" {
			action = extractedResource.Action
		} else if input.Resource != nil && input.Resource.Action != "" {
			action = input.Resource.Action
		}
		if !containsString(rule.Conditions.Actions, action) {
			return false, nil, nil
		}
		reasons = append(reasons, fmt.Sprintf("action %s matched", action))
	}

	// Check token conditions if token is present
	if input.Token != nil {
		// Check roles
		if len(rule.Conditions.Roles) > 0 {
			if !hasAnyRole(input.Token.Roles, rule.Conditions.Roles) {
				return false, nil, nil
			}
			reasons = append(reasons, "required roles present")
		}

		// Check scopes
		if len(rule.Conditions.Scopes) > 0 {
			if !hasAnyScope(input.Token.Scopes, rule.Conditions.Scopes) {
				return false, nil, nil
			}
			reasons = append(reasons, "required scopes present")
		}

		// Check issuers
		if len(rule.Conditions.Issuers) > 0 {
			if !containsString(rule.Conditions.Issuers, input.Token.Issuer) {
				return false, nil, nil
			}
		}

		// Check audiences
		if len(rule.Conditions.Audiences) > 0 {
			if !hasAnyAudience(input.Token.Audience, rule.Conditions.Audiences) {
				return false, nil, nil
			}
		}

		// Check subject patterns
		if len(rule.Conditions.Subjects) > 0 {
			result := e.pathMatcher.MatchAny(rule.Conditions.Subjects, input.Token.Subject)
			if !result.Matched {
				return false, nil, nil
			}
		}
	} else {
		// No token but token conditions required
		if len(rule.Conditions.Roles) > 0 ||
			len(rule.Conditions.Scopes) > 0 ||
			len(rule.Conditions.Issuers) > 0 {
			return false, nil, nil
		}
	}

	// Check source conditions with proper CIDR matching
	if len(rule.Conditions.SourceIPs) > 0 {
		if !e.cidrMatcher.Match(rule.Conditions.SourceIPs, input.Source.Address) {
			return false, nil, nil
		}
	}

	if len(rule.Conditions.SourcePrincipals) > 0 {
		result := e.pathMatcher.MatchAny(rule.Conditions.SourcePrincipals, input.Source.Principal)
		if !result.Matched {
			return false, nil, nil
		}
	}

	reasons = append(reasons, fmt.Sprintf("rule '%s' matched", rule.Name))
	return true, reasons, extractedResource
}

// extractResourceFromParams creates a ResourceInfo from extracted path parameters.
func extractResourceFromParams(params map[string]string) *domain.ResourceInfo {
	if len(params) == 0 {
		return nil
	}

	resource := &domain.ResourceInfo{
		Params: params,
	}

	// Extract resource type from various conventional names
	for _, key := range []string{"resource_type", "resource", "type", "entity", "collection"} {
		if v, ok := params[key]; ok && resource.Type == "" {
			resource.Type = v
		}
	}

	// Extract resource ID from various conventional names
	for _, key := range []string{"resource_id", "id", "uuid", "key"} {
		if v, ok := params[key]; ok && resource.ID == "" {
			resource.ID = v
		}
	}

	// Extract action
	if v, ok := params["action"]; ok {
		resource.Action = v
	}

	return resource
}

// loadRules loads rules from the YAML file.
func (e *BuiltinEngine) loadRules() error {
	data, err := os.ReadFile(e.rulesPath)
	if err != nil {
		return err
	}

	var rules RuleSet
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return errors.Wrap(errors.ErrPolicyInvalid, err.Error())
	}

	// Sort rules by priority (higher priority first)
	sortRules(rules.Rules)

	e.mu.Lock()
	e.rules = &rules
	e.version = rules.Version
	e.mu.Unlock()

	logger.Info("policy rules loaded",
		logger.String("version", rules.Version),
		logger.Int("rule_count", len(rules.Rules)),
		logger.String("path", e.rulesPath),
	)

	return nil
}

// defaultRules returns default rules when no rules file exists.
func (e *BuiltinEngine) defaultRules() *RuleSet {
	return &RuleSet{
		Version:     "default-v1",
		Description: "Default policy rules",
		DefaultDeny: true,
		Rules: []Rule{
			{
				Name:        "allow-health-endpoints",
				Description: "Allow access to health check endpoints",
				Priority:    1000,
				Enabled:     true,
				Conditions: Conditions{
					Paths:   []string{"/health", "/health/*", "/ready", "/live"},
					Methods: []string{"GET"},
				},
				Effect: "allow",
			},
			{
				Name:        "allow-metrics",
				Description: "Allow access to metrics endpoint",
				Priority:    999,
				Enabled:     true,
				Conditions: Conditions{
					Paths:   []string{"/metrics"},
					Methods: []string{"GET"},
				},
				Effect: "allow",
			},
		},
	}
}

// ReloadRules reloads rules from the file.
func (e *BuiltinEngine) ReloadRules() error {
	return e.loadRules()
}

// GetRulesPath returns the rules file path.
func (e *BuiltinEngine) GetRulesPath() string {
	return e.rulesPath
}

// Helper functions

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func hasAnyRole(userRoles, requiredRoles []string) bool {
	roleSet := make(map[string]bool)
	for _, r := range userRoles {
		roleSet[r] = true
	}
	for _, r := range requiredRoles {
		if roleSet[r] {
			return true
		}
	}
	return false
}

func hasAnyScope(userScopes, requiredScopes []string) bool {
	scopeSet := make(map[string]bool)
	for _, s := range userScopes {
		scopeSet[s] = true
	}
	for _, s := range requiredScopes {
		if scopeSet[s] {
			return true
		}
	}
	return false
}

func hasAnyAudience(tokenAud, requiredAud []string) bool {
	for _, required := range requiredAud {
		for _, actual := range tokenAud {
			if actual == required {
				return true
			}
		}
	}
	return false
}


func sortRules(rules []Rule) {
	// Simple bubble sort for now (rules count should be small)
	for i := 0; i < len(rules)-1; i++ {
		for j := 0; j < len(rules)-i-1; j++ {
			if rules[j].Priority < rules[j+1].Priority {
				rules[j], rules[j+1] = rules[j+1], rules[j]
			}
		}
	}
}
