package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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
	mu       sync.RWMutex
	rules    *RuleSet
	rulesPath string
	version  string
}

// RuleSet contains all authorization rules.
type RuleSet struct {
	Version     string `yaml:"version"`
	Description string `yaml:"description"`
	Rules       []Rule `yaml:"rules"`
	DefaultDeny bool   `yaml:"default_deny"`
}

// Rule defines a single authorization rule.
type Rule struct {
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	Priority    int         `yaml:"priority"`
	Enabled     bool        `yaml:"enabled"`
	Conditions  Conditions  `yaml:"conditions"`
	Effect      string      `yaml:"effect"` // allow, deny
	Constraints Constraints `yaml:"constraints,omitempty"`
}

// Conditions defines matching conditions for a rule.
type Conditions struct {
	// Request conditions
	Methods []string `yaml:"methods,omitempty"`
	Paths   []string `yaml:"paths,omitempty"`   // Glob patterns
	Hosts   []string `yaml:"hosts,omitempty"`

	// Subject conditions
	Roles           []string `yaml:"roles,omitempty"`
	Scopes          []string `yaml:"scopes,omitempty"`
	Issuers         []string `yaml:"issuers,omitempty"`
	Subjects        []string `yaml:"subjects,omitempty"` // Subject ID patterns
	Audiences       []string `yaml:"audiences,omitempty"`

	// Source conditions
	SourceIPs       []string `yaml:"source_ips,omitempty"`       // CIDR patterns
	SourcePrincipals []string `yaml:"source_principals,omitempty"` // SPIFFE IDs

	// Custom conditions (for extension)
	Custom map[string]any `yaml:"custom,omitempty"`
}

// Constraints defines constraints to be applied when the rule matches.
type Constraints struct {
	MaxTokenAge    string            `yaml:"max_token_age,omitempty"`
	RequiredClaims map[string]string `yaml:"required_claims,omitempty"`
	AllowedHeaders []string          `yaml:"allowed_headers,omitempty"`
}

// NewBuiltinEngine creates a new built-in policy engine.
func NewBuiltinEngine(cfg config.BuiltinPolicyConfig) *BuiltinEngine {
	return &BuiltinEngine{
		rulesPath: cfg.RulesPath,
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

		if match, reasons := e.matchRule(rule, input); match {
			decision := &domain.Decision{
				Allowed:       rule.Effect == "allow",
				Reasons:       reasons,
				PolicyVersion: version,
				EvaluatedAt:   time.Now(),
				Cached:        false,
			}

			// Add constraints if present
			if rule.Constraints.MaxTokenAge != "" || len(rule.Constraints.RequiredClaims) > 0 {
				decision.Metadata = map[string]any{
					"matched_rule": rule.Name,
					"constraints":  rule.Constraints,
				}
			}

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

// matchRule checks if a rule matches the input.
func (e *BuiltinEngine) matchRule(rule Rule, input *domain.PolicyInput) (bool, []string) {
	var reasons []string

	// Check methods
	if len(rule.Conditions.Methods) > 0 {
		if !containsString(rule.Conditions.Methods, input.Request.Method) {
			return false, nil
		}
		reasons = append(reasons, fmt.Sprintf("method %s matched", input.Request.Method))
	}

	// Check paths (glob patterns)
	if len(rule.Conditions.Paths) > 0 {
		if !matchesAnyPattern(rule.Conditions.Paths, input.Request.Path) {
			return false, nil
		}
		reasons = append(reasons, fmt.Sprintf("path %s matched", input.Request.Path))
	}

	// Check hosts
	if len(rule.Conditions.Hosts) > 0 {
		if !containsString(rule.Conditions.Hosts, input.Request.Host) {
			return false, nil
		}
	}

	// Check token conditions if token is present
	if input.Token != nil {
		// Check roles
		if len(rule.Conditions.Roles) > 0 {
			if !hasAnyRole(input.Token.Roles, rule.Conditions.Roles) {
				return false, nil
			}
			reasons = append(reasons, "required roles present")
		}

		// Check scopes
		if len(rule.Conditions.Scopes) > 0 {
			if !hasAnyScope(input.Token.Scopes, rule.Conditions.Scopes) {
				return false, nil
			}
			reasons = append(reasons, "required scopes present")
		}

		// Check issuers
		if len(rule.Conditions.Issuers) > 0 {
			if !containsString(rule.Conditions.Issuers, input.Token.Issuer) {
				return false, nil
			}
		}

		// Check audiences
		if len(rule.Conditions.Audiences) > 0 {
			if !hasAnyAudience(input.Token.Audience, rule.Conditions.Audiences) {
				return false, nil
			}
		}

		// Check subject patterns
		if len(rule.Conditions.Subjects) > 0 {
			if !matchesAnyPattern(rule.Conditions.Subjects, input.Token.Subject) {
				return false, nil
			}
		}
	} else {
		// No token but token conditions required
		if len(rule.Conditions.Roles) > 0 ||
			len(rule.Conditions.Scopes) > 0 ||
			len(rule.Conditions.Issuers) > 0 {
			return false, nil
		}
	}

	// Check source conditions
	if len(rule.Conditions.SourceIPs) > 0 {
		if !matchesAnyCIDR(rule.Conditions.SourceIPs, input.Source.Address) {
			return false, nil
		}
	}

	if len(rule.Conditions.SourcePrincipals) > 0 {
		if !matchesAnyPattern(rule.Conditions.SourcePrincipals, input.Source.Principal) {
			return false, nil
		}
	}

	reasons = append(reasons, fmt.Sprintf("rule '%s' matched", rule.Name))
	return true, reasons
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

func matchesAnyPattern(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if matched, _ := filepath.Match(pattern, value); matched {
			return true
		}
		// Try regex if glob doesn't match
		if strings.HasPrefix(pattern, "^") || strings.HasSuffix(pattern, "$") {
			if re, err := regexp.Compile(pattern); err == nil && re.MatchString(value) {
				return true
			}
		}
	}
	return false
}

func matchesAnyCIDR(cidrs []string, ip string) bool {
	// Simple exact match for now
	// TODO: implement proper CIDR matching
	for _, cidr := range cidrs {
		if cidr == ip || cidr == "*" {
			return true
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
