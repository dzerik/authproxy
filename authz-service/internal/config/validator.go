package config

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// ValidationError contains detailed information about a validation error.
type ValidationError struct {
	Field   string
	Message string
	Details []string
}

func (e ValidationError) Error() string {
	if len(e.Details) > 0 {
		return fmt.Sprintf("%s: %s\n    - %s", e.Field, e.Message, strings.Join(e.Details, "\n    - "))
	}
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidationErrors is a collection of validation errors.
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	var sb strings.Builder
	sb.WriteString("configuration validation failed:\n")
	for _, err := range e {
		sb.WriteString("  ")
		sb.WriteString(err.Error())
		sb.WriteString("\n")
	}
	return sb.String()
}

// ConfigValidator validates configuration.
type ConfigValidator struct {
	errors ValidationErrors
}

// NewConfigValidator creates a new ConfigValidator.
func NewConfigValidator() *ConfigValidator {
	return &ConfigValidator{}
}

// ValidateServices validates ServicesConfig.
// envCfg is needed to check for port conflicts with management/metrics ports.
// rulesConfig is needed to validate rule_sets references against rules.yaml.
func (v *ConfigValidator) ValidateServices(cfg *ServicesConfig, envCfg *EnvironmentConfig, rulesConfig *RulesConfig) error {
	v.errors = nil

	// 1. Validate required fields are present
	v.validateRequiredFields(cfg)

	// 2. Validate port uniqueness (including management/metrics)
	v.validatePortUniqueness(cfg, envCfg)

	// 3. Validate rule set references exist in rules.yaml
	v.validateRuleSetReferences(cfg, rulesConfig)

	if len(v.errors) > 0 {
		return v.errors
	}
	return nil
}

// ValidateRules validates RulesConfig.
func (v *ConfigValidator) ValidateRules(cfg *RulesConfig) error {
	v.errors = nil

	// Validate priority uniqueness in rules
	v.validateRulesPriorities(cfg)

	if len(v.errors) > 0 {
		return v.errors
	}
	return nil
}

// parsePortFromAddr extracts port number from address string like ":8080" or "0.0.0.0:8080".
// Returns 0 if the address is empty or port cannot be parsed.
func parsePortFromAddr(addr string) int {
	if addr == "" {
		return 0
	}
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		// Try parsing as just a port (e.g., ":8080" without host)
		if strings.HasPrefix(addr, ":") {
			portStr = addr[1:]
		} else {
			return 0
		}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}
	return port
}

// validatePortUniqueness checks that all ports are unique across all listeners and system ports.
func (v *ConfigValidator) validatePortUniqueness(cfg *ServicesConfig, envCfg *EnvironmentConfig) {
	ports := make(map[int][]string) // port -> listener names

	// Helper to add port to map
	addPort := func(addr, name string) {
		if port := parsePortFromAddr(addr); port > 0 {
			ports[port] = append(ports[port], name)
		}
	}

	// Collect management ports from environment config
	if envCfg != nil && envCfg.Management.Enabled {
		addPort(envCfg.Management.AdminAddr, "management:admin")
		addPort(envCfg.Management.HealthAddr, "management:health")
		addPort(envCfg.Management.ReadyAddr, "management:ready")
	}

	// Collect HTTP server port
	if envCfg != nil && envCfg.Server.HTTP.Enabled {
		addPort(envCfg.Server.HTTP.Addr, "server:http")
	}

	// Collect gRPC server port
	if envCfg != nil && envCfg.Server.GRPC.Enabled {
		addPort(envCfg.Server.GRPC.Addr, "server:grpc")
	}

	// Collect proxy listener ports
	for _, l := range cfg.Proxy.Listeners {
		ports[l.Port] = append(ports[l.Port], fmt.Sprintf("proxy:%s", l.Name))
	}

	// Collect egress listener ports
	for _, l := range cfg.Egress.Listeners {
		ports[l.Port] = append(ports[l.Port], fmt.Sprintf("egress:%s", l.Name))
	}

	// Check for conflicts
	for port, listeners := range ports {
		if len(listeners) > 1 {
			// Sort for deterministic output
			sort.Strings(listeners)
			v.errors = append(v.errors, ValidationError{
				Field:   "listeners",
				Message: fmt.Sprintf("port %d is used by multiple listeners", port),
				Details: listeners,
			})
		}
	}
}

// validateRuleSetReferences checks that all referenced rule sets exist in rules.yaml.
func (v *ConfigValidator) validateRuleSetReferences(cfg *ServicesConfig, rulesConfig *RulesConfig) {
	for _, l := range cfg.Proxy.Listeners {
		for _, rsName := range l.RuleSets {
			if rulesConfig == nil || rulesConfig.RuleSets == nil {
				v.errors = append(v.errors, ValidationError{
					Field:   fmt.Sprintf("proxy.listeners[%s].rule_sets", l.Name),
					Message: fmt.Sprintf("rule set %q not found (no rule_sets defined in rules.yaml)", rsName),
				})
				continue
			}
			if _, exists := rulesConfig.RuleSets[rsName]; !exists {
				// List available rule sets for better error message
				var available []string
				for name := range rulesConfig.RuleSets {
					available = append(available, name)
				}
				sort.Strings(available)
				v.errors = append(v.errors, ValidationError{
					Field:   fmt.Sprintf("proxy.listeners[%s].rule_sets", l.Name),
					Message: fmt.Sprintf("rule set %q not found in rules.yaml", rsName),
					Details: []string{fmt.Sprintf("available: %s", strings.Join(available, ", "))},
				})
			}
		}
	}
}


// validateRequiredFields checks that all required fields are present and not empty.
func (v *ConfigValidator) validateRequiredFields(cfg *ServicesConfig) {
	// Check that proxy listeners have routing configuration
	for _, l := range cfg.Proxy.Listeners {
		hasInlineRoutes := len(l.Routes) > 0

		if !hasInlineRoutes {
			v.errors = append(v.errors, ValidationError{
				Field:   fmt.Sprintf("proxy.listeners[%s]", l.Name),
				Message: "listener must have at least one route defined",
			})
		}

		// Check that upstreams referenced in routes exist
		for i, route := range l.Routes {
			if route.Upstream != "" {
				if _, exists := l.Upstreams[route.Upstream]; !exists {
					var available []string
					for name := range l.Upstreams {
						available = append(available, name)
					}
					sort.Strings(available)
					v.errors = append(v.errors, ValidationError{
						Field:   fmt.Sprintf("proxy.listeners[%s].routes[%d]", l.Name, i),
						Message: fmt.Sprintf("upstream %q not found in listener upstreams", route.Upstream),
						Details: []string{fmt.Sprintf("available: %s", strings.Join(available, ", "))},
					})
				}
			}
		}
	}

	// Check that egress listeners have targets
	for _, l := range cfg.Egress.Listeners {
		if len(l.Targets) == 0 && len(l.Routes) == 0 {
			v.errors = append(v.errors, ValidationError{
				Field:   fmt.Sprintf("egress.listeners[%s]", l.Name),
				Message: "listener must have at least one target or route",
			})
		}
	}
}

// validateRulesPriorities checks for priority conflicts in authorization rules.
func (v *ConfigValidator) validateRulesPriorities(cfg *RulesConfig) {
	if cfg == nil {
		return
	}

	// Check for priority conflicts in global rules
	if len(cfg.Rules) > 0 {
		priorities := make(map[int][]string) // priority -> rule names
		for _, rule := range cfg.Rules {
			name := rule.Name
			if name == "" {
				name = fmt.Sprintf("rule@%d", rule.Priority)
			}
			priorities[rule.Priority] = append(priorities[rule.Priority], name)
		}

		for priority, rules := range priorities {
			if len(rules) > 1 {
				sort.Strings(rules)
				v.errors = append(v.errors, ValidationError{
					Field:   "rules",
					Message: fmt.Sprintf("priority %d is used by multiple global rules", priority),
					Details: rules,
				})
			}
		}
	}

	// Check for priority conflicts within each rule set
	for setName, rules := range cfg.RuleSets {
		if len(rules) == 0 {
			v.errors = append(v.errors, ValidationError{
				Field:   fmt.Sprintf("rule_sets[%s]", setName),
				Message: "rule set cannot be empty, must contain at least one rule",
			})
			continue
		}

		priorities := make(map[int][]string)
		for _, rule := range rules {
			name := rule.Name
			if name == "" {
				name = fmt.Sprintf("rule@%d", rule.Priority)
			}
			priorities[rule.Priority] = append(priorities[rule.Priority], name)
		}

		for priority, ruleNames := range priorities {
			if len(ruleNames) > 1 {
				sort.Strings(ruleNames)
				v.errors = append(v.errors, ValidationError{
					Field:   fmt.Sprintf("rule_sets[%s]", setName),
					Message: fmt.Sprintf("priority %d is used by multiple rules", priority),
					Details: ruleNames,
				})
			}
		}
	}
}

// GetRulesForListener returns merged authorization rules for a listener.
// Rules are merged from referenced rule sets (in order specified) plus global rules.
func GetRulesForListener(listener ProxyListenerConfig, rulesConfig *RulesConfig) []Rule {
	if rulesConfig == nil {
		return nil
	}

	var result []Rule

	// Add rules from referenced rule sets (in order)
	for _, rsName := range listener.RuleSets {
		if rules, ok := rulesConfig.RuleSets[rsName]; ok {
			result = append(result, rules...)
		}
	}

	// Add global rules
	result = append(result, rulesConfig.Rules...)

	return result
}
