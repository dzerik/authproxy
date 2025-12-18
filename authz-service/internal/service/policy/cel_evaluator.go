// Package policy provides policy evaluation engines.
package policy

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

	"github.com/your-org/authz-service/internal/domain"
	"github.com/your-org/authz-service/pkg/logger"
)

// CELEvaluator provides CEL expression evaluation with caching.
type CELEvaluator struct {
	env *cel.Env
	mu  sync.RWMutex

	// Cache for compiled programs (expression string -> compiled program)
	programs map[string]cel.Program
}

// NewCELEvaluator creates a new CEL evaluator with predefined variables.
func NewCELEvaluator() (*CELEvaluator, error) {
	// Define CEL environment with available variables
	env, err := cel.NewEnv(
		// Token variables (from JWT)
		cel.Variable("token", cel.MapType(cel.StringType, cel.DynType)),

		// Request variables
		cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),

		// Extracted resource
		cel.Variable("resource", cel.MapType(cel.StringType, cel.DynType)),

		// Source info
		cel.Variable("source", cel.MapType(cel.StringType, cel.DynType)),

		// Context
		cel.Variable("context", cel.MapType(cel.StringType, cel.DynType)),

		// Current timestamp
		cel.Variable("now", cel.TimestampType),

		// Custom function: CIDR matching
		cel.Function("cidrMatch",
			cel.Overload("cidr_match_string_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(cidrMatchFunc),
			),
		),

		// Custom function: Check if string matches glob pattern
		cel.Function("globMatch",
			cel.Overload("glob_match_string_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(globMatchFunc),
			),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	return &CELEvaluator{
		env:      env,
		programs: make(map[string]cel.Program),
	}, nil
}

// Compile compiles a CEL expression and caches the program.
func (e *CELEvaluator) Compile(expression string) (cel.Program, error) {
	// Check cache first
	e.mu.RLock()
	if prg, ok := e.programs[expression]; ok {
		e.mu.RUnlock()
		return prg, nil
	}
	e.mu.RUnlock()

	// Compile expression
	ast, issues := e.env.Compile(expression)
	if issues.Err() != nil {
		return nil, fmt.Errorf("CEL compilation error: %w", issues.Err())
	}

	// Check output type
	if ast.OutputType() != cel.BoolType {
		return nil, fmt.Errorf("CEL expression must return boolean, got %v", ast.OutputType())
	}

	// Create program
	prg, err := e.env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL program: %w", err)
	}

	// Cache program
	e.mu.Lock()
	e.programs[expression] = prg
	e.mu.Unlock()

	return prg, nil
}

// Evaluate evaluates a CEL expression against the policy input.
func (e *CELEvaluator) Evaluate(expression string, input *domain.PolicyInput) (bool, error) {
	prg, err := e.Compile(expression)
	if err != nil {
		return false, err
	}

	// Build evaluation context
	vars := e.buildEvalContext(input)

	out, _, err := prg.Eval(vars)
	if err != nil {
		return false, fmt.Errorf("CEL evaluation error: %w", err)
	}

	result, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("CEL expression must return boolean, got %T", out.Value())
	}

	return result, nil
}

// ValidateExpression validates a CEL expression without evaluating it.
func (e *CELEvaluator) ValidateExpression(expression string) error {
	if expression == "" {
		return nil
	}

	// Check length limit
	const maxExpressionLength = 4096
	if len(expression) > maxExpressionLength {
		return fmt.Errorf("expression too long: %d > %d", len(expression), maxExpressionLength)
	}

	// Try to compile
	_, err := e.Compile(expression)
	return err
}

// ClearCache clears the compiled programs cache.
func (e *CELEvaluator) ClearCache() {
	e.mu.Lock()
	e.programs = make(map[string]cel.Program)
	e.mu.Unlock()
}

// CacheSize returns the number of cached programs.
func (e *CELEvaluator) CacheSize() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.programs)
}

// buildEvalContext builds the evaluation context from PolicyInput.
func (e *CELEvaluator) buildEvalContext(input *domain.PolicyInput) map[string]any {
	vars := map[string]any{
		"now": time.Now(),
	}

	// Token variables
	if input.Token != nil {
		vars["token"] = map[string]any{
			"sub":       input.Token.Subject,
			"iss":       input.Token.Issuer,
			"aud":       input.Token.Audience,
			"exp":       input.Token.ExpiresAt,
			"iat":       input.Token.IssuedAt,
			"roles":     input.Token.Roles,
			"scopes":    input.Token.Scopes,
			"groups":    input.Token.Groups,
			"client_id": input.Token.ClientID,
			"claims":    input.Token.ExtraClaims,
			"valid":     input.Token.Valid,
		}
	} else {
		vars["token"] = map[string]any{
			"valid":  false,
			"roles":  []string{},
			"scopes": []string{},
		}
	}

	// Request variables
	vars["request"] = map[string]any{
		"method":   input.Request.Method,
		"path":     input.Request.Path,
		"host":     input.Request.Host,
		"headers":  input.Request.Headers,
		"query":    input.Request.Query,
		"protocol": input.Request.Protocol,
		"time":     time.Now(),
	}

	// Resource variables
	if input.Resource != nil {
		vars["resource"] = map[string]any{
			"type":   input.Resource.Type,
			"id":     input.Resource.ID,
			"action": input.Resource.Action,
			"params": input.Resource.Params,
		}
	} else {
		vars["resource"] = map[string]any{
			"type":   "",
			"id":     "",
			"action": "",
			"params": map[string]string{},
		}
	}

	// Source variables
	vars["source"] = map[string]any{
		"address":         input.Source.Address,
		"principal":       input.Source.Principal,
		"namespace":       input.Source.Namespace,
		"service_account": input.Source.ServiceAccount,
	}

	// Context variables
	vars["context"] = map[string]any{
		"request_id": input.Context.RequestID,
		"trace_id":   input.Context.TraceID,
		"timestamp":  input.Context.Timestamp,
		"custom":     input.Context.Custom,
	}

	return vars
}

// cidrMatchFunc is a custom CEL function for CIDR matching.
func cidrMatchFunc(lhs, rhs ref.Val) ref.Val {
	ipStr, ok1 := lhs.Value().(string)
	cidrStr, ok2 := rhs.Value().(string)
	if !ok1 || !ok2 {
		return types.False
	}

	// Parse IP
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return types.False
	}

	// Parse CIDR
	_, cidr, err := net.ParseCIDR(cidrStr)
	if err != nil {
		// Try as single IP
		singleIP := net.ParseIP(cidrStr)
		if singleIP != nil {
			return types.Bool(ip.Equal(singleIP))
		}
		return types.False
	}

	return types.Bool(cidr.Contains(ip))
}

// globMatchFunc is a custom CEL function for glob pattern matching.
func globMatchFunc(lhs, rhs ref.Val) ref.Val {
	str, ok1 := lhs.Value().(string)
	pattern, ok2 := rhs.Value().(string)
	if !ok1 || !ok2 {
		return types.False
	}

	// Use the package-level globMatch function
	matched := globMatch(pattern, str)
	return types.Bool(matched)
}

// PrecompileExpressions precompiles a list of expressions.
// Useful for validating all rules at startup.
func (e *CELEvaluator) PrecompileExpressions(expressions []string) error {
	for _, expr := range expressions {
		if expr == "" {
			continue
		}
		if _, err := e.Compile(expr); err != nil {
			logger.Error("failed to precompile CEL expression",
				logger.String("expression", expr),
				logger.Err(err),
			)
			return fmt.Errorf("failed to compile expression %q: %w", expr, err)
		}
	}
	return nil
}
