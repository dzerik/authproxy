// Package policy provides policy evaluation engines.
package policy

import (
	"container/list"
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

const (
	// DefaultCELCacheSize is the default maximum number of cached CEL programs.
	DefaultCELCacheSize = 500
)

// CELEvaluator provides CEL expression evaluation with LRU caching.
type CELEvaluator struct {
	env *cel.Env
	mu  sync.RWMutex

	// Cache for compiled programs with LRU eviction
	programs map[string]*celCacheEntry
	order    *list.List // LRU order: front = most recently used
	capacity int
}

// celCacheEntry holds a cached CEL program with its LRU list element.
type celCacheEntry struct {
	program    cel.Program
	expression string
	element    *list.Element
}

// NewCELEvaluator creates a new CEL evaluator with predefined variables and default cache capacity.
func NewCELEvaluator() (*CELEvaluator, error) {
	return NewCELEvaluatorWithCapacity(DefaultCELCacheSize)
}

// NewCELEvaluatorWithCapacity creates a new CEL evaluator with specified cache capacity.
func NewCELEvaluatorWithCapacity(capacity int) (*CELEvaluator, error) {
	if capacity <= 0 {
		capacity = DefaultCELCacheSize
	}

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

		// Environment info (production, staging, etc.)
		cel.Variable("env", cel.MapType(cel.StringType, cel.DynType)),

		// TLS/mTLS client certificate info
		cel.Variable("tls", cel.MapType(cel.StringType, cel.DynType)),

		// Request body (when enabled)
		// WARNING: Body access has security and performance implications
		cel.Variable("body", cel.MapType(cel.StringType, cel.DynType)),

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
		programs: make(map[string]*celCacheEntry),
		order:    list.New(),
		capacity: capacity,
	}, nil
}

// Compile compiles a CEL expression and caches the program with LRU eviction.
func (e *CELEvaluator) Compile(expression string) (cel.Program, error) {
	// Check cache first (read lock)
	e.mu.RLock()
	if entry, ok := e.programs[expression]; ok {
		e.mu.RUnlock()
		// Move to front (requires write lock)
		e.mu.Lock()
		// Double-check after acquiring write lock
		if entry, ok := e.programs[expression]; ok {
			e.order.MoveToFront(entry.element)
		}
		e.mu.Unlock()
		return entry.program, nil
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

	// Cache program with LRU
	e.mu.Lock()
	defer e.mu.Unlock()

	// Double-check if another goroutine already added it
	if entry, ok := e.programs[expression]; ok {
		e.order.MoveToFront(entry.element)
		return entry.program, nil
	}

	// Evict oldest if at capacity
	for e.order.Len() >= e.capacity {
		e.evictOldest()
	}

	// Add new entry at front
	entry := &celCacheEntry{
		program:    prg,
		expression: expression,
	}
	entry.element = e.order.PushFront(entry)
	e.programs[expression] = entry

	return prg, nil
}

// evictOldest removes the least recently used cache entry.
func (e *CELEvaluator) evictOldest() {
	oldest := e.order.Back()
	if oldest == nil {
		return
	}
	entry := oldest.Value.(*celCacheEntry)
	delete(e.programs, entry.expression)
	e.order.Remove(oldest)
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
	e.programs = make(map[string]*celCacheEntry)
	e.order.Init()
	e.mu.Unlock()
}

// CacheSize returns the number of cached programs.
func (e *CELEvaluator) CacheSize() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.programs)
}

// CacheCapacity returns the maximum cache capacity.
func (e *CELEvaluator) CacheCapacity() int {
	return e.capacity
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

	// Environment variables
	features := input.Env.Features
	if features == nil {
		features = map[string]bool{}
	}
	custom := input.Env.Custom
	if custom == nil {
		custom = map[string]any{}
	}
	vars["env"] = map[string]any{
		"name":     input.Env.Name,
		"region":   input.Env.Region,
		"cluster":  input.Env.Cluster,
		"version":  input.Env.Version,
		"features": features,
		"custom":   custom,
	}

	// TLS/mTLS variables
	if input.TLS != nil {
		spiffe := map[string]any{
			"trust_domain":    "",
			"namespace":       "",
			"service_account": "",
			"path":            "",
			"uri":             "",
		}
		if input.TLS.SPIFFE != nil {
			spiffe = map[string]any{
				"trust_domain":    input.TLS.SPIFFE.TrustDomain,
				"namespace":       input.TLS.SPIFFE.Namespace,
				"service_account": input.TLS.SPIFFE.ServiceAccount,
				"path":            input.TLS.SPIFFE.Path,
				"uri":             input.TLS.SPIFFE.URI,
			}
		}
		dnsNames := input.TLS.DNSNames
		if dnsNames == nil {
			dnsNames = []string{}
		}
		uris := input.TLS.URIs
		if uris == nil {
			uris = []string{}
		}
		raw := input.TLS.Raw
		if raw == nil {
			raw = map[string]string{}
		}
		vars["tls"] = map[string]any{
			"verified":    input.TLS.Verified,
			"subject":     input.TLS.Subject,
			"issuer":      input.TLS.Issuer,
			"common_name": input.TLS.CommonName,
			"serial":      input.TLS.Serial,
			"not_before":  input.TLS.NotBefore,
			"not_after":   input.TLS.NotAfter,
			"dns_names":   dnsNames,
			"uris":        uris,
			"fingerprint": input.TLS.Fingerprint,
			"spiffe":      spiffe,
			"raw":         raw,
		}
	} else {
		vars["tls"] = map[string]any{
			"verified":    false,
			"subject":     "",
			"issuer":      "",
			"common_name": "",
			"serial":      "",
			"not_before":  int64(0),
			"not_after":   int64(0),
			"dns_names":   []string{},
			"uris":        []string{},
			"fingerprint": "",
			"spiffe": map[string]any{
				"trust_domain":    "",
				"namespace":       "",
				"service_account": "",
				"path":            "",
				"uri":             "",
			},
			"raw": map[string]string{},
		}
	}

	// Request body (when available)
	if input.Body != nil && len(input.Body) > 0 {
		vars["body"] = input.Body
	} else {
		vars["body"] = map[string]any{}
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
