# Custom Evaluator Implementation Analysis

## 1. Overview

This document analyzes the implementation of a custom expression evaluator for the authorization rules engine, enabling advanced condition matching with operators like comparisons, `in`, `not`, `and`, `or`, etc.

### Current State

The current `Conditions` struct in `builtin.go` supports:
- Static array-based matching (roles, scopes, methods, paths)
- Glob/regex patterns for paths and subjects
- CIDR matching for IPs
- `Custom` field (`map[string]any`) for extension

**Limitation**: No support for dynamic expressions like:
```yaml
# Cannot do this today:
conditions:
  expression: "token.sub == resource.owner_id"
  expression: "token.claims.level >= 3 and 'admin' in token.roles"
```

---

## 2. Library Comparison

### 2.1 CEL-Go (Google Common Expression Language)

**Repository**: `github.com/google/cel-go`
**Trust Score**: 8.9 | **Snippets**: 168

#### Pros
- Designed specifically for security policies (used in Kubernetes, Envoy, Firebase)
- Non-Turing complete (safe, cannot loop forever)
- Type-safe with compile-time checking
- Excellent documentation and Google support
- Native protobuf support
- Partial evaluation support (for caching)

#### Cons
- Larger dependency footprint
- Slightly more complex setup
- Requires type declarations upfront

#### Syntax Examples
```cel
// Comparisons
token.sub == "user123"
request.time > timestamp("2024-01-01T00:00:00Z")

// Logical operators
token.roles.exists(r, r == "admin") && token.scopes.exists(s, s == "write")
!token.expired && token.iss == "https://keycloak.example.com"

// Membership
"admin" in token.roles
token.aud.exists(a, a == "my-api")

// String operations
request.path.startsWith("/api/v1")
token.email.endsWith("@company.com")
request.host.matches("^api\\.(dev|staging)\\.example\\.com$")

// Ternary
token.level >= 3 ? "premium" : "basic"

// List operations
token.roles.all(r, r.startsWith("app_"))
resource.tags.exists(t, t in ["public", "shared"])

// Comparison with extracted resource
resource.owner_id == token.sub
resource.team in token.teams
```

#### Setup Code
```go
import "github.com/google/cel-go/cel"

// Define environment with available variables
env, err := cel.NewEnv(
    cel.Variable("token", cel.ObjectType("TokenInfo")),
    cel.Variable("request", cel.ObjectType("RequestInfo")),
    cel.Variable("resource", cel.ObjectType("ResourceInfo")),
    cel.Variable("source", cel.ObjectType("SourceInfo")),
)

// Compile expression (can cache AST)
ast, issues := env.Compile(`token.roles.exists(r, r == "admin")`)
if issues.Err() != nil {
    return err
}

// Create program (thread-safe, cacheable)
prg, err := env.Program(ast)

// Evaluate
out, _, err := prg.Eval(map[string]interface{}{
    "token": tokenInfo,
    "request": requestInfo,
    "resource": resourceInfo,
})
```

---

### 2.2 Expr (expr-lang)

**Repository**: `github.com/expr-lang/expr`
**Trust Score**: 5.4 | **Snippets**: 113

#### Pros
- Simpler API, faster setup
- Very fast evaluation (optimized bytecode)
- Good for simple to medium complexity expressions
- Lightweight dependency
- Native Go struct support

#### Cons
- Less security-focused than CEL
- No partial evaluation
- Less mature ecosystem

#### Syntax Examples
```expr
// Comparisons
token.Sub == "user123"
token.Level >= 3

// Logical operators
"admin" in token.Roles && "write" in token.Scopes
not token.Expired and token.Valid

// Membership with 'in' and 'not in'
"admin" in token.Roles
token.ClientID not in ["blocked-client-1", "blocked-client-2"]

// Ranges
token.Level in 1..5
request.Port in 8000..9000

// String operations
request.Path startsWith "/api"
token.Email endsWith "@company.com"
request.Path matches "^/api/v[0-9]+"

// Ternary
token.Level >= 3 ? "premium" : "basic"

// Array operations
all(token.Roles, {# startsWith "app_"})
any(token.Scopes, {# == "admin" or # == "superuser"})
filter(token.Roles, {# startsWith "role_"})

// Nil-safe access
token?.Claims?.CustomField ?? "default"
```

#### Setup Code
```go
import "github.com/expr-lang/expr"

// Define environment struct
type Env struct {
    Token    *TokenInfo
    Request  *RequestInfo
    Resource *ResourceInfo
    Source   *SourceInfo
}

// Compile expression
program, err := expr.Compile(
    `"admin" in Token.Roles && Request.Method == "DELETE"`,
    expr.Env(Env{}),
    expr.AsBool(),
)

// Evaluate
output, err := expr.Run(program, Env{
    Token:    tokenInfo,
    Request:  requestInfo,
    Resource: resourceInfo,
})
```

---

### 2.3 Gval

**Repository**: `github.com/PaesslerAG/gval`
**Trust Score**: 7.8 | **Snippets**: 18

#### Pros
- Go-like syntax
- Custom operators/functions
- Good balance of features

#### Cons
- Smaller community
- Less documentation
- Not security-focused

---

## 3. Recommendation

### Primary Choice: **CEL-Go**

**Rationale**:
1. **Security-first design** - CEL is specifically designed for authorization policies
2. **Production-proven** - Used in Kubernetes RBAC, Envoy, Firebase Security Rules
3. **Type safety** - Catches errors at compile time
4. **Performance** - Compiled programs are cached and fast
5. **Ecosystem** - Tooling, documentation, and community support
6. **Partial evaluation** - Can optimize expressions with known values

### Secondary/Fallback: **Expr**

Use for simpler cases where:
- Performance is critical (expr is slightly faster)
- Expressions are simple and don't need security guarantees
- Quick prototyping

---

## 4. Proposed Implementation

### 4.1 Schema Changes

```yaml
# rules.yaml - New 'expression' field in conditions
rules:
  - name: owner-can-edit
    conditions:
      paths:
        - "/api/v1/documents/{document_id}"
      methods:
        - PUT
        - PATCH
      # NEW: CEL expression for complex conditions
      expression: |
        resource.owner_id == token.sub ||
        "admin" in token.roles ||
        (resource.team != "" && resource.team in token.teams)
    effect: allow

  - name: premium-features
    conditions:
      paths:
        - "/api/v1/premium/**"
      expression: |
        token.claims.subscription_level >= 2 &&
        !token.claims.account_suspended &&
        timestamp(token.claims.subscription_expires) > now
    effect: allow

  - name: time-based-access
    conditions:
      paths:
        - "/api/v1/reports/**"
      expression: |
        // Only during business hours (9 AM - 6 PM UTC)
        request.time.getHours() >= 9 &&
        request.time.getHours() < 18 &&
        request.time.getDayOfWeek() in [1, 2, 3, 4, 5]
    effect: allow
```

### 4.2 Go Struct Changes

```go
// builtin.go

// Conditions defines matching conditions for a rule.
type Conditions struct {
    // ... existing fields ...

    // Expression is a CEL expression for complex conditions
    // Available variables: token, request, resource, source, context
    Expression string `yaml:"expression,omitempty" jsonschema:"description=CEL expression for advanced conditions. Variables: token (JWT claims), request (HTTP request), resource (extracted resource), source (client info), context (request context)."`

    // ExpressionMode defines how expression combines with other conditions
    // - "and" (default): expression AND other conditions must match
    // - "or": expression OR other conditions must match
    // - "override": only expression is evaluated, other conditions ignored
    ExpressionMode string `yaml:"expression_mode,omitempty" jsonschema:"enum=and,enum=or,enum=override,default=and"`
}
```

### 4.3 CEL Environment Setup

```go
// cel_evaluator.go

package policy

import (
    "sync"
    "time"

    "github.com/google/cel-go/cel"
    "github.com/google/cel-go/checker/decls"
    "github.com/google/cel-go/common/types"
    "github.com/google/cel-go/common/types/ref"

    "github.com/your-org/authz-service/internal/domain"
)

// CELEvaluator provides CEL expression evaluation with caching.
type CELEvaluator struct {
    env      *cel.Env
    mu       sync.RWMutex
    programs map[string]cel.Program // Cache compiled programs
}

// NewCELEvaluator creates a new CEL evaluator with predefined variables.
func NewCELEvaluator() (*CELEvaluator, error) {
    env, err := cel.NewEnv(
        // Token variables (from JWT)
        cel.Variable("token", cel.ObjectType("token")),

        // Request variables
        cel.Variable("request", cel.ObjectType("request")),

        // Extracted resource
        cel.Variable("resource", cel.ObjectType("resource")),

        // Source info
        cel.Variable("source", cel.ObjectType("source")),

        // Context
        cel.Variable("context", cel.ObjectType("context")),

        // Current timestamp
        cel.Variable("now", cel.TimestampType),

        // Custom functions
        cel.Function("cidrMatch",
            cel.Overload("cidr_match_string_string",
                []*cel.Type{cel.StringType, cel.StringType},
                cel.BoolType,
                cel.BinaryBinding(cidrMatchFunc),
            ),
        ),
    )
    if err != nil {
        return nil, err
    }

    return &CELEvaluator{
        env:      env,
        programs: make(map[string]cel.Program),
    }, nil
}

// Compile compiles a CEL expression and caches the program.
func (e *CELEvaluator) Compile(expression string) (cel.Program, error) {
    e.mu.RLock()
    if prg, ok := e.programs[expression]; ok {
        e.mu.RUnlock()
        return prg, nil
    }
    e.mu.RUnlock()

    ast, issues := e.env.Compile(expression)
    if issues.Err() != nil {
        return nil, issues.Err()
    }

    prg, err := e.env.Program(ast)
    if err != nil {
        return nil, err
    }

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
    vars := map[string]interface{}{
        "now": time.Now(),
    }

    // Token variables
    if input.Token != nil {
        vars["token"] = map[string]interface{}{
            "sub":         input.Token.Subject,
            "iss":         input.Token.Issuer,
            "aud":         input.Token.Audience,
            "exp":         input.Token.ExpiresAt,
            "iat":         input.Token.IssuedAt,
            "roles":       input.Token.Roles,
            "scopes":      input.Token.Scopes,
            "client_id":   input.Token.ClientID,
            "email":       input.Token.Email,
            "claims":      input.Token.ExtraClaims,
            "valid":       input.Token.Valid,
        }
    } else {
        vars["token"] = map[string]interface{}{
            "valid": false,
        }
    }

    // Request variables
    vars["request"] = map[string]interface{}{
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
        vars["resource"] = map[string]interface{}{
            "type":   input.Resource.Type,
            "id":     input.Resource.ID,
            "action": input.Resource.Action,
            "params": input.Resource.Params,
        }
    } else {
        vars["resource"] = map[string]interface{}{}
    }

    // Source variables
    vars["source"] = map[string]interface{}{
        "address":         input.Source.Address,
        "principal":       input.Source.Principal,
        "namespace":       input.Source.Namespace,
        "service_account": input.Source.ServiceAccount,
    }

    // Context variables
    vars["context"] = map[string]interface{}{
        "request_id": input.Context.RequestID,
        "trace_id":   input.Context.TraceID,
        "timestamp":  input.Context.Timestamp,
        "custom":     input.Context.Custom,
    }

    out, _, err := prg.Eval(vars)
    if err != nil {
        return false, err
    }

    result, ok := out.Value().(bool)
    if !ok {
        return false, fmt.Errorf("expression must return boolean, got %T", out.Value())
    }

    return result, nil
}

// Custom function: CIDR matching
func cidrMatchFunc(ip, cidr ref.Val) ref.Val {
    ipStr, ok1 := ip.Value().(string)
    cidrStr, ok2 := cidr.Value().(string)
    if !ok1 || !ok2 {
        return types.False
    }

    matcher := NewCIDRMatcher()
    return types.Bool(matcher.Match([]string{cidrStr}, ipStr))
}
```

### 4.4 Integration with BuiltinEngine

```go
// builtin.go - Updated matchRule method

func (e *BuiltinEngine) matchRule(rule Rule, input *domain.PolicyInput) (bool, []string, *domain.ResourceInfo) {
    var reasons []string
    var extractedResource *domain.ResourceInfo

    // ... existing condition checks ...

    // Evaluate CEL expression if present
    if rule.Conditions.Expression != "" {
        result, err := e.celEvaluator.Evaluate(rule.Conditions.Expression, input)
        if err != nil {
            logger.Warn("CEL expression evaluation failed",
                logger.String("rule", rule.Name),
                logger.Err(err),
            )
            return false, nil, nil
        }

        if !result {
            return false, nil, nil
        }
        reasons = append(reasons, "expression matched")
    }

    // ... rest of existing logic ...
}
```

---

## 5. CEL Expression Examples for Common Use Cases

### 5.1 Owner-based Access
```cel
// User can access their own resources
resource.owner_id == token.sub

// Or user is admin
resource.owner_id == token.sub || "admin" in token.roles
```

### 5.2 Team/Group Access
```cel
// User's team matches resource team
resource.team in token.teams

// Hierarchical access
resource.org == token.org && (
    resource.team == token.team ||
    "org_admin" in token.roles
)
```

### 5.3 Attribute-based Conditions
```cel
// Subscription level check
token.claims.subscription_level >= 2

// Account status
!token.claims.suspended && token.claims.verified

// Feature flags
token.claims.features.exists(f, f == "beta_access")
```

### 5.4 Time-based Access
```cel
// Business hours only (UTC)
request.time.getHours() >= 9 && request.time.getHours() < 18

// Weekdays only
request.time.getDayOfWeek() in [1, 2, 3, 4, 5]

// Not expired subscription
timestamp(token.claims.subscription_expires) > now

// Token age check (issued within last hour)
now - timestamp(token.iat) < duration("1h")
```

### 5.5 Combined Conditions
```cel
// Complex multi-factor authorization
(
    // Admin always allowed
    "admin" in token.roles
) || (
    // Owner with valid subscription
    resource.owner_id == token.sub &&
    token.claims.subscription_level >= 1 &&
    timestamp(token.claims.subscription_expires) > now
) || (
    // Team member with appropriate scope
    resource.team in token.teams &&
    "team:write" in token.scopes
)
```

### 5.6 IP and Network Conditions
```cel
// Internal network check (custom function)
cidrMatch(source.address, "10.0.0.0/8") ||
cidrMatch(source.address, "192.168.0.0/16")

// Exclude blocked IPs
!(source.address in ["1.2.3.4", "5.6.7.8"])
```

### 5.7 Request Content Validation
```cel
// Header presence
"X-API-Key" in request.headers

// Query parameter check
request.query.exists(k, k == "admin_mode") ? "admin" in token.roles : true

// Method-specific rules
request.method == "DELETE" ? "delete" in token.scopes : true
```

---

## 6. Performance Considerations

### 6.1 Caching Strategy
```go
// Compile-time caching
type CELEvaluator struct {
    programs sync.Map // map[expression]cel.Program
}

// Evaluation results caching (with input hash)
type CachedResult struct {
    Result    bool
    ExpiresAt time.Time
}
```

### 6.2 Benchmarks (Expected)

| Operation | CEL | Expr | Native Go |
|-----------|-----|------|-----------|
| Simple comparison | ~100ns | ~50ns | ~10ns |
| Array membership | ~200ns | ~100ns | ~50ns |
| Complex expression | ~500ns | ~300ns | ~100ns |
| Compilation | ~1ms | ~500us | N/A |

### 6.3 Optimization Tips

1. **Compile once, evaluate many** - Cache compiled programs
2. **Short-circuit evaluation** - CEL/Expr both support this natively
3. **Partial evaluation** - CEL can pre-compute parts with known values
4. **Expression complexity limits** - Set max depth/length

---

## 7. Security Considerations

### 7.1 Input Validation
```go
// Validate expression before compilation
func ValidateExpression(expr string) error {
    if len(expr) > 4096 {
        return errors.New("expression too long")
    }
    // Check for dangerous patterns
    if strings.Contains(expr, "while") || strings.Contains(expr, "for") {
        return errors.New("loops not allowed")
    }
    return nil
}
```

### 7.2 Sandboxing
- CEL is non-Turing complete by design (no loops, recursion limits)
- Set evaluation timeout
- Limit custom function capabilities

### 7.3 Audit Logging
```go
// Log expression evaluations for security audit
logger.Info("CEL expression evaluated",
    logger.String("rule", ruleName),
    logger.String("expression_hash", hash(expression)),
    logger.Bool("result", result),
    logger.String("subject", input.Token.Subject),
)
```

---

## 8. Migration Path

### Phase 1: Add Infrastructure
1. Add CEL-Go dependency
2. Implement `CELEvaluator`
3. Add `expression` field to `Conditions`
4. Update schema generation

### Phase 2: Parallel Evaluation
1. Evaluate expressions alongside existing conditions
2. Validate with `expression_mode: "and"`
3. Comprehensive testing

### Phase 3: Production Rollout
1. Document expression syntax
2. Add expression validation
3. Performance monitoring
4. Gradual migration of complex rules

### Phase 4: Advanced Features
1. Partial evaluation for caching
2. Custom functions library
3. Expression editor/validator tool

---

## 9. Dependencies

```go
// go.mod additions
require (
    github.com/google/cel-go v0.20.1
    google.golang.org/genproto/googleapis/api v0.0.0-20240102182953-50ed04b92917
)
```

---

## 10. Conclusion

**Recommendation**: Implement CEL-Go as the primary expression language for custom evaluators.

**Key Benefits**:
- Security-first design perfect for authorization
- Rich expression syntax covering all required operators
- Excellent performance with compilation caching
- Production-proven in similar systems (K8s, Envoy)
- Strong typing prevents runtime errors

**Timeline Estimate**:
- Phase 1: 2-3 days
- Phase 2: 2-3 days
- Phase 3: 1-2 days
- Phase 4: Ongoing

**Risk**: Medium-low. CEL is well-documented and battle-tested.
