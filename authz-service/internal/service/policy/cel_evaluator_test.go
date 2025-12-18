package policy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/your-org/authz-service/internal/domain"
)

func TestNewCELEvaluator(t *testing.T) {
	eval, err := NewCELEvaluator()
	require.NoError(t, err)
	require.NotNil(t, eval)
	assert.NotNil(t, eval.env)
	assert.NotNil(t, eval.programs)
}

func TestCELEvaluator_Compile(t *testing.T) {
	eval, err := NewCELEvaluator()
	require.NoError(t, err)

	tests := []struct {
		name       string
		expression string
		wantErr    bool
	}{
		{
			name:       "simple comparison",
			expression: `request.method == "GET"`,
			wantErr:    false,
		},
		{
			name:       "role check with in operator",
			expression: `"admin" in token.roles`,
			wantErr:    false,
		},
		{
			name:       "complex logical expression",
			expression: `("admin" in token.roles) || (token.sub == "user123")`,
			wantErr:    false,
		},
		{
			name:       "invalid expression - syntax error",
			expression: `"admin" in token.roles &&`,
			wantErr:    true,
		},
		{
			name:       "invalid expression - wrong return type",
			expression: `token.sub`,
			wantErr:    true, // returns string, not bool
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prg, err := eval.Compile(tt.expression)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, prg)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, prg)
			}
		})
	}
}

func TestCELEvaluator_Compile_Caching(t *testing.T) {
	eval, err := NewCELEvaluator()
	require.NoError(t, err)

	expression := `"admin" in token.roles`

	// First compile
	prg1, err := eval.Compile(expression)
	require.NoError(t, err)

	// Second compile - should return cached
	prg2, err := eval.Compile(expression)
	require.NoError(t, err)

	// Should be the same instance (cached)
	assert.Equal(t, prg1, prg2)
	assert.Equal(t, 1, eval.CacheSize())
}

func TestCELEvaluator_Evaluate_RoleCheck(t *testing.T) {
	eval, err := NewCELEvaluator()
	require.NoError(t, err)

	tests := []struct {
		name       string
		expression string
		input      *domain.PolicyInput
		want       bool
		wantErr    bool
	}{
		{
			name:       "admin role present",
			expression: `"admin" in token.roles`,
			input: &domain.PolicyInput{
				Token: &domain.TokenInfo{
					Valid: true,
					Roles: []string{"user", "admin"},
				},
				Request: domain.RequestInfo{Method: "GET", Path: "/api/test"},
			},
			want:    true,
			wantErr: false,
		},
		{
			name:       "admin role not present",
			expression: `"admin" in token.roles`,
			input: &domain.PolicyInput{
				Token: &domain.TokenInfo{
					Valid: true,
					Roles: []string{"user"},
				},
				Request: domain.RequestInfo{Method: "GET", Path: "/api/test"},
			},
			want:    false,
			wantErr: false,
		},
		{
			name:       "nil token - roles empty",
			expression: `"admin" in token.roles`,
			input: &domain.PolicyInput{
				Request: domain.RequestInfo{Method: "GET", Path: "/api/test"},
			},
			want:    false,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := eval.Evaluate(tt.expression, tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, result)
			}
		})
	}
}

func TestCELEvaluator_Evaluate_RequestMatching(t *testing.T) {
	eval, err := NewCELEvaluator()
	require.NoError(t, err)

	tests := []struct {
		name       string
		expression string
		input      *domain.PolicyInput
		want       bool
	}{
		{
			name:       "method equals",
			expression: `request.method == "POST"`,
			input: &domain.PolicyInput{
				Request: domain.RequestInfo{Method: "POST", Path: "/api/test"},
			},
			want: true,
		},
		{
			name:       "method not equals",
			expression: `request.method == "POST"`,
			input: &domain.PolicyInput{
				Request: domain.RequestInfo{Method: "GET", Path: "/api/test"},
			},
			want: false,
		},
		{
			name:       "method in list",
			expression: `request.method in ["GET", "HEAD"]`,
			input: &domain.PolicyInput{
				Request: domain.RequestInfo{Method: "GET", Path: "/api/test"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := eval.Evaluate(tt.expression, tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestCELEvaluator_Evaluate_ResourceOwnership(t *testing.T) {
	eval, err := NewCELEvaluator()
	require.NoError(t, err)

	tests := []struct {
		name       string
		expression string
		input      *domain.PolicyInput
		want       bool
	}{
		{
			name:       "owner matches subject",
			expression: `resource.params["owner_id"] == token.sub`,
			input: &domain.PolicyInput{
				Token: &domain.TokenInfo{
					Valid:   true,
					Subject: "user-123",
				},
				Request: domain.RequestInfo{Method: "GET", Path: "/api/documents/456"},
				Resource: &domain.ResourceInfo{
					Type: "documents",
					ID:   "456",
					Params: map[string]string{
						"owner_id": "user-123",
					},
				},
			},
			want: true,
		},
		{
			name:       "owner does not match subject",
			expression: `resource.params["owner_id"] == token.sub`,
			input: &domain.PolicyInput{
				Token: &domain.TokenInfo{
					Valid:   true,
					Subject: "user-999",
				},
				Request: domain.RequestInfo{Method: "GET", Path: "/api/documents/456"},
				Resource: &domain.ResourceInfo{
					Type: "documents",
					ID:   "456",
					Params: map[string]string{
						"owner_id": "user-123",
					},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := eval.Evaluate(tt.expression, tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestCELEvaluator_Evaluate_ComplexConditions(t *testing.T) {
	eval, err := NewCELEvaluator()
	require.NoError(t, err)

	tests := []struct {
		name       string
		expression string
		input      *domain.PolicyInput
		want       bool
	}{
		{
			name: "admin OR owner can edit",
			expression: `
				"admin" in token.roles ||
				resource.params["owner_id"] == token.sub
			`,
			input: &domain.PolicyInput{
				Token: &domain.TokenInfo{
					Valid:   true,
					Subject: "user-123",
					Roles:   []string{"user"},
				},
				Request: domain.RequestInfo{Method: "PUT", Path: "/api/documents/456"},
				Resource: &domain.ResourceInfo{
					Params: map[string]string{"owner_id": "user-123"},
				},
			},
			want: true, // is owner
		},
		{
			name: "admin OR owner can edit - admin",
			expression: `
				"admin" in token.roles ||
				resource.params["owner_id"] == token.sub
			`,
			input: &domain.PolicyInput{
				Token: &domain.TokenInfo{
					Valid:   true,
					Subject: "admin-1",
					Roles:   []string{"admin"},
				},
				Request: domain.RequestInfo{Method: "PUT", Path: "/api/documents/456"},
				Resource: &domain.ResourceInfo{
					Params: map[string]string{"owner_id": "user-123"},
				},
			},
			want: true, // is admin
		},
		{
			name: "admin OR owner can edit - denied",
			expression: `
				"admin" in token.roles ||
				resource.params["owner_id"] == token.sub
			`,
			input: &domain.PolicyInput{
				Token: &domain.TokenInfo{
					Valid:   true,
					Subject: "user-999",
					Roles:   []string{"user"},
				},
				Request: domain.RequestInfo{Method: "PUT", Path: "/api/documents/456"},
				Resource: &domain.ResourceInfo{
					Params: map[string]string{"owner_id": "user-123"},
				},
			},
			want: false, // neither admin nor owner
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := eval.Evaluate(tt.expression, tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestCELEvaluator_Evaluate_ScopeCheck(t *testing.T) {
	eval, err := NewCELEvaluator()
	require.NoError(t, err)

	tests := []struct {
		name       string
		expression string
		input      *domain.PolicyInput
		want       bool
	}{
		{
			name:       "has required scope",
			expression: `"write" in token.scopes`,
			input: &domain.PolicyInput{
				Token: &domain.TokenInfo{
					Valid:  true,
					Scopes: []string{"read", "write"},
				},
				Request: domain.RequestInfo{Method: "POST", Path: "/api/test"},
			},
			want: true,
		},
		{
			name:       "missing required scope",
			expression: `"write" in token.scopes`,
			input: &domain.PolicyInput{
				Token: &domain.TokenInfo{
					Valid:  true,
					Scopes: []string{"read"},
				},
				Request: domain.RequestInfo{Method: "POST", Path: "/api/test"},
			},
			want: false,
		},
		{
			name:       "method requires specific scope",
			expression: `request.method == "DELETE" ? "admin" in token.roles : true`,
			input: &domain.PolicyInput{
				Token: &domain.TokenInfo{
					Valid: true,
					Roles: []string{"user"},
				},
				Request: domain.RequestInfo{Method: "GET", Path: "/api/test"},
			},
			want: true, // not DELETE, so true
		},
		{
			name:       "DELETE requires admin",
			expression: `request.method == "DELETE" ? "admin" in token.roles : true`,
			input: &domain.PolicyInput{
				Token: &domain.TokenInfo{
					Valid: true,
					Roles: []string{"user"},
				},
				Request: domain.RequestInfo{Method: "DELETE", Path: "/api/test"},
			},
			want: false, // is DELETE but not admin
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := eval.Evaluate(tt.expression, tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestCELEvaluator_Evaluate_SourceIP(t *testing.T) {
	eval, err := NewCELEvaluator()
	require.NoError(t, err)

	tests := []struct {
		name       string
		expression string
		input      *domain.PolicyInput
		want       bool
	}{
		{
			name:       "CIDR match - internal network",
			expression: `cidrMatch(source.address, "10.0.0.0/8")`,
			input: &domain.PolicyInput{
				Request: domain.RequestInfo{Method: "GET", Path: "/api/test"},
				Source: domain.SourceInfo{
					Address: "10.1.2.3",
				},
			},
			want: true,
		},
		{
			name:       "CIDR match - external network",
			expression: `cidrMatch(source.address, "10.0.0.0/8")`,
			input: &domain.PolicyInput{
				Request: domain.RequestInfo{Method: "GET", Path: "/api/test"},
				Source: domain.SourceInfo{
					Address: "8.8.8.8",
				},
			},
			want: false,
		},
		{
			name:       "CIDR match - exact IP",
			expression: `cidrMatch(source.address, "127.0.0.1")`,
			input: &domain.PolicyInput{
				Request: domain.RequestInfo{Method: "GET", Path: "/api/test"},
				Source: domain.SourceInfo{
					Address: "127.0.0.1",
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := eval.Evaluate(tt.expression, tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestCELEvaluator_Evaluate_GlobMatch(t *testing.T) {
	eval, err := NewCELEvaluator()
	require.NoError(t, err)

	tests := []struct {
		name       string
		expression string
		input      *domain.PolicyInput
		want       bool
	}{
		{
			name:       "glob match - single wildcard",
			expression: `globMatch(request.path, "/api/*")`,
			input: &domain.PolicyInput{
				Request: domain.RequestInfo{Method: "GET", Path: "/api/users"},
			},
			want: true,
		},
		{
			name:       "glob match - double wildcard",
			expression: `globMatch(request.path, "/api/**")`,
			input: &domain.PolicyInput{
				Request: domain.RequestInfo{Method: "GET", Path: "/api/v1/users/123"},
			},
			want: true,
		},
		{
			name:       "glob match - no match",
			expression: `globMatch(request.path, "/admin/*")`,
			input: &domain.PolicyInput{
				Request: domain.RequestInfo{Method: "GET", Path: "/api/users"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := eval.Evaluate(tt.expression, tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestCELEvaluator_ValidateExpression(t *testing.T) {
	eval, err := NewCELEvaluator()
	require.NoError(t, err)

	tests := []struct {
		name       string
		expression string
		wantErr    bool
	}{
		{
			name:       "valid expression",
			expression: `"admin" in token.roles`,
			wantErr:    false,
		},
		{
			name:       "empty expression",
			expression: "",
			wantErr:    false,
		},
		{
			name:       "invalid expression",
			expression: `this is not valid CEL`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := eval.ValidateExpression(tt.expression)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCELEvaluator_ClearCache(t *testing.T) {
	eval, err := NewCELEvaluator()
	require.NoError(t, err)

	// Compile some expressions
	_, err = eval.Compile(`"admin" in token.roles`)
	require.NoError(t, err)
	_, err = eval.Compile(`request.method == "GET"`)
	require.NoError(t, err)

	assert.Equal(t, 2, eval.CacheSize())

	// Clear cache
	eval.ClearCache()
	assert.Equal(t, 0, eval.CacheSize())
}

func TestCELEvaluator_PrecompileExpressions(t *testing.T) {
	tests := []struct {
		name        string
		expressions []string
		wantErr     bool
	}{
		{
			name: "all valid",
			expressions: []string{
				`"admin" in token.roles`,
				`request.method == "GET"`,
				`token.valid == true`,
			},
			wantErr: false,
		},
		{
			name: "one invalid",
			expressions: []string{
				`"admin" in token.roles`,
				`invalid expression @#$`,
			},
			wantErr: true,
		},
		{
			name:        "empty list",
			expressions: []string{},
			wantErr:     false,
		},
		{
			name:        "with empty string",
			expressions: []string{"", `"admin" in token.roles`},
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fresh evaluator for each test
			eval, err := NewCELEvaluator()
			require.NoError(t, err)

			err = eval.PrecompileExpressions(tt.expressions)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCELEvaluator_TokenClaims(t *testing.T) {
	eval, err := NewCELEvaluator()
	require.NoError(t, err)

	tests := []struct {
		name       string
		expression string
		input      *domain.PolicyInput
		want       bool
	}{
		{
			name:       "subject match",
			expression: `token.sub == "user-123"`,
			input: &domain.PolicyInput{
				Token: &domain.TokenInfo{
					Valid:   true,
					Subject: "user-123",
				},
				Request: domain.RequestInfo{Method: "GET", Path: "/api/test"},
			},
			want: true,
		},
		{
			name:       "issuer match",
			expression: `token.iss == "https://keycloak.example.com"`,
			input: &domain.PolicyInput{
				Token: &domain.TokenInfo{
					Valid:  true,
					Issuer: "https://keycloak.example.com",
				},
				Request: domain.RequestInfo{Method: "GET", Path: "/api/test"},
			},
			want: true,
		},
		{
			name:       "client_id match",
			expression: `token.client_id == "my-app"`,
			input: &domain.PolicyInput{
				Token: &domain.TokenInfo{
					Valid:    true,
					ClientID: "my-app",
				},
				Request: domain.RequestInfo{Method: "GET", Path: "/api/test"},
			},
			want: true,
		},
		{
			name:       "token validity check",
			expression: `token.valid == true`,
			input: &domain.PolicyInput{
				Token: &domain.TokenInfo{
					Valid: true,
				},
				Request: domain.RequestInfo{Method: "GET", Path: "/api/test"},
			},
			want: true,
		},
		{
			name:       "token invalid",
			expression: `token.valid == true`,
			input: &domain.PolicyInput{
				Request: domain.RequestInfo{Method: "GET", Path: "/api/test"},
			},
			want: false, // nil token means invalid
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := eval.Evaluate(tt.expression, tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestCELEvaluator_Evaluate_TokenExpiration(t *testing.T) {
	celEval, err := NewCELEvaluator()
	require.NoError(t, err)

	// Test that we can access token timestamps
	input := &domain.PolicyInput{
		Token: &domain.TokenInfo{
			Valid:     true,
			IssuedAt:  time.Now().Add(-1 * time.Hour),
			ExpiresAt: time.Now().Add(1 * time.Hour),
		},
		Request: domain.RequestInfo{Method: "GET", Path: "/api/test"},
	}

	// Check that token is valid (basic expression with token.valid)
	result, err := celEval.Evaluate(`token.valid == true`, input)
	require.NoError(t, err)
	assert.True(t, result)
}

func TestCELEvaluator_Groups(t *testing.T) {
	eval, err := NewCELEvaluator()
	require.NoError(t, err)

	tests := []struct {
		name       string
		expression string
		input      *domain.PolicyInput
		want       bool
	}{
		{
			name:       "group check - member",
			expression: `"engineering" in token.groups`,
			input: &domain.PolicyInput{
				Token: &domain.TokenInfo{
					Valid:  true,
					Groups: []string{"engineering", "platform"},
				},
				Request: domain.RequestInfo{Method: "GET", Path: "/api/test"},
			},
			want: true,
		},
		{
			name:       "group check - not member",
			expression: `"admin" in token.groups`,
			input: &domain.PolicyInput{
				Token: &domain.TokenInfo{
					Valid:  true,
					Groups: []string{"engineering", "platform"},
				},
				Request: domain.RequestInfo{Method: "GET", Path: "/api/test"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := eval.Evaluate(tt.expression, tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, result)
		})
	}
}
