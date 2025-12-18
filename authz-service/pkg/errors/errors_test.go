package errors

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthzError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *AuthzError
		expected string
	}{
		{
			name: "without cause",
			err: &AuthzError{
				Code:    CodeAccessDenied,
				Message: "access is denied",
			},
			expected: "ACCESS_DENIED: access is denied",
		},
		{
			name: "with cause",
			err: &AuthzError{
				Code:    CodeTokenInvalid,
				Message: "token validation failed",
				Cause:   errors.New("signature mismatch"),
			},
			expected: "INVALID_TOKEN: token validation failed: signature mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAuthzError_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := &AuthzError{
		Code:    CodeInternalError,
		Message: "something went wrong",
		Cause:   cause,
	}

	unwrapped := err.Unwrap()
	assert.Equal(t, cause, unwrapped)
}

func TestAuthzError_Unwrap_NilCause(t *testing.T) {
	err := &AuthzError{
		Code:    CodeAccessDenied,
		Message: "denied",
	}

	unwrapped := err.Unwrap()
	assert.Nil(t, unwrapped)
}

func TestAuthzError_WithDetail(t *testing.T) {
	err := &AuthzError{
		Code:    CodeAccessDenied,
		Message: "access denied",
	}

	result := err.WithDetail("resource", "/api/users").WithDetail("method", "POST")

	require.NotNil(t, result.Details)
	assert.Equal(t, "/api/users", result.Details["resource"])
	assert.Equal(t, "POST", result.Details["method"])
	// Should return same instance (chaining)
	assert.Same(t, err, result)
}

func TestNewAuthzError(t *testing.T) {
	cause := errors.New("cause error")
	err := NewAuthzError(CodeTokenExpired, "token has expired", cause)

	require.NotNil(t, err)
	assert.Equal(t, CodeTokenExpired, err.Code)
	assert.Equal(t, "token has expired", err.Message)
	assert.Equal(t, cause, err.Cause)
}

func TestNewAuthzError_NilCause(t *testing.T) {
	err := NewAuthzError(CodeAccessDenied, "denied", nil)

	require.NotNil(t, err)
	assert.Nil(t, err.Cause)
}

func TestIs(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		target   error
		expected bool
	}{
		{
			name:     "match",
			err:      ErrTokenExpired,
			target:   ErrTokenExpired,
			expected: true,
		},
		{
			name:     "no match",
			err:      ErrTokenExpired,
			target:   ErrTokenInvalid,
			expected: false,
		},
		{
			name:     "wrapped match",
			err:      Wrap(ErrTokenExpired, "context"),
			target:   ErrTokenExpired,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Is(tt.err, tt.target)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAs(t *testing.T) {
	authzErr := &AuthzError{
		Code:    CodeAccessDenied,
		Message: "denied",
	}

	var target *AuthzError
	result := As(authzErr, &target)

	assert.True(t, result)
	assert.Equal(t, authzErr.Code, target.Code)
}

func TestAs_NoMatch(t *testing.T) {
	err := errors.New("plain error")

	var target *AuthzError
	result := As(err, &target)

	assert.False(t, result)
}

func TestWrap(t *testing.T) {
	err := errors.New("original error")
	wrapped := Wrap(err, "context message")

	require.NotNil(t, wrapped)
	assert.Contains(t, wrapped.Error(), "context message")
	assert.Contains(t, wrapped.Error(), "original error")
	assert.True(t, errors.Is(wrapped, err))
}

func TestWrap_NilError(t *testing.T) {
	wrapped := Wrap(nil, "context message")
	assert.Nil(t, wrapped)
}

func TestStandardErrors(t *testing.T) {
	// Ensure all standard errors are unique
	standardErrors := []error{
		ErrTokenMissing,
		ErrTokenInvalid,
		ErrTokenExpired,
		ErrTokenNotYetValid,
		ErrTokenMalformed,
		ErrSignatureInvalid,
		ErrIssuerInvalid,
		ErrAudienceInvalid,
		ErrJWKSFetchFailed,
		ErrJWKSKeyNotFound,
		ErrJWKSInvalidKey,
		ErrJWKSRefreshFailed,
		ErrJWKSParseError,
		ErrPolicyEvaluation,
		ErrPolicyNotFound,
		ErrPolicyInvalid,
		ErrPolicyTimeout,
		ErrAccessDenied,
		ErrInsufficientScope,
		ErrMissingRole,
		ErrConfigInvalid,
		ErrConfigNotFound,
		ErrConfigLoadFailed,
		ErrServiceUnavailable,
		ErrTimeout,
		ErrInternal,
	}

	// Each error should be unique
	seen := make(map[string]bool)
	for _, err := range standardErrors {
		msg := err.Error()
		assert.False(t, seen[msg], "duplicate error: %s", msg)
		seen[msg] = true
	}
}

func TestErrorCodes(t *testing.T) {
	codes := []string{
		CodeTokenInvalid,
		CodeTokenExpired,
		CodeTokenMissing,
		CodeAccessDenied,
		CodeInsufficientScope,
		CodePolicyError,
		CodeInternalError,
		CodeConfigError,
		CodeUnavailable,
	}

	// Each code should be unique
	seen := make(map[string]bool)
	for _, code := range codes {
		assert.False(t, seen[code], "duplicate code: %s", code)
		seen[code] = true
	}
}

func TestAuthzError_ErrorsIsCompatibility(t *testing.T) {
	cause := ErrTokenExpired
	authzErr := NewAuthzError(CodeTokenExpired, "token expired", cause)

	// Should be able to use errors.Is to check cause
	assert.True(t, errors.Is(authzErr, ErrTokenExpired))
}

func TestAuthzError_ChainedDetails(t *testing.T) {
	err := NewAuthzError(CodeAccessDenied, "denied", nil).
		WithDetail("user", "john").
		WithDetail("resource", "/admin").
		WithDetail("action", "read")

	assert.Len(t, err.Details, 3)
	assert.Equal(t, "john", err.Details["user"])
	assert.Equal(t, "/admin", err.Details["resource"])
	assert.Equal(t, "read", err.Details["action"])
}

func BenchmarkAuthzError_Error(b *testing.B) {
	err := &AuthzError{
		Code:    CodeAccessDenied,
		Message: "access denied",
		Cause:   errors.New("underlying cause"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = err.Error()
	}
}

func BenchmarkAuthzError_WithDetail(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := &AuthzError{Code: "TEST", Message: "test"}
		err.WithDetail("key", "value")
	}
}

func BenchmarkWrap(b *testing.B) {
	err := errors.New("original")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Wrap(err, "context")
	}
}

func BenchmarkIs(b *testing.B) {
	err := Wrap(ErrTokenExpired, "context")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Is(err, ErrTokenExpired)
	}
}
