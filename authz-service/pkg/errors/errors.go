package errors

import (
	"errors"
	"fmt"
)

// Standard error types for the authorization service.
var (
	// Token errors
	ErrTokenMissing     = errors.New("token is missing")
	ErrTokenInvalid     = errors.New("token is invalid")
	ErrTokenExpired     = errors.New("token has expired")
	ErrTokenNotYetValid = errors.New("token is not yet valid")
	ErrTokenMalformed   = errors.New("token is malformed")
	ErrSignatureInvalid = errors.New("token signature is invalid")
	ErrIssuerInvalid    = errors.New("token issuer is not trusted")
	ErrAudienceInvalid  = errors.New("token audience is invalid")

	// JWKS errors
	ErrJWKSFetchFailed    = errors.New("failed to fetch JWKS")
	ErrJWKSKeyNotFound    = errors.New("key not found in JWKS")
	ErrJWKSInvalidKey     = errors.New("invalid key in JWKS")
	ErrJWKSRefreshFailed  = errors.New("failed to refresh JWKS")
	ErrJWKSParseError     = errors.New("failed to parse JWKS")

	// Policy errors
	ErrPolicyEvaluation = errors.New("policy evaluation failed")
	ErrPolicyNotFound   = errors.New("policy not found")
	ErrPolicyInvalid    = errors.New("policy is invalid")
	ErrPolicyTimeout    = errors.New("policy evaluation timeout")

	// Authorization errors
	ErrAccessDenied      = errors.New("access denied")
	ErrInsufficientScope = errors.New("insufficient scope")
	ErrMissingRole       = errors.New("required role is missing")

	// Configuration errors
	ErrConfigInvalid    = errors.New("invalid configuration")
	ErrConfigNotFound   = errors.New("configuration not found")
	ErrConfigLoadFailed = errors.New("failed to load configuration")

	// Service errors
	ErrServiceUnavailable = errors.New("service unavailable")
	ErrTimeout            = errors.New("operation timeout")
	ErrInternal           = errors.New("internal error")
)

// AuthzError represents a structured authorization error.
type AuthzError struct {
	// Code is the error code
	Code string `json:"code"`

	// Message is the error message
	Message string `json:"message"`

	// Details contains additional error details
	Details map[string]any `json:"details,omitempty"`

	// Cause is the underlying error
	Cause error `json:"-"`
}

// Error implements the error interface.
func (e *AuthzError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying error.
func (e *AuthzError) Unwrap() error {
	return e.Cause
}

// WithDetail adds a detail to the error.
func (e *AuthzError) WithDetail(key string, value any) *AuthzError {
	if e.Details == nil {
		e.Details = make(map[string]any)
	}
	e.Details[key] = value
	return e
}

// NewAuthzError creates a new AuthzError.
func NewAuthzError(code, message string, cause error) *AuthzError {
	return &AuthzError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// Error codes
const (
	CodeTokenInvalid      = "INVALID_TOKEN"
	CodeTokenExpired      = "TOKEN_EXPIRED"
	CodeTokenMissing      = "TOKEN_MISSING"
	CodeAccessDenied      = "ACCESS_DENIED"
	CodeInsufficientScope = "INSUFFICIENT_SCOPE"
	CodePolicyError       = "POLICY_ERROR"
	CodeInternalError     = "INTERNAL_ERROR"
	CodeConfigError       = "CONFIG_ERROR"
	CodeUnavailable       = "SERVICE_UNAVAILABLE"
)

// Is reports whether err matches target.
func Is(err, target error) bool {
	return errors.Is(err, target)
}

// As finds the first error in err's chain that matches target.
func As(err error, target any) bool {
	return errors.As(err, target)
}

// Wrap wraps an error with additional context.
func Wrap(err error, message string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, err)
}
