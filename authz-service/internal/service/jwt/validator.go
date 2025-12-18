package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/internal/domain"
	"github.com/your-org/authz-service/pkg/errors"
	"github.com/your-org/authz-service/pkg/logger"
)

// Verify JWKSProvider implements KeyProvider interface at compile time.
var _ KeyProvider = (*JWKSProvider)(nil)

// KeyProvider provides signing keys for JWT validation.
type KeyProvider interface {
	GetKey(ctx context.Context, issuerURL, keyID string) (jwk.Key, error)
}

// Validator validates JWT tokens.
type Validator struct {
	keyProvider   KeyProvider
	issuers       map[string]config.IssuerConfig
	validationCfg config.ValidationConfig
	allowedAlgos  map[string]bool
}

// NewValidator creates a new JWT validator.
func NewValidator(keyProvider KeyProvider, jwtConfig config.JWTConfig) *Validator {
	issuers := make(map[string]config.IssuerConfig)
	allowedAlgos := make(map[string]bool)

	for _, issuer := range jwtConfig.Issuers {
		issuers[issuer.IssuerURL] = issuer
		for _, algo := range issuer.Algorithms {
			allowedAlgos[algo] = true
		}
	}

	// Default algorithms if none specified
	if len(allowedAlgos) == 0 {
		allowedAlgos["RS256"] = true
		allowedAlgos["RS384"] = true
		allowedAlgos["RS512"] = true
		allowedAlgos["ES256"] = true
		allowedAlgos["ES384"] = true
		allowedAlgos["ES512"] = true
	}

	return &Validator{
		keyProvider:   keyProvider,
		issuers:       issuers,
		validationCfg: jwtConfig.Validation,
		allowedAlgos:  allowedAlgos,
	}
}

// Validate validates a JWT token and returns token information.
func (v *Validator) Validate(ctx context.Context, tokenString string) (*domain.TokenInfo, error) {
	// Parse without validation first to get header info
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, errors.NewAuthzError(errors.CodeTokenInvalid, "failed to parse token", err)
	}

	// Check algorithm
	alg := token.Method.Alg()
	if !v.allowedAlgos[alg] {
		return nil, errors.NewAuthzError(errors.CodeTokenInvalid,
			fmt.Sprintf("algorithm %s is not allowed", alg), nil)
	}

	// Get claims to find issuer
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.NewAuthzError(errors.CodeTokenInvalid, "invalid claims format", nil)
	}

	issuer, _ := claims["iss"].(string)
	if issuer == "" {
		return nil, errors.NewAuthzError(errors.CodeTokenInvalid, "missing issuer claim", nil)
	}

	// Check if issuer is trusted
	issuerConfig, ok := v.issuers[issuer]
	if !ok {
		return nil, errors.NewAuthzError(errors.CodeTokenInvalid,
			fmt.Sprintf("untrusted issuer: %s", issuer), errors.ErrIssuerInvalid)
	}

	// Get key ID from header
	kid, _ := token.Header["kid"].(string)
	if kid == "" {
		return nil, errors.NewAuthzError(errors.CodeTokenInvalid, "missing key ID in header", nil)
	}

	// Get the signing key
	jwkKey, err := v.keyProvider.GetKey(ctx, issuer, kid)
	if err != nil {
		return nil, errors.NewAuthzError(errors.CodeTokenInvalid, "failed to get signing key", err)
	}

	// Convert JWK to crypto key
	var rawKey interface{}
	if err := jwkKey.Raw(&rawKey); err != nil {
		return nil, errors.NewAuthzError(errors.CodeTokenInvalid, "failed to extract raw key", err)
	}

	// Parse and validate the token
	validatedToken, err := v.parseAndValidate(tokenString, rawKey)
	if err != nil {
		return nil, err
	}

	// Extract token info
	tokenInfo, err := v.extractTokenInfo(validatedToken, issuerConfig)
	if err != nil {
		return nil, err
	}

	tokenInfo.Raw = tokenString
	tokenInfo.Valid = true

	logger.Debug("token validated successfully",
		logger.String("subject", tokenInfo.Subject),
		logger.String("issuer", tokenInfo.Issuer),
	)

	return tokenInfo, nil
}

// parseAndValidate parses and validates the token with the given key.
func (v *Validator) parseAndValidate(tokenString string, key interface{}) (*jwt.Token, error) {
	options := []jwt.ParserOption{
		jwt.WithLeeway(v.validationCfg.ClockSkew),
	}

	if v.validationCfg.RequireExpiration {
		options = append(options, jwt.WithExpirationRequired())
	}

	parser := jwt.NewParser(options...)

	token, err := parser.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return key, nil
	})

	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, errors.NewAuthzError(errors.CodeTokenExpired, "token has expired", err)
		case errors.Is(err, jwt.ErrTokenNotValidYet):
			return nil, errors.NewAuthzError(errors.CodeTokenInvalid, "token not yet valid", err)
		case errors.Is(err, jwt.ErrTokenMalformed):
			return nil, errors.NewAuthzError(errors.CodeTokenInvalid, "malformed token", err)
		case errors.Is(err, jwt.ErrSignatureInvalid):
			return nil, errors.NewAuthzError(errors.CodeTokenInvalid, "invalid signature", err)
		default:
			return nil, errors.NewAuthzError(errors.CodeTokenInvalid, "token validation failed", err)
		}
	}

	return token, nil
}

// extractTokenInfo extracts token information from validated token.
func (v *Validator) extractTokenInfo(token *jwt.Token, issuerConfig config.IssuerConfig) (*domain.TokenInfo, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.NewAuthzError(errors.CodeTokenInvalid, "invalid claims format", nil)
	}

	info := &domain.TokenInfo{
		Subject:     getStringClaim(claims, "sub"),
		Issuer:      getStringClaim(claims, "iss"),
		IssuedAt:    getTimeClaim(claims, "iat"),
		ExpiresAt:   getTimeClaim(claims, "exp"),
		NotBefore:   getTimeClaim(claims, "nbf"),
		JTI:         getStringClaim(claims, "jti"),
		ClientID:    getStringClaim(claims, "client_id", "azp"),
		ExtraClaims: make(map[string]any),
	}

	// Extract audience
	info.Audience = getAudienceClaim(claims)

	// Validate audience if configured
	if len(issuerConfig.Audience) > 0 {
		if !hasValidAudience(info.Audience, issuerConfig.Audience) {
			return nil, errors.NewAuthzError(errors.CodeTokenInvalid,
				"token audience does not match expected audience", errors.ErrAudienceInvalid)
		}
	}

	// Extract roles (Keycloak format)
	info.Roles = extractRoles(claims)

	// Extract scopes
	info.Scopes = extractScopes(claims)

	// Store extra claims for extension points
	knownClaims := map[string]bool{
		"iss": true, "sub": true, "aud": true, "exp": true, "nbf": true,
		"iat": true, "jti": true, "client_id": true, "azp": true,
		"scope": true, "realm_access": true, "resource_access": true,
	}

	for key, value := range claims {
		if !knownClaims[key] {
			info.ExtraClaims[key] = value
		}
	}

	return info, nil
}

// Helper functions for claim extraction

func getStringClaim(claims jwt.MapClaims, keys ...string) string {
	for _, key := range keys {
		if val, ok := claims[key].(string); ok {
			return val
		}
	}
	return ""
}

func getTimeClaim(claims jwt.MapClaims, key string) time.Time {
	if val, ok := claims[key]; ok {
		switch v := val.(type) {
		case float64:
			return time.Unix(int64(v), 0)
		case json.Number:
			if i, err := v.Int64(); err == nil {
				return time.Unix(i, 0)
			}
		}
	}
	return time.Time{}
}

func getAudienceClaim(claims jwt.MapClaims) []string {
	switch aud := claims["aud"].(type) {
	case string:
		return []string{aud}
	case []interface{}:
		result := make([]string, 0, len(aud))
		for _, a := range aud {
			if s, ok := a.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

func hasValidAudience(tokenAud, expectedAud []string) bool {
	for _, expected := range expectedAud {
		for _, actual := range tokenAud {
			if actual == expected {
				return true
			}
		}
	}
	return false
}

// extractRoles extracts roles from Keycloak-style claims.
func extractRoles(claims jwt.MapClaims) []string {
	var roles []string

	// Realm roles
	if realmAccess, ok := claims["realm_access"].(map[string]interface{}); ok {
		if realmRoles, ok := realmAccess["roles"].([]interface{}); ok {
			for _, r := range realmRoles {
				if role, ok := r.(string); ok {
					roles = append(roles, role)
				}
			}
		}
	}

	// Resource/client roles
	if resourceAccess, ok := claims["resource_access"].(map[string]interface{}); ok {
		for client, access := range resourceAccess {
			if clientAccess, ok := access.(map[string]interface{}); ok {
				if clientRoles, ok := clientAccess["roles"].([]interface{}); ok {
					for _, r := range clientRoles {
						if role, ok := r.(string); ok {
							roles = append(roles, fmt.Sprintf("%s:%s", client, role))
						}
					}
				}
			}
		}
	}

	// Direct roles claim (some OIDC providers)
	if directRoles, ok := claims["roles"].([]interface{}); ok {
		for _, r := range directRoles {
			if role, ok := r.(string); ok {
				roles = append(roles, role)
			}
		}
	}

	return roles
}

// extractScopes extracts scopes from token claims.
func extractScopes(claims jwt.MapClaims) []string {
	if scope, ok := claims["scope"].(string); ok {
		return strings.Split(scope, " ")
	}
	if scopes, ok := claims["scp"].([]interface{}); ok {
		result := make([]string, 0, len(scopes))
		for _, s := range scopes {
			if scope, ok := s.(string); ok {
				result = append(result, scope)
			}
		}
		return result
	}
	return nil
}
