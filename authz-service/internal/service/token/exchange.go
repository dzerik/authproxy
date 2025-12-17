package token

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/your-org/authz-service/internal/domain"
	"github.com/your-org/authz-service/pkg/errors"
	"github.com/your-org/authz-service/pkg/logger"
)

// ExchangeService handles OAuth 2.0 Token Exchange (RFC 8693).
type ExchangeService struct {
	client       *http.Client
	tokenURL     string
	clientID     string
	clientSecret string
}

// ExchangeConfig holds token exchange configuration.
type ExchangeConfig struct {
	TokenURL     string
	ClientID     string
	ClientSecret string
	Timeout      time.Duration
}

// ExchangeRequest represents a token exchange request.
type ExchangeRequest struct {
	// SubjectToken is the token to be exchanged (required)
	SubjectToken string `json:"subject_token"`

	// SubjectTokenType indicates the type of the subject token
	// e.g., urn:ietf:params:oauth:token-type:access_token
	SubjectTokenType string `json:"subject_token_type"`

	// ActorToken is the token representing the actor (optional)
	ActorToken string `json:"actor_token,omitempty"`

	// ActorTokenType indicates the type of the actor token
	ActorTokenType string `json:"actor_token_type,omitempty"`

	// RequestedTokenType is the desired type of the new token (optional)
	// e.g., urn:ietf:params:oauth:token-type:access_token
	RequestedTokenType string `json:"requested_token_type,omitempty"`

	// Audience is the target service/resource for the new token (optional)
	Audience string `json:"audience,omitempty"`

	// Scope is the requested scope for the new token (optional)
	Scope string `json:"scope,omitempty"`

	// Resource is the resource indicator (optional)
	Resource string `json:"resource,omitempty"`
}

// ExchangeResponse represents a token exchange response.
type ExchangeResponse struct {
	// AccessToken is the newly issued token
	AccessToken string `json:"access_token"`

	// IssuedTokenType indicates the type of the issued token
	IssuedTokenType string `json:"issued_token_type"`

	// TokenType is the token type (usually "Bearer")
	TokenType string `json:"token_type"`

	// ExpiresIn is the lifetime of the token in seconds
	ExpiresIn int `json:"expires_in,omitempty"`

	// Scope is the scope of the issued token
	Scope string `json:"scope,omitempty"`

	// RefreshToken is the optional refresh token
	RefreshToken string `json:"refresh_token,omitempty"`
}

// Token type URNs per RFC 8693
const (
	TokenTypeAccessToken  = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token"
	TokenTypeIDToken      = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeJWT          = "urn:ietf:params:oauth:token-type:jwt"
	TokenTypeSAML1        = "urn:ietf:params:oauth:token-type:saml1"
	TokenTypeSAML2        = "urn:ietf:params:oauth:token-type:saml2"
)

// NewExchangeService creates a new token exchange service.
func NewExchangeService(cfg ExchangeConfig) *ExchangeService {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	return &ExchangeService{
		client: &http.Client{
			Timeout: timeout,
		},
		tokenURL:     cfg.TokenURL,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
	}
}

// Exchange performs a token exchange.
func (s *ExchangeService) Exchange(ctx context.Context, req *ExchangeRequest) (*ExchangeResponse, error) {
	if req.SubjectToken == "" {
		return nil, errors.NewAuthzError(errors.CodeTokenInvalid, "subject_token is required", nil)
	}

	if req.SubjectTokenType == "" {
		req.SubjectTokenType = TokenTypeAccessToken
	}

	// Build form data
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("subject_token", req.SubjectToken)
	form.Set("subject_token_type", req.SubjectTokenType)

	if req.ActorToken != "" {
		form.Set("actor_token", req.ActorToken)
		if req.ActorTokenType != "" {
			form.Set("actor_token_type", req.ActorTokenType)
		}
	}

	if req.RequestedTokenType != "" {
		form.Set("requested_token_type", req.RequestedTokenType)
	}

	if req.Audience != "" {
		form.Set("audience", req.Audience)
	}

	if req.Scope != "" {
		form.Set("scope", req.Scope)
	}

	if req.Resource != "" {
		form.Set("resource", req.Resource)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "failed to create exchange request")
	}

	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Add client authentication
	if s.clientID != "" && s.clientSecret != "" {
		httpReq.SetBasicAuth(s.clientID, s.clientSecret)
	}

	// Send request
	resp, err := s.client.Do(httpReq)
	if err != nil {
		return nil, errors.Wrap(err, "token exchange request failed")
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read exchange response")
	}

	// Check for error response
	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error != "" {
			return nil, errors.NewAuthzError(
				errors.CodeTokenInvalid,
				fmt.Sprintf("token exchange failed: %s - %s", errResp.Error, errResp.ErrorDescription),
				nil,
			)
		}
		return nil, errors.NewAuthzError(
			errors.CodeTokenInvalid,
			fmt.Sprintf("token exchange failed with status %d", resp.StatusCode),
			nil,
		)
	}

	// Parse successful response
	var exchangeResp ExchangeResponse
	if err := json.Unmarshal(body, &exchangeResp); err != nil {
		return nil, errors.Wrap(err, "failed to parse exchange response")
	}

	logger.Debug("token exchange successful",
		logger.String("issued_token_type", exchangeResp.IssuedTokenType),
		logger.Int("expires_in", exchangeResp.ExpiresIn),
	)

	return &exchangeResp, nil
}

// ExchangeForAudience exchanges a token for a specific audience/service.
func (s *ExchangeService) ExchangeForAudience(ctx context.Context, subjectToken, audience string) (*ExchangeResponse, error) {
	return s.Exchange(ctx, &ExchangeRequest{
		SubjectToken:       subjectToken,
		SubjectTokenType:   TokenTypeAccessToken,
		RequestedTokenType: TokenTypeAccessToken,
		Audience:           audience,
	})
}

// ExchangeWithDelegation exchanges a token with actor (delegation) information.
// This is used for scenarios like service-to-service calls on behalf of a user.
func (s *ExchangeService) ExchangeWithDelegation(ctx context.Context, subjectToken, actorToken, audience string) (*ExchangeResponse, error) {
	return s.Exchange(ctx, &ExchangeRequest{
		SubjectToken:       subjectToken,
		SubjectTokenType:   TokenTypeAccessToken,
		ActorToken:         actorToken,
		ActorTokenType:     TokenTypeAccessToken,
		RequestedTokenType: TokenTypeAccessToken,
		Audience:           audience,
	})
}

// Impersonate creates a token that represents impersonation.
// The new token will have the subject of subjectToken but will include
// "act" claim indicating the original caller.
func (s *ExchangeService) Impersonate(ctx context.Context, subjectToken, actorToken string) (*ExchangeResponse, error) {
	return s.Exchange(ctx, &ExchangeRequest{
		SubjectToken:       subjectToken,
		SubjectTokenType:   TokenTypeAccessToken,
		ActorToken:         actorToken,
		ActorTokenType:     TokenTypeAccessToken,
		RequestedTokenType: TokenTypeAccessToken,
	})
}

// ParseDelegationChain extracts the delegation chain from a token's "act" claim.
// RFC 8693 specifies nested "act" claims for delegation chains.
func ParseDelegationChain(tokenInfo *domain.TokenInfo) []DelegationInfo {
	var chain []DelegationInfo

	actClaim, ok := tokenInfo.GetExtraClaim("act")
	if !ok {
		return chain
	}

	// Parse nested act claims
	for actClaim != nil {
		actMap, ok := actClaim.(map[string]any)
		if !ok {
			break
		}

		info := DelegationInfo{}
		if sub, ok := actMap["sub"].(string); ok {
			info.Subject = sub
		}
		if iss, ok := actMap["iss"].(string); ok {
			info.Issuer = iss
		}
		if clientID, ok := actMap["client_id"].(string); ok {
			info.ClientID = clientID
		}

		chain = append(chain, info)

		// Check for nested act claim
		actClaim, _ = actMap["act"]
	}

	return chain
}

// DelegationInfo represents a single actor in a delegation chain.
type DelegationInfo struct {
	Subject  string `json:"sub"`
	Issuer   string `json:"iss,omitempty"`
	ClientID string `json:"client_id,omitempty"`
}
