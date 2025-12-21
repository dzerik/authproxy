package idp

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/model"
	"golang.org/x/oauth2"
)

// OIDCProvider implements Provider interface for OIDC/Keycloak
type OIDCProvider struct {
	config       *config.KeycloakConfig
	provider     *oidc.Provider
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
}

// NewOIDCProvider creates a new OIDC provider
func NewOIDCProvider(cfg *config.KeycloakConfig) (*OIDCProvider, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create OIDC provider (this fetches the discovery document)
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Configure OAuth2
	oauth2Config := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       cfg.Scopes,
	}

	// Ensure openid scope is included
	hasOpenID := false
	for _, s := range oauth2Config.Scopes {
		if s == oidc.ScopeOpenID {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		oauth2Config.Scopes = append([]string{oidc.ScopeOpenID}, oauth2Config.Scopes...)
	}

	// Create ID token verifier
	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
	})

	return &OIDCProvider{
		config:       cfg,
		provider:     provider,
		oauth2Config: oauth2Config,
		verifier:     verifier,
	}, nil
}

// Name returns the provider name
func (p *OIDCProvider) Name() string {
	return "keycloak"
}

// AuthURL generates the authorization URL
func (p *OIDCProvider) AuthURL(opts AuthURLOptions) string {
	var authOpts []oauth2.AuthCodeOption

	// Add nonce
	if opts.Nonce != "" {
		authOpts = append(authOpts, oauth2.SetAuthURLParam("nonce", opts.Nonce))
	}

	// Add kc_idp_hint for Keycloak social login
	if opts.IDPHint != "" {
		authOpts = append(authOpts, oauth2.SetAuthURLParam("kc_idp_hint", opts.IDPHint))
	}

	// Add login_hint
	if opts.LoginHint != "" {
		authOpts = append(authOpts, oauth2.SetAuthURLParam("login_hint", opts.LoginHint))
	}

	// Add prompt
	if opts.Prompt != "" {
		authOpts = append(authOpts, oauth2.SetAuthURLParam("prompt", opts.Prompt))
	}

	return p.oauth2Config.AuthCodeURL(opts.State, authOpts...)
}

// Exchange exchanges the authorization code for tokens
func (p *OIDCProvider) Exchange(ctx context.Context, code string) (*Tokens, error) {
	token, err := p.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenExchangeFailed, err)
	}

	// Extract ID token
	idToken, _ := token.Extra("id_token").(string)

	// Calculate expires_in
	expiresIn := int64(0)
	if !token.Expiry.IsZero() {
		expiresIn = int64(time.Until(token.Expiry).Seconds())
	}

	return &Tokens{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		IDToken:      idToken,
		TokenType:    token.TokenType,
		ExpiresIn:    expiresIn,
	}, nil
}

// UserInfo retrieves user information using the access token
func (p *OIDCProvider) UserInfo(ctx context.Context, accessToken string) (*model.User, error) {
	userInfo, err := p.provider.UserInfo(ctx, oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: accessToken,
	}))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUserInfoFailed, err)
	}

	// Parse claims
	var claims struct {
		Sub               string   `json:"sub"`
		Email             string   `json:"email"`
		EmailVerified     bool     `json:"email_verified"`
		Name              string   `json:"name"`
		PreferredUsername string   `json:"preferred_username"`
		GivenName         string   `json:"given_name"`
		FamilyName        string   `json:"family_name"`
		Picture           string   `json:"picture"`
		Locale            string   `json:"locale"`
		RealmAccess       struct {
			Roles []string `json:"roles"`
		} `json:"realm_access"`
		ResourceAccess map[string]struct {
			Roles []string `json:"roles"`
		} `json:"resource_access"`
		Groups   []string `json:"groups"`
		TenantID string   `json:"tenant_id"`
	}

	if err := userInfo.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	// Collect all roles
	roles := claims.RealmAccess.Roles
	for _, ra := range claims.ResourceAccess {
		roles = append(roles, ra.Roles...)
	}

	return &model.User{
		ID:            claims.Sub,
		Email:         claims.Email,
		Name:          claims.Name,
		PreferredName: claims.PreferredUsername,
		GivenName:     claims.GivenName,
		FamilyName:    claims.FamilyName,
		Picture:       claims.Picture,
		Locale:        claims.Locale,
		Roles:         uniqueStrings(roles),
		Groups:        claims.Groups,
		TenantID:      claims.TenantID,
		CreatedAt:     time.Now(),
	}, nil
}

// Refresh refreshes the access token using the refresh token
func (p *OIDCProvider) Refresh(ctx context.Context, refreshToken string) (*Tokens, error) {
	tokenSource := p.oauth2Config.TokenSource(ctx, &oauth2.Token{
		RefreshToken: refreshToken,
	})

	token, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRefreshFailed, err)
	}

	idToken, _ := token.Extra("id_token").(string)

	expiresIn := int64(0)
	if !token.Expiry.IsZero() {
		expiresIn = int64(time.Until(token.Expiry).Seconds())
	}

	return &Tokens{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		IDToken:      idToken,
		TokenType:    token.TokenType,
		ExpiresIn:    expiresIn,
	}, nil
}

// Verify verifies an ID token and returns user info from claims
func (p *OIDCProvider) Verify(ctx context.Context, rawIDToken string) (*model.User, error) {
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	var claims struct {
		Sub               string   `json:"sub"`
		Email             string   `json:"email"`
		Name              string   `json:"name"`
		PreferredUsername string   `json:"preferred_username"`
		GivenName         string   `json:"given_name"`
		FamilyName        string   `json:"family_name"`
		Picture           string   `json:"picture"`
		Locale            string   `json:"locale"`
		RealmAccess       struct {
			Roles []string `json:"roles"`
		} `json:"realm_access"`
		Groups   []string `json:"groups"`
		TenantID string   `json:"tenant_id"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	return &model.User{
		ID:            claims.Sub,
		Email:         claims.Email,
		Name:          claims.Name,
		PreferredName: claims.PreferredUsername,
		GivenName:     claims.GivenName,
		FamilyName:    claims.FamilyName,
		Picture:       claims.Picture,
		Locale:        claims.Locale,
		Roles:         claims.RealmAccess.Roles,
		Groups:        claims.Groups,
		TenantID:      claims.TenantID,
		CreatedAt:     time.Now(),
	}, nil
}

// LogoutURL returns the RP-initiated logout URL
func (p *OIDCProvider) LogoutURL(idTokenHint, postLogoutRedirectURI string) string {
	// Keycloak logout endpoint
	logoutURL := strings.TrimSuffix(p.config.IssuerURL, "/") + "/protocol/openid-connect/logout"

	params := url.Values{}
	if idTokenHint != "" {
		params.Set("id_token_hint", idTokenHint)
	}
	if postLogoutRedirectURI != "" {
		params.Set("post_logout_redirect_uri", postLogoutRedirectURI)
	}
	params.Set("client_id", p.config.ClientID)

	if len(params) > 0 {
		logoutURL += "?" + params.Encode()
	}

	return logoutURL
}

// uniqueStrings returns unique strings from a slice
func uniqueStrings(s []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}
