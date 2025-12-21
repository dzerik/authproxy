package idp

import (
	"context"
	"errors"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/model"
	"golang.org/x/oauth2"
)

var (
	ErrProviderNotConfigured = errors.New("provider not configured")
	ErrAuthFailed            = errors.New("authentication failed")
	ErrTokenExchangeFailed   = errors.New("token exchange failed")
	ErrUserInfoFailed        = errors.New("failed to get user info")
	ErrRefreshFailed         = errors.New("token refresh failed")
	ErrInvalidState          = errors.New("invalid state parameter")
)

// Tokens represents OAuth2 tokens
type Tokens struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	TokenType    string
	ExpiresIn    int64 // seconds
}

// AuthURLOptions contains options for generating auth URL
type AuthURLOptions struct {
	State     string
	Nonce     string
	IDPHint   string // kc_idp_hint for Keycloak
	LoginHint string
	Prompt    string // none, login, consent, select_account
}

// Provider defines the interface for identity providers
type Provider interface {
	// Name returns the provider name
	Name() string

	// AuthURL generates the authorization URL
	AuthURL(opts AuthURLOptions) string

	// Exchange exchanges the authorization code for tokens
	Exchange(ctx context.Context, code string) (*Tokens, error)

	// UserInfo retrieves user information using the access token
	UserInfo(ctx context.Context, accessToken string) (*model.User, error)

	// Refresh refreshes the access token using the refresh token
	Refresh(ctx context.Context, refreshToken string) (*Tokens, error)

	// Verify verifies an ID token and returns claims
	Verify(ctx context.Context, idToken string) (*model.User, error)

	// LogoutURL returns the logout URL (for RP-initiated logout)
	LogoutURL(idTokenHint, postLogoutRedirectURI string) string
}

// Manager manages identity providers
type Manager struct {
	provider Provider
	config   *config.AuthConfig
	devMode  bool
}

// NewManager creates a new IdP manager
func NewManager(cfg *config.AuthConfig, devMode bool, devCfg *config.DevModeConfig) (*Manager, error) {
	var provider Provider
	var err error

	if devMode && devCfg != nil && devCfg.Enabled {
		provider, err = NewMockProvider(devCfg)
	} else {
		provider, err = NewOIDCProvider(&cfg.Keycloak)
	}

	if err != nil {
		return nil, err
	}

	return &Manager{
		provider: provider,
		config:   cfg,
		devMode:  devMode,
	}, nil
}

// Provider returns the underlying provider
func (m *Manager) Provider() Provider {
	return m.provider
}

// IsDevMode returns true if running in dev mode
func (m *Manager) IsDevMode() bool {
	return m.devMode
}

// AuthURL generates the authorization URL
func (m *Manager) AuthURL(opts AuthURLOptions) string {
	return m.provider.AuthURL(opts)
}

// Exchange exchanges the authorization code for tokens
func (m *Manager) Exchange(ctx context.Context, code string) (*Tokens, error) {
	return m.provider.Exchange(ctx, code)
}

// UserInfo retrieves user information
func (m *Manager) UserInfo(ctx context.Context, accessToken string) (*model.User, error) {
	return m.provider.UserInfo(ctx, accessToken)
}

// Refresh refreshes the access token
func (m *Manager) Refresh(ctx context.Context, refreshToken string) (*Tokens, error) {
	return m.provider.Refresh(ctx, refreshToken)
}

// Verify verifies an ID token
func (m *Manager) Verify(ctx context.Context, idToken string) (*model.User, error) {
	return m.provider.Verify(ctx, idToken)
}

// LogoutURL returns the logout URL
func (m *Manager) LogoutURL(idTokenHint, postLogoutRedirectURI string) string {
	return m.provider.LogoutURL(idTokenHint, postLogoutRedirectURI)
}

// GetSocialProviders returns configured social providers
func (m *Manager) GetSocialProviders() []config.SocialProvider {
	return m.config.Keycloak.SocialProviders
}

// tokenToOAuth2Token converts our Tokens to oauth2.Token
func tokenToOAuth2Token(t *Tokens) *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		TokenType:    t.TokenType,
	}
}
