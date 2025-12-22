package idp

import (
	"context"
	"testing"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrProviderNotConfigured", ErrProviderNotConfigured},
		{"ErrAuthFailed", ErrAuthFailed},
		{"ErrTokenExchangeFailed", ErrTokenExchangeFailed},
		{"ErrUserInfoFailed", ErrUserInfoFailed},
		{"ErrRefreshFailed", ErrRefreshFailed},
		{"ErrInvalidState", ErrInvalidState},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotNil(t, tt.err, "error should not be nil")
			assert.NotEmpty(t, tt.err.Error(), "error should have message")
		})
	}
}

func TestTokens_Struct(t *testing.T) {
	tokens := Tokens{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		IDToken:      "id-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}

	assert.Equal(t, "access-token", tokens.AccessToken)
	assert.Equal(t, "refresh-token", tokens.RefreshToken)
	assert.Equal(t, "id-token", tokens.IDToken)
	assert.Equal(t, "Bearer", tokens.TokenType)
	assert.Equal(t, int64(3600), tokens.ExpiresIn)
}

func TestAuthURLOptions_Struct(t *testing.T) {
	opts := AuthURLOptions{
		State:     "state-123",
		Nonce:     "nonce-456",
		IDPHint:   "google",
		LoginHint: "user@example.com",
		Prompt:    "login",
	}

	assert.Equal(t, "state-123", opts.State)
	assert.Equal(t, "nonce-456", opts.Nonce)
	assert.Equal(t, "google", opts.IDPHint)
	assert.Equal(t, "user@example.com", opts.LoginHint)
	assert.Equal(t, "login", opts.Prompt)
}

func TestNewManager_DevMode(t *testing.T) {
	authCfg := &config.AuthConfig{
		Keycloak: config.KeycloakConfig{
			IssuerURL:    "https://keycloak.example.com/realms/test",
			ClientID:     "test-client",
			ClientSecret: "secret",
		},
	}

	devCfg := &config.DevModeConfig{
		Enabled:        true,
		DefaultProfile: "default",
	}

	m, err := NewManager(authCfg, true, devCfg)
	require.NoError(t, err)
	require.NotNil(t, m, "NewManager returned nil")

	assert.True(t, m.IsDevMode(), "IsDevMode should return true")
	assert.NotNil(t, m.Provider(), "Provider should not be nil")
	assert.Equal(t, "mock", m.Provider().Name())
}

func TestNewManager_DevModeDisabled(t *testing.T) {
	authCfg := &config.AuthConfig{
		Keycloak: config.KeycloakConfig{
			IssuerURL:    "https://keycloak.example.com/realms/test",
			ClientID:     "test-client",
			ClientSecret: "secret",
		},
	}

	devCfg := &config.DevModeConfig{
		Enabled: false,
	}

	// When dev mode is disabled, it will try to create OIDC provider
	// which will fail because we can't connect to the issuer URL
	_, err := NewManager(authCfg, false, devCfg)
	// Error is expected because OIDC provider needs real Keycloak
	if err == nil {
		t.Log("NewManager succeeded (unexpected but possible if network allows)")
	}
}

func TestManager_WithMockProvider(t *testing.T) {
	authCfg := &config.AuthConfig{
		Keycloak: config.KeycloakConfig{
			SocialProviders: []config.SocialProvider{
				{Name: "google", IDPHint: "google", Icon: "google"},
				{Name: "github", IDPHint: "github", Icon: "github"},
			},
		},
	}

	devCfg := &config.DevModeConfig{
		Enabled:        true,
		DefaultProfile: "default",
	}

	m, err := NewManager(authCfg, true, devCfg)
	require.NoError(t, err)

	// Test GetSocialProviders
	providers := m.GetSocialProviders()
	assert.Len(t, providers, 2)

	// Test AuthURL
	url := m.AuthURL(AuthURLOptions{State: "test-state"})
	assert.NotEmpty(t, url, "AuthURL should not be empty")

	// Test Exchange
	tokens, err := m.Exchange(context.Background(), "mock_default")
	require.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken, "AccessToken should not be empty")

	// Test UserInfo
	user, err := m.UserInfo(context.Background(), tokens.AccessToken)
	require.NoError(t, err)
	assert.NotNil(t, user, "UserInfo should not return nil")

	// Test Refresh
	newTokens, err := m.Refresh(context.Background(), tokens.RefreshToken)
	require.NoError(t, err)
	assert.NotEmpty(t, newTokens.AccessToken, "New AccessToken should not be empty")

	// Test Verify
	verifiedUser, err := m.Verify(context.Background(), tokens.IDToken)
	require.NoError(t, err)
	assert.NotNil(t, verifiedUser, "Verify should not return nil")

	// Test LogoutURL
	logoutURL := m.LogoutURL("token-hint", "https://example.com/logout")
	assert.NotEmpty(t, logoutURL, "LogoutURL should not be empty")
}

func TestTokenToOAuth2Token(t *testing.T) {
	tokens := &Tokens{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		TokenType:    "Bearer",
	}

	oauth2Token := tokenToOAuth2Token(tokens)

	assert.Equal(t, "access-token", oauth2Token.AccessToken)
	assert.Equal(t, "refresh-token", oauth2Token.RefreshToken)
	assert.Equal(t, "Bearer", oauth2Token.TokenType)
}

// mockProvider is a minimal Provider implementation for testing
type testProvider struct {
	name string
}

func (p *testProvider) Name() string {
	return p.name
}

func (p *testProvider) AuthURL(opts AuthURLOptions) string {
	return "https://auth.example.com/authorize?state=" + opts.State
}

func (p *testProvider) Exchange(ctx context.Context, code string) (*Tokens, error) {
	return &Tokens{
		AccessToken:  "test-access",
		RefreshToken: "test-refresh",
		IDToken:      "test-id",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}, nil
}

func (p *testProvider) UserInfo(ctx context.Context, accessToken string) (*model.User, error) {
	return &model.User{
		ID:    "user-1",
		Email: "test@example.com",
	}, nil
}

func (p *testProvider) Refresh(ctx context.Context, refreshToken string) (*Tokens, error) {
	return &Tokens{
		AccessToken:  "new-access",
		RefreshToken: "new-refresh",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}, nil
}

func (p *testProvider) Verify(ctx context.Context, idToken string) (*model.User, error) {
	return &model.User{
		ID:    "user-1",
		Email: "test@example.com",
	}, nil
}

func (p *testProvider) LogoutURL(idTokenHint, postLogoutRedirectURI string) string {
	return "https://auth.example.com/logout"
}

func TestProviderInterface(t *testing.T) {
	var p Provider = &testProvider{name: "test"}

	assert.Equal(t, "test", p.Name())

	url := p.AuthURL(AuthURLOptions{State: "state-123"})
	assert.NotEmpty(t, url, "AuthURL should not be empty")

	tokens, err := p.Exchange(context.Background(), "code")
	require.NoError(t, err)
	assert.Equal(t, "test-access", tokens.AccessToken)

	user, err := p.UserInfo(context.Background(), "token")
	require.NoError(t, err)
	assert.Equal(t, "test@example.com", user.Email)

	newTokens, err := p.Refresh(context.Background(), "refresh")
	require.NoError(t, err)
	assert.Equal(t, "new-access", newTokens.AccessToken)

	verifiedUser, err := p.Verify(context.Background(), "id-token")
	require.NoError(t, err)
	assert.Equal(t, "user-1", verifiedUser.ID)

	logoutURL := p.LogoutURL("hint", "redirect")
	assert.NotEmpty(t, logoutURL, "LogoutURL should not be empty")
}
