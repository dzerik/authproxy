package idp

import (
	"context"
	"testing"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/model"
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
			if tt.err == nil {
				t.Error("error should not be nil")
			}
			if tt.err.Error() == "" {
				t.Error("error should have message")
			}
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

	if tokens.AccessToken != "access-token" {
		t.Errorf("AccessToken = %s, want access-token", tokens.AccessToken)
	}
	if tokens.RefreshToken != "refresh-token" {
		t.Errorf("RefreshToken = %s, want refresh-token", tokens.RefreshToken)
	}
	if tokens.IDToken != "id-token" {
		t.Errorf("IDToken = %s, want id-token", tokens.IDToken)
	}
	if tokens.TokenType != "Bearer" {
		t.Errorf("TokenType = %s, want Bearer", tokens.TokenType)
	}
	if tokens.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn = %d, want 3600", tokens.ExpiresIn)
	}
}

func TestAuthURLOptions_Struct(t *testing.T) {
	opts := AuthURLOptions{
		State:     "state-123",
		Nonce:     "nonce-456",
		IDPHint:   "google",
		LoginHint: "user@example.com",
		Prompt:    "login",
	}

	if opts.State != "state-123" {
		t.Errorf("State = %s, want state-123", opts.State)
	}
	if opts.Nonce != "nonce-456" {
		t.Errorf("Nonce = %s, want nonce-456", opts.Nonce)
	}
	if opts.IDPHint != "google" {
		t.Errorf("IDPHint = %s, want google", opts.IDPHint)
	}
	if opts.LoginHint != "user@example.com" {
		t.Errorf("LoginHint = %s, want user@example.com", opts.LoginHint)
	}
	if opts.Prompt != "login" {
		t.Errorf("Prompt = %s, want login", opts.Prompt)
	}
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
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	if m == nil {
		t.Fatal("NewManager returned nil")
	}

	if !m.IsDevMode() {
		t.Error("IsDevMode should return true")
	}

	if m.Provider() == nil {
		t.Error("Provider should not be nil")
	}

	if m.Provider().Name() != "mock" {
		t.Errorf("Provider.Name() = %s, want mock", m.Provider().Name())
	}
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
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Test GetSocialProviders
	providers := m.GetSocialProviders()
	if len(providers) != 2 {
		t.Errorf("GetSocialProviders length = %d, want 2", len(providers))
	}

	// Test AuthURL
	url := m.AuthURL(AuthURLOptions{State: "test-state"})
	if url == "" {
		t.Error("AuthURL should not be empty")
	}

	// Test Exchange
	tokens, err := m.Exchange(context.Background(), "mock_default")
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}
	if tokens.AccessToken == "" {
		t.Error("AccessToken should not be empty")
	}

	// Test UserInfo
	user, err := m.UserInfo(context.Background(), tokens.AccessToken)
	if err != nil {
		t.Fatalf("UserInfo failed: %v", err)
	}
	if user == nil {
		t.Error("UserInfo should not return nil")
	}

	// Test Refresh
	newTokens, err := m.Refresh(context.Background(), tokens.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}
	if newTokens.AccessToken == "" {
		t.Error("New AccessToken should not be empty")
	}

	// Test Verify
	verifiedUser, err := m.Verify(context.Background(), tokens.IDToken)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if verifiedUser == nil {
		t.Error("Verify should not return nil")
	}

	// Test LogoutURL
	logoutURL := m.LogoutURL("token-hint", "https://example.com/logout")
	if logoutURL == "" {
		t.Error("LogoutURL should not be empty")
	}
}

func TestTokenToOAuth2Token(t *testing.T) {
	tokens := &Tokens{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		TokenType:    "Bearer",
	}

	oauth2Token := tokenToOAuth2Token(tokens)

	if oauth2Token.AccessToken != "access-token" {
		t.Errorf("AccessToken = %s, want access-token", oauth2Token.AccessToken)
	}
	if oauth2Token.RefreshToken != "refresh-token" {
		t.Errorf("RefreshToken = %s, want refresh-token", oauth2Token.RefreshToken)
	}
	if oauth2Token.TokenType != "Bearer" {
		t.Errorf("TokenType = %s, want Bearer", oauth2Token.TokenType)
	}
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

	if p.Name() != "test" {
		t.Errorf("Name() = %s, want test", p.Name())
	}

	url := p.AuthURL(AuthURLOptions{State: "state-123"})
	if url == "" {
		t.Error("AuthURL should not be empty")
	}

	tokens, err := p.Exchange(context.Background(), "code")
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}
	if tokens.AccessToken != "test-access" {
		t.Errorf("AccessToken = %s, want test-access", tokens.AccessToken)
	}

	user, err := p.UserInfo(context.Background(), "token")
	if err != nil {
		t.Fatalf("UserInfo failed: %v", err)
	}
	if user.Email != "test@example.com" {
		t.Errorf("Email = %s, want test@example.com", user.Email)
	}

	newTokens, err := p.Refresh(context.Background(), "refresh")
	if err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}
	if newTokens.AccessToken != "new-access" {
		t.Errorf("AccessToken = %s, want new-access", newTokens.AccessToken)
	}

	verifiedUser, err := p.Verify(context.Background(), "id-token")
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if verifiedUser.ID != "user-1" {
		t.Errorf("ID = %s, want user-1", verifiedUser.ID)
	}

	logoutURL := p.LogoutURL("hint", "redirect")
	if logoutURL == "" {
		t.Error("LogoutURL should not be empty")
	}
}
