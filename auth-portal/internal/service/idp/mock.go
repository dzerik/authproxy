package idp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/model"
	"gopkg.in/yaml.v3"
)

// ProfileUser represents user data in a profile YAML file
type ProfileUser struct {
	ID            string   `yaml:"id"`
	Email         string   `yaml:"email"`
	Name          string   `yaml:"name"`
	PreferredName string   `yaml:"preferred_name"`
	GivenName     string   `yaml:"given_name"`
	FamilyName    string   `yaml:"family_name"`
	Picture       string   `yaml:"picture"`
	Locale        string   `yaml:"locale"`
	Roles         []string `yaml:"roles"`
	Groups        []string `yaml:"groups"`
	TenantID      string   `yaml:"tenant_id"`
}

// Profile represents a dev mode profile
type Profile struct {
	User ProfileUser `yaml:"user"`
}

// MockProvider implements Provider interface for development mode
type MockProvider struct {
	config         *config.DevModeConfig
	profiles       map[string]*Profile
	defaultProfile string
	mu             sync.RWMutex
}

// NewMockProvider creates a new mock provider for dev mode
func NewMockProvider(cfg *config.DevModeConfig) (*MockProvider, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, fmt.Errorf("dev mode is not enabled")
	}

	provider := &MockProvider{
		config:         cfg,
		profiles:       make(map[string]*Profile),
		defaultProfile: cfg.DefaultProfile,
	}

	// Load profiles
	if err := provider.loadProfiles(); err != nil {
		return nil, fmt.Errorf("failed to load profiles: %w", err)
	}

	// Validate default profile exists
	if provider.defaultProfile != "" {
		if _, exists := provider.profiles[provider.defaultProfile]; !exists {
			return nil, fmt.Errorf("default profile '%s' not found", provider.defaultProfile)
		}
	}

	return provider, nil
}

// loadProfiles loads all YAML profiles from the profiles directory
func (p *MockProvider) loadProfiles() error {
	profilesDir := p.config.ProfilesDir
	if profilesDir == "" {
		profilesDir = "./configs/profiles"
	}

	// Check if directory exists
	info, err := os.Stat(profilesDir)
	if err != nil {
		if os.IsNotExist(err) {
			// Create default profile in memory if directory doesn't exist
			p.profiles["default"] = &Profile{
				User: ProfileUser{
					ID:       "mock-user-1",
					Email:    "mock@local",
					Name:     "Mock User",
					Roles:    []string{"user"},
					Groups:   []string{"default"},
					TenantID: "default",
				},
			}
			if p.defaultProfile == "" {
				p.defaultProfile = "default"
			}
			return nil
		}
		return fmt.Errorf("failed to access profiles directory: %w", err)
	}

	if !info.IsDir() {
		return fmt.Errorf("profiles path is not a directory: %s", profilesDir)
	}

	// Load all YAML files
	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		return fmt.Errorf("failed to read profiles directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		ext := filepath.Ext(name)
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		profileName := name[:len(name)-len(ext)]
		profilePath := filepath.Join(profilesDir, name)

		profile, err := p.loadProfile(profilePath)
		if err != nil {
			return fmt.Errorf("failed to load profile '%s': %w", profileName, err)
		}

		p.profiles[profileName] = profile
	}

	// Set default profile if not set and profiles exist
	if p.defaultProfile == "" && len(p.profiles) > 0 {
		for name := range p.profiles {
			p.defaultProfile = name
			break
		}
	}

	return nil
}

// loadProfile loads a single profile from a YAML file
func (p *MockProvider) loadProfile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var profile Profile
	if err := yaml.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return &profile, nil
}

// Name returns the provider name
func (p *MockProvider) Name() string {
	return "mock"
}

// AuthURL generates a mock authorization URL
// In dev mode, this redirects to the callback with a mock code
func (p *MockProvider) AuthURL(opts AuthURLOptions) string {
	// For mock provider, we construct a URL that will be handled by our callback
	// The code contains the profile name to use
	profile := p.defaultProfile
	if opts.IDPHint != "" {
		// Use IDPHint as profile selector
		if _, exists := p.profiles[opts.IDPHint]; exists {
			profile = opts.IDPHint
		}
	}

	return fmt.Sprintf("/callback?code=mock_%s&state=%s", profile, opts.State)
}

// Exchange exchanges the mock authorization code for tokens
func (p *MockProvider) Exchange(ctx context.Context, code string) (*Tokens, error) {
	// Extract profile name from mock code
	profileName := p.defaultProfile
	if len(code) > 5 && code[:5] == "mock_" {
		profileName = code[5:]
	}

	p.mu.RLock()
	profile, exists := p.profiles[profileName]
	p.mu.RUnlock()

	if !exists {
		profile = p.profiles[p.defaultProfile]
		if profile == nil {
			return nil, fmt.Errorf("%w: profile not found", ErrTokenExchangeFailed)
		}
	}

	// Generate mock tokens
	mockAccessToken := fmt.Sprintf("mock_access_%s_%d", profileName, time.Now().Unix())
	mockRefreshToken := fmt.Sprintf("mock_refresh_%s_%d", profileName, time.Now().Unix())
	mockIDToken := fmt.Sprintf("mock_id_%s_%d", profileName, time.Now().Unix())

	return &Tokens{
		AccessToken:  mockAccessToken,
		RefreshToken: mockRefreshToken,
		IDToken:      mockIDToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600, // 1 hour
	}, nil
}

// UserInfo retrieves user information from the mock profile
func (p *MockProvider) UserInfo(ctx context.Context, accessToken string) (*model.User, error) {
	// Extract profile name from access token
	profileName := p.extractProfileFromToken(accessToken)

	p.mu.RLock()
	profile, exists := p.profiles[profileName]
	p.mu.RUnlock()

	if !exists {
		profile = p.profiles[p.defaultProfile]
		if profile == nil {
			return nil, fmt.Errorf("%w: profile not found", ErrUserInfoFailed)
		}
	}

	return p.profileToUser(profile), nil
}

// Refresh refreshes the mock tokens
func (p *MockProvider) Refresh(ctx context.Context, refreshToken string) (*Tokens, error) {
	// Extract profile name from refresh token
	profileName := p.extractProfileFromToken(refreshToken)

	// Generate new mock tokens
	mockAccessToken := fmt.Sprintf("mock_access_%s_%d", profileName, time.Now().Unix())
	mockRefreshToken := fmt.Sprintf("mock_refresh_%s_%d", profileName, time.Now().Unix())
	mockIDToken := fmt.Sprintf("mock_id_%s_%d", profileName, time.Now().Unix())

	return &Tokens{
		AccessToken:  mockAccessToken,
		RefreshToken: mockRefreshToken,
		IDToken:      mockIDToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}, nil
}

// Verify verifies a mock ID token
func (p *MockProvider) Verify(ctx context.Context, rawIDToken string) (*model.User, error) {
	// Extract profile name from ID token
	profileName := p.extractProfileFromToken(rawIDToken)

	p.mu.RLock()
	profile, exists := p.profiles[profileName]
	p.mu.RUnlock()

	if !exists {
		profile = p.profiles[p.defaultProfile]
		if profile == nil {
			return nil, fmt.Errorf("failed to verify ID token: profile not found")
		}
	}

	return p.profileToUser(profile), nil
}

// LogoutURL returns a mock logout URL
func (p *MockProvider) LogoutURL(idTokenHint, postLogoutRedirectURI string) string {
	if postLogoutRedirectURI != "" {
		return postLogoutRedirectURI
	}
	return "/login"
}

// GetProfile returns a profile by name
func (p *MockProvider) GetProfile(name string) (*Profile, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	profile, exists := p.profiles[name]
	return profile, exists
}

// GetProfiles returns all available profile names
func (p *MockProvider) GetProfiles() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	names := make([]string, 0, len(p.profiles))
	for name := range p.profiles {
		names = append(names, name)
	}
	return names
}

// SetActiveProfile sets a profile as active (for session-based switching)
func (p *MockProvider) SetActiveProfile(name string) error {
	p.mu.RLock()
	_, exists := p.profiles[name]
	p.mu.RUnlock()

	if !exists {
		return fmt.Errorf("profile '%s' not found", name)
	}

	p.mu.Lock()
	p.defaultProfile = name
	p.mu.Unlock()

	return nil
}

// extractProfileFromToken extracts profile name from a mock token
func (p *MockProvider) extractProfileFromToken(token string) string {
	// Token format: mock_type_profilename_timestamp
	// Example: mock_access_developer_1234567890
	if len(token) < 12 {
		return p.defaultProfile
	}

	// Find the profile name between type and timestamp
	// Skip "mock_" prefix
	rest := token[5:]

	// Skip type (access/refresh/id) and underscore
	for i, c := range rest {
		if c == '_' {
			rest = rest[i+1:]
			break
		}
	}

	// Extract profile name (everything before last underscore)
	lastUnderscore := -1
	for i := len(rest) - 1; i >= 0; i-- {
		if rest[i] == '_' {
			lastUnderscore = i
			break
		}
	}

	if lastUnderscore > 0 {
		return rest[:lastUnderscore]
	}

	return p.defaultProfile
}

// profileToUser converts a Profile to a model.User
func (p *MockProvider) profileToUser(profile *Profile) *model.User {
	return &model.User{
		ID:            profile.User.ID,
		Email:         profile.User.Email,
		Name:          profile.User.Name,
		PreferredName: profile.User.PreferredName,
		GivenName:     profile.User.GivenName,
		FamilyName:    profile.User.FamilyName,
		Picture:       profile.User.Picture,
		Locale:        profile.User.Locale,
		Roles:         profile.User.Roles,
		Groups:        profile.User.Groups,
		TenantID:      profile.User.TenantID,
		CreatedAt:     time.Now(),
	}
}

// ReloadProfiles reloads profiles from disk
func (p *MockProvider) ReloadProfiles() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.profiles = make(map[string]*Profile)
	return p.loadProfiles()
}
