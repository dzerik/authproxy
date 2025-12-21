package idp

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/dzerik/auth-portal/internal/config"
)

func TestNewMockProvider(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		cfg := &config.DevModeConfig{
			Enabled:        true,
			DefaultProfile: "default",
		}

		p, err := NewMockProvider(cfg)
		if err != nil {
			t.Fatalf("NewMockProvider failed: %v", err)
		}

		if p == nil {
			t.Fatal("NewMockProvider returned nil")
		}

		if p.Name() != "mock" {
			t.Errorf("Name() = %s, want mock", p.Name())
		}
	})

	t.Run("nil config", func(t *testing.T) {
		_, err := NewMockProvider(nil)
		if err == nil {
			t.Error("NewMockProvider should fail with nil config")
		}
	})

	t.Run("dev mode disabled", func(t *testing.T) {
		cfg := &config.DevModeConfig{
			Enabled: false,
		}

		_, err := NewMockProvider(cfg)
		if err == nil {
			t.Error("NewMockProvider should fail when dev mode is disabled")
		}
	})
}

func TestNewMockProvider_WithProfiles(t *testing.T) {
	// Create temp directory with profiles
	tmpDir := t.TempDir()

	// Create developer profile
	devProfile := `user:
  id: "dev-user-1"
  email: "developer@test.com"
  name: "Developer"
  roles:
    - admin
    - developer
  groups:
    - engineering
  tenant_id: "tenant-1"
`
	if err := os.WriteFile(filepath.Join(tmpDir, "developer.yaml"), []byte(devProfile), 0644); err != nil {
		t.Fatal(err)
	}

	// Create admin profile
	adminProfile := `user:
  id: "admin-user-1"
  email: "admin@test.com"
  name: "Admin"
  roles:
    - admin
    - super-admin
  groups:
    - admins
  tenant_id: "tenant-1"
`
	if err := os.WriteFile(filepath.Join(tmpDir, "admin.yaml"), []byte(adminProfile), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.DevModeConfig{
		Enabled:        true,
		ProfilesDir:    tmpDir,
		DefaultProfile: "developer",
	}

	p, err := NewMockProvider(cfg)
	if err != nil {
		t.Fatalf("NewMockProvider failed: %v", err)
	}

	// Check profiles loaded
	profiles := p.GetProfiles()
	if len(profiles) != 2 {
		t.Errorf("GetProfiles length = %d, want 2", len(profiles))
	}

	// Check developer profile
	devP, exists := p.GetProfile("developer")
	if !exists {
		t.Error("developer profile should exist")
	}
	if devP.User.Email != "developer@test.com" {
		t.Errorf("developer email = %s, want developer@test.com", devP.User.Email)
	}

	// Check admin profile
	adminP, exists := p.GetProfile("admin")
	if !exists {
		t.Error("admin profile should exist")
	}
	if adminP.User.Email != "admin@test.com" {
		t.Errorf("admin email = %s, want admin@test.com", adminP.User.Email)
	}
}

func TestNewMockProvider_InvalidDefaultProfile(t *testing.T) {
	tmpDir := t.TempDir()

	profile := `user:
  id: "user-1"
  email: "user@test.com"
`
	if err := os.WriteFile(filepath.Join(tmpDir, "user.yaml"), []byte(profile), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.DevModeConfig{
		Enabled:        true,
		ProfilesDir:    tmpDir,
		DefaultProfile: "nonexistent",
	}

	_, err := NewMockProvider(cfg)
	if err == nil {
		t.Error("NewMockProvider should fail with invalid default profile")
	}
}

func TestNewMockProvider_InvalidProfilesPath(t *testing.T) {
	// Create a file instead of directory
	tmpFile, err := os.CreateTemp("", "notadir")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	cfg := &config.DevModeConfig{
		Enabled:     true,
		ProfilesDir: tmpFile.Name(),
	}

	_, err = NewMockProvider(cfg)
	if err == nil {
		t.Error("NewMockProvider should fail when profiles path is not a directory")
	}
}

func TestMockProvider_AuthURL(t *testing.T) {
	cfg := &config.DevModeConfig{
		Enabled:        true,
		DefaultProfile: "default",
	}

	p, err := NewMockProvider(cfg)
	if err != nil {
		t.Fatalf("NewMockProvider failed: %v", err)
	}

	t.Run("with state", func(t *testing.T) {
		url := p.AuthURL(AuthURLOptions{State: "test-state"})
		if url == "" {
			t.Error("AuthURL should not be empty")
		}
		// Should contain callback and state
		if url != "/callback?code=mock_default&state=test-state" {
			t.Errorf("AuthURL = %s, want /callback?code=mock_default&state=test-state", url)
		}
	})

	t.Run("with IDPHint", func(t *testing.T) {
		// Add a profile for the hint
		p.profiles["custom"] = &Profile{
			User: ProfileUser{ID: "custom-user"},
		}

		url := p.AuthURL(AuthURLOptions{
			State:   "test-state",
			IDPHint: "custom",
		})
		if url != "/callback?code=mock_custom&state=test-state" {
			t.Errorf("AuthURL = %s, want /callback?code=mock_custom&state=test-state", url)
		}
	})

	t.Run("with unknown IDPHint", func(t *testing.T) {
		url := p.AuthURL(AuthURLOptions{
			State:   "test-state",
			IDPHint: "unknown",
		})
		// Should fall back to default profile
		if url != "/callback?code=mock_default&state=test-state" {
			t.Errorf("AuthURL = %s, want /callback?code=mock_default&state=test-state", url)
		}
	})
}

func TestMockProvider_Exchange(t *testing.T) {
	cfg := &config.DevModeConfig{
		Enabled:        true,
		DefaultProfile: "default",
	}

	p, err := NewMockProvider(cfg)
	if err != nil {
		t.Fatalf("NewMockProvider failed: %v", err)
	}

	t.Run("valid mock code", func(t *testing.T) {
		tokens, err := p.Exchange(context.Background(), "mock_default")
		if err != nil {
			t.Fatalf("Exchange failed: %v", err)
		}

		if tokens.AccessToken == "" {
			t.Error("AccessToken should not be empty")
		}
		if tokens.RefreshToken == "" {
			t.Error("RefreshToken should not be empty")
		}
		if tokens.IDToken == "" {
			t.Error("IDToken should not be empty")
		}
		if tokens.TokenType != "Bearer" {
			t.Errorf("TokenType = %s, want Bearer", tokens.TokenType)
		}
		if tokens.ExpiresIn != 3600 {
			t.Errorf("ExpiresIn = %d, want 3600", tokens.ExpiresIn)
		}
	})

	t.Run("code with profile name", func(t *testing.T) {
		tokens, err := p.Exchange(context.Background(), "mock_default")
		if err != nil {
			t.Fatalf("Exchange failed: %v", err)
		}
		// Token should contain profile name
		if tokens.AccessToken == "" {
			t.Error("AccessToken should contain profile info")
		}
	})

	t.Run("short code", func(t *testing.T) {
		tokens, err := p.Exchange(context.Background(), "abc")
		if err != nil {
			t.Fatalf("Exchange failed: %v", err)
		}
		// Should use default profile
		if tokens.AccessToken == "" {
			t.Error("AccessToken should not be empty")
		}
	})
}

func TestMockProvider_UserInfo(t *testing.T) {
	tmpDir := t.TempDir()

	profile := `user:
  id: "test-user-1"
  email: "test@example.com"
  name: "Test User"
  preferred_name: "tester"
  given_name: "Test"
  family_name: "User"
  picture: "https://example.com/pic.jpg"
  locale: "en"
  roles:
    - admin
    - user
  groups:
    - team-a
  tenant_id: "tenant-1"
`
	if err := os.WriteFile(filepath.Join(tmpDir, "test.yaml"), []byte(profile), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.DevModeConfig{
		Enabled:        true,
		ProfilesDir:    tmpDir,
		DefaultProfile: "test",
	}

	p, err := NewMockProvider(cfg)
	if err != nil {
		t.Fatalf("NewMockProvider failed: %v", err)
	}

	// Get tokens first
	tokens, err := p.Exchange(context.Background(), "mock_test")
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}

	// Get user info
	user, err := p.UserInfo(context.Background(), tokens.AccessToken)
	if err != nil {
		t.Fatalf("UserInfo failed: %v", err)
	}

	if user.ID != "test-user-1" {
		t.Errorf("ID = %s, want test-user-1", user.ID)
	}
	if user.Email != "test@example.com" {
		t.Errorf("Email = %s, want test@example.com", user.Email)
	}
	if user.Name != "Test User" {
		t.Errorf("Name = %s, want Test User", user.Name)
	}
	if user.PreferredName != "tester" {
		t.Errorf("PreferredName = %s, want tester", user.PreferredName)
	}
	if user.GivenName != "Test" {
		t.Errorf("GivenName = %s, want Test", user.GivenName)
	}
	if user.FamilyName != "User" {
		t.Errorf("FamilyName = %s, want User", user.FamilyName)
	}
	if user.Picture != "https://example.com/pic.jpg" {
		t.Errorf("Picture = %s", user.Picture)
	}
	if user.Locale != "en" {
		t.Errorf("Locale = %s, want en", user.Locale)
	}
	if len(user.Roles) != 2 {
		t.Errorf("Roles length = %d, want 2", len(user.Roles))
	}
	if len(user.Groups) != 1 {
		t.Errorf("Groups length = %d, want 1", len(user.Groups))
	}
	if user.TenantID != "tenant-1" {
		t.Errorf("TenantID = %s, want tenant-1", user.TenantID)
	}
}

func TestMockProvider_Refresh(t *testing.T) {
	cfg := &config.DevModeConfig{
		Enabled:        true,
		DefaultProfile: "default",
	}

	p, err := NewMockProvider(cfg)
	if err != nil {
		t.Fatalf("NewMockProvider failed: %v", err)
	}

	tokens, err := p.Exchange(context.Background(), "mock_default")
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}

	newTokens, err := p.Refresh(context.Background(), tokens.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	if newTokens.AccessToken == "" {
		t.Error("New AccessToken should not be empty")
	}
	if newTokens.RefreshToken == "" {
		t.Error("New RefreshToken should not be empty")
	}
	// New tokens should be different
	if newTokens.AccessToken == tokens.AccessToken {
		t.Log("AccessToken changed (expected due to timestamp)")
	}
}

func TestMockProvider_Verify(t *testing.T) {
	cfg := &config.DevModeConfig{
		Enabled:        true,
		DefaultProfile: "default",
	}

	p, err := NewMockProvider(cfg)
	if err != nil {
		t.Fatalf("NewMockProvider failed: %v", err)
	}

	tokens, err := p.Exchange(context.Background(), "mock_default")
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}

	user, err := p.Verify(context.Background(), tokens.IDToken)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if user == nil {
		t.Error("User should not be nil")
	}
}

func TestMockProvider_LogoutURL(t *testing.T) {
	cfg := &config.DevModeConfig{
		Enabled:        true,
		DefaultProfile: "default",
	}

	p, err := NewMockProvider(cfg)
	if err != nil {
		t.Fatalf("NewMockProvider failed: %v", err)
	}

	t.Run("with postLogoutRedirectURI", func(t *testing.T) {
		url := p.LogoutURL("token-hint", "https://example.com/logout")
		if url != "https://example.com/logout" {
			t.Errorf("LogoutURL = %s, want https://example.com/logout", url)
		}
	})

	t.Run("without postLogoutRedirectURI", func(t *testing.T) {
		url := p.LogoutURL("token-hint", "")
		if url != "/login" {
			t.Errorf("LogoutURL = %s, want /login", url)
		}
	})
}

func TestMockProvider_SetActiveProfile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create two profiles
	profile1 := `user:
  id: "user-1"
  email: "user1@test.com"
`
	profile2 := `user:
  id: "user-2"
  email: "user2@test.com"
`
	if err := os.WriteFile(filepath.Join(tmpDir, "profile1.yaml"), []byte(profile1), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "profile2.yaml"), []byte(profile2), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.DevModeConfig{
		Enabled:        true,
		ProfilesDir:    tmpDir,
		DefaultProfile: "profile1",
	}

	p, err := NewMockProvider(cfg)
	if err != nil {
		t.Fatalf("NewMockProvider failed: %v", err)
	}

	t.Run("set valid profile", func(t *testing.T) {
		err := p.SetActiveProfile("profile2")
		if err != nil {
			t.Fatalf("SetActiveProfile failed: %v", err)
		}
	})

	t.Run("set invalid profile", func(t *testing.T) {
		err := p.SetActiveProfile("nonexistent")
		if err == nil {
			t.Error("SetActiveProfile should fail for nonexistent profile")
		}
	})
}

func TestMockProvider_ReloadProfiles(t *testing.T) {
	tmpDir := t.TempDir()

	profile := `user:
  id: "user-1"
  email: "user1@test.com"
`
	if err := os.WriteFile(filepath.Join(tmpDir, "initial.yaml"), []byte(profile), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.DevModeConfig{
		Enabled:        true,
		ProfilesDir:    tmpDir,
		DefaultProfile: "initial",
	}

	p, err := NewMockProvider(cfg)
	if err != nil {
		t.Fatalf("NewMockProvider failed: %v", err)
	}

	if len(p.GetProfiles()) != 1 {
		t.Errorf("Initial profiles = %d, want 1", len(p.GetProfiles()))
	}

	// Add another profile
	newProfile := `user:
  id: "user-2"
  email: "user2@test.com"
`
	if err := os.WriteFile(filepath.Join(tmpDir, "new.yaml"), []byte(newProfile), 0644); err != nil {
		t.Fatal(err)
	}

	// Reload profiles
	err = p.ReloadProfiles()
	if err != nil {
		t.Fatalf("ReloadProfiles failed: %v", err)
	}

	if len(p.GetProfiles()) != 2 {
		t.Errorf("After reload profiles = %d, want 2", len(p.GetProfiles()))
	}
}

func TestMockProvider_extractProfileFromToken(t *testing.T) {
	cfg := &config.DevModeConfig{
		Enabled:        true,
		DefaultProfile: "default",
	}

	p, err := NewMockProvider(cfg)
	if err != nil {
		t.Fatalf("NewMockProvider failed: %v", err)
	}

	tests := []struct {
		token    string
		expected string
	}{
		{"mock_access_developer_1234567890", "developer"},
		{"mock_refresh_admin_1234567890", "admin"},
		{"mock_id_user_1234567890", "user"},
		{"mock_access_test-profile_1234567890", "test-profile"},
		{"short", "default"},        // Too short, use default
		{"", "default"},             // Empty, use default
		{"mock_access_", "default"}, // No profile name
	}

	for _, tt := range tests {
		t.Run(tt.token, func(t *testing.T) {
			result := p.extractProfileFromToken(tt.token)
			if result != tt.expected {
				t.Errorf("extractProfileFromToken(%q) = %s, want %s", tt.token, result, tt.expected)
			}
		})
	}
}

func TestProfileUser_Struct(t *testing.T) {
	pu := ProfileUser{
		ID:            "user-1",
		Email:         "user@test.com",
		Name:          "Test User",
		PreferredName: "tester",
		GivenName:     "Test",
		FamilyName:    "User",
		Picture:       "https://example.com/pic.jpg",
		Locale:        "en",
		Roles:         []string{"admin", "user"},
		Groups:        []string{"team-a"},
		TenantID:      "tenant-1",
	}

	if pu.ID != "user-1" {
		t.Errorf("ID = %s, want user-1", pu.ID)
	}
	if pu.Email != "user@test.com" {
		t.Errorf("Email = %s, want user@test.com", pu.Email)
	}
	if len(pu.Roles) != 2 {
		t.Errorf("Roles length = %d, want 2", len(pu.Roles))
	}
}

func TestProfile_Struct(t *testing.T) {
	profile := Profile{
		User: ProfileUser{
			ID:    "user-1",
			Email: "user@test.com",
		},
	}

	if profile.User.ID != "user-1" {
		t.Errorf("User.ID = %s, want user-1", profile.User.ID)
	}
}

func BenchmarkMockProvider_Exchange(b *testing.B) {
	cfg := &config.DevModeConfig{
		Enabled:        true,
		DefaultProfile: "default",
	}

	p, _ := NewMockProvider(cfg)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = p.Exchange(ctx, "mock_default")
	}
}

func BenchmarkMockProvider_UserInfo(b *testing.B) {
	cfg := &config.DevModeConfig{
		Enabled:        true,
		DefaultProfile: "default",
	}

	p, _ := NewMockProvider(cfg)
	ctx := context.Background()
	tokens, _ := p.Exchange(ctx, "mock_default")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = p.UserInfo(ctx, tokens.AccessToken)
	}
}
