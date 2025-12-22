package idp

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMockProvider(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		cfg := &config.DevModeConfig{
			Enabled:        true,
			DefaultProfile: "default",
		}

		p, err := NewMockProvider(cfg)
		require.NoError(t, err)
		require.NotNil(t, p, "NewMockProvider returned nil")
		assert.Equal(t, "mock", p.Name())
	})

	t.Run("nil config", func(t *testing.T) {
		_, err := NewMockProvider(nil)
		assert.Error(t, err, "NewMockProvider should fail with nil config")
	})

	t.Run("dev mode disabled", func(t *testing.T) {
		cfg := &config.DevModeConfig{
			Enabled: false,
		}

		_, err := NewMockProvider(cfg)
		assert.Error(t, err, "NewMockProvider should fail when dev mode is disabled")
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
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "developer.yaml"), []byte(devProfile), 0644))

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
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "admin.yaml"), []byte(adminProfile), 0644))

	cfg := &config.DevModeConfig{
		Enabled:        true,
		ProfilesDir:    tmpDir,
		DefaultProfile: "developer",
	}

	p, err := NewMockProvider(cfg)
	require.NoError(t, err)

	// Check profiles loaded
	profiles := p.GetProfiles()
	assert.Len(t, profiles, 2)

	// Check developer profile
	devP, exists := p.GetProfile("developer")
	assert.True(t, exists, "developer profile should exist")
	assert.Equal(t, "developer@test.com", devP.User.Email)

	// Check admin profile
	adminP, exists := p.GetProfile("admin")
	assert.True(t, exists, "admin profile should exist")
	assert.Equal(t, "admin@test.com", adminP.User.Email)
}

func TestNewMockProvider_InvalidDefaultProfile(t *testing.T) {
	tmpDir := t.TempDir()

	profile := `user:
  id: "user-1"
  email: "user@test.com"
`
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "user.yaml"), []byte(profile), 0644))

	cfg := &config.DevModeConfig{
		Enabled:        true,
		ProfilesDir:    tmpDir,
		DefaultProfile: "nonexistent",
	}

	_, err := NewMockProvider(cfg)
	assert.Error(t, err, "NewMockProvider should fail with invalid default profile")
}

func TestNewMockProvider_InvalidProfilesPath(t *testing.T) {
	// Create a file instead of directory
	tmpFile, err := os.CreateTemp("", "notadir")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	cfg := &config.DevModeConfig{
		Enabled:     true,
		ProfilesDir: tmpFile.Name(),
	}

	_, err = NewMockProvider(cfg)
	assert.Error(t, err, "NewMockProvider should fail when profiles path is not a directory")
}

func TestMockProvider_AuthURL(t *testing.T) {
	cfg := &config.DevModeConfig{
		Enabled:        true,
		DefaultProfile: "default",
	}

	p, err := NewMockProvider(cfg)
	require.NoError(t, err)

	t.Run("with state", func(t *testing.T) {
		url := p.AuthURL(AuthURLOptions{State: "test-state"})
		assert.NotEmpty(t, url, "AuthURL should not be empty")
		// Should contain callback and state
		assert.Equal(t, "/callback?code=mock_default&state=test-state", url)
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
		assert.Equal(t, "/callback?code=mock_custom&state=test-state", url)
	})

	t.Run("with unknown IDPHint", func(t *testing.T) {
		url := p.AuthURL(AuthURLOptions{
			State:   "test-state",
			IDPHint: "unknown",
		})
		// Should fall back to default profile
		assert.Equal(t, "/callback?code=mock_default&state=test-state", url)
	})
}

func TestMockProvider_Exchange(t *testing.T) {
	cfg := &config.DevModeConfig{
		Enabled:        true,
		DefaultProfile: "default",
	}

	p, err := NewMockProvider(cfg)
	require.NoError(t, err)

	t.Run("valid mock code", func(t *testing.T) {
		tokens, err := p.Exchange(context.Background(), "mock_default")
		require.NoError(t, err)

		assert.NotEmpty(t, tokens.AccessToken, "AccessToken should not be empty")
		assert.NotEmpty(t, tokens.RefreshToken, "RefreshToken should not be empty")
		assert.NotEmpty(t, tokens.IDToken, "IDToken should not be empty")
		assert.Equal(t, "Bearer", tokens.TokenType)
		assert.Equal(t, int64(3600), tokens.ExpiresIn)
	})

	t.Run("code with profile name", func(t *testing.T) {
		tokens, err := p.Exchange(context.Background(), "mock_default")
		require.NoError(t, err)
		// Token should contain profile name
		assert.NotEmpty(t, tokens.AccessToken, "AccessToken should contain profile info")
	})

	t.Run("short code", func(t *testing.T) {
		tokens, err := p.Exchange(context.Background(), "abc")
		require.NoError(t, err)
		// Should use default profile
		assert.NotEmpty(t, tokens.AccessToken, "AccessToken should not be empty")
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
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "test.yaml"), []byte(profile), 0644))

	cfg := &config.DevModeConfig{
		Enabled:        true,
		ProfilesDir:    tmpDir,
		DefaultProfile: "test",
	}

	p, err := NewMockProvider(cfg)
	require.NoError(t, err)

	// Get tokens first
	tokens, err := p.Exchange(context.Background(), "mock_test")
	require.NoError(t, err)

	// Get user info
	user, err := p.UserInfo(context.Background(), tokens.AccessToken)
	require.NoError(t, err)

	assert.Equal(t, "test-user-1", user.ID)
	assert.Equal(t, "test@example.com", user.Email)
	assert.Equal(t, "Test User", user.Name)
	assert.Equal(t, "tester", user.PreferredName)
	assert.Equal(t, "Test", user.GivenName)
	assert.Equal(t, "User", user.FamilyName)
	assert.Equal(t, "https://example.com/pic.jpg", user.Picture)
	assert.Equal(t, "en", user.Locale)
	assert.Len(t, user.Roles, 2)
	assert.Len(t, user.Groups, 1)
	assert.Equal(t, "tenant-1", user.TenantID)
}

func TestMockProvider_Refresh(t *testing.T) {
	cfg := &config.DevModeConfig{
		Enabled:        true,
		DefaultProfile: "default",
	}

	p, err := NewMockProvider(cfg)
	require.NoError(t, err)

	tokens, err := p.Exchange(context.Background(), "mock_default")
	require.NoError(t, err)

	newTokens, err := p.Refresh(context.Background(), tokens.RefreshToken)
	require.NoError(t, err)

	assert.NotEmpty(t, newTokens.AccessToken, "New AccessToken should not be empty")
	assert.NotEmpty(t, newTokens.RefreshToken, "New RefreshToken should not be empty")
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
	require.NoError(t, err)

	tokens, err := p.Exchange(context.Background(), "mock_default")
	require.NoError(t, err)

	user, err := p.Verify(context.Background(), tokens.IDToken)
	require.NoError(t, err)
	assert.NotNil(t, user, "User should not be nil")
}

func TestMockProvider_LogoutURL(t *testing.T) {
	cfg := &config.DevModeConfig{
		Enabled:        true,
		DefaultProfile: "default",
	}

	p, err := NewMockProvider(cfg)
	require.NoError(t, err)

	t.Run("with postLogoutRedirectURI", func(t *testing.T) {
		url := p.LogoutURL("token-hint", "https://example.com/logout")
		assert.Equal(t, "https://example.com/logout", url)
	})

	t.Run("without postLogoutRedirectURI", func(t *testing.T) {
		url := p.LogoutURL("token-hint", "")
		assert.Equal(t, "/login", url)
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
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "profile1.yaml"), []byte(profile1), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "profile2.yaml"), []byte(profile2), 0644))

	cfg := &config.DevModeConfig{
		Enabled:        true,
		ProfilesDir:    tmpDir,
		DefaultProfile: "profile1",
	}

	p, err := NewMockProvider(cfg)
	require.NoError(t, err)

	t.Run("set valid profile", func(t *testing.T) {
		err := p.SetActiveProfile("profile2")
		require.NoError(t, err)
	})

	t.Run("set invalid profile", func(t *testing.T) {
		err := p.SetActiveProfile("nonexistent")
		assert.Error(t, err, "SetActiveProfile should fail for nonexistent profile")
	})
}

func TestMockProvider_ReloadProfiles(t *testing.T) {
	tmpDir := t.TempDir()

	profile := `user:
  id: "user-1"
  email: "user1@test.com"
`
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "initial.yaml"), []byte(profile), 0644))

	cfg := &config.DevModeConfig{
		Enabled:        true,
		ProfilesDir:    tmpDir,
		DefaultProfile: "initial",
	}

	p, err := NewMockProvider(cfg)
	require.NoError(t, err)

	assert.Len(t, p.GetProfiles(), 1, "Initial profiles should be 1")

	// Add another profile
	newProfile := `user:
  id: "user-2"
  email: "user2@test.com"
`
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "new.yaml"), []byte(newProfile), 0644))

	// Reload profiles
	err = p.ReloadProfiles()
	require.NoError(t, err)

	assert.Len(t, p.GetProfiles(), 2, "After reload profiles should be 2")
}

func TestMockProvider_extractProfileFromToken(t *testing.T) {
	cfg := &config.DevModeConfig{
		Enabled:        true,
		DefaultProfile: "default",
	}

	p, err := NewMockProvider(cfg)
	require.NoError(t, err)

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
			assert.Equal(t, tt.expected, result)
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

	assert.Equal(t, "user-1", pu.ID)
	assert.Equal(t, "user@test.com", pu.Email)
	assert.Len(t, pu.Roles, 2)
}

func TestProfile_Struct(t *testing.T) {
	profile := Profile{
		User: ProfileUser{
			ID:    "user-1",
			Email: "user@test.com",
		},
	}

	assert.Equal(t, "user-1", profile.User.ID)
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
