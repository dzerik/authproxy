package model

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSession(t *testing.T) {
	user := &User{
		ID:    "user-123",
		Email: "test@example.com",
	}

	session := NewSession("session-456", user)

	require.NotNil(t, session, "NewSession returned nil")
	assert.Equal(t, "session-456", session.ID)
	assert.Equal(t, user, session.User)
	assert.False(t, session.CreatedAt.IsZero(), "CreatedAt should be set")
	assert.False(t, session.LastAccessAt.IsZero(), "LastAccessAt should be set")
	assert.Equal(t, session.CreatedAt, session.LastAccessAt, "CreatedAt and LastAccessAt should be equal on creation")
}

func TestSession_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{"expired 1 hour ago", time.Now().Add(-time.Hour), true},
		{"expires in 1 hour", time.Now().Add(time.Hour), false},
		{"just expired", time.Now().Add(-time.Second), true},
		{"expires soon", time.Now().Add(time.Second), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{ExpiresAt: tt.expiresAt}
			assert.Equal(t, tt.expected, session.IsExpired())
		})
	}
}

func TestSession_IsAccessTokenExpired(t *testing.T) {
	session := &Session{ExpiresAt: time.Now().Add(-time.Hour)}
	assert.True(t, session.IsAccessTokenExpired(), "should return true for expired session")

	session.ExpiresAt = time.Now().Add(time.Hour)
	assert.False(t, session.IsAccessTokenExpired(), "should return false for valid session")
}

func TestSession_NeedsRefresh(t *testing.T) {
	threshold := 5 * time.Minute

	tests := []struct {
		name         string
		refreshToken string
		expiresAt    time.Time
		expected     bool
	}{
		{
			name:         "no refresh token",
			refreshToken: "",
			expiresAt:    time.Now().Add(time.Minute),
			expected:     false,
		},
		{
			name:         "expires soon, has refresh token",
			refreshToken: "refresh-token",
			expiresAt:    time.Now().Add(3 * time.Minute),
			expected:     true,
		},
		{
			name:         "not expiring soon",
			refreshToken: "refresh-token",
			expiresAt:    time.Now().Add(10 * time.Minute),
			expected:     false,
		},
		{
			name:         "already expired",
			refreshToken: "refresh-token",
			expiresAt:    time.Now().Add(-time.Minute),
			expected:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{
				RefreshToken: tt.refreshToken,
				ExpiresAt:    tt.expiresAt,
			}
			assert.Equal(t, tt.expected, session.NeedsRefresh(threshold))
		})
	}
}

func TestSession_Touch(t *testing.T) {
	session := &Session{
		LastAccessAt: time.Now().Add(-time.Hour),
	}

	oldLastAccess := session.LastAccessAt
	session.Touch()

	assert.True(t, session.LastAccessAt.After(oldLastAccess), "Touch should update LastAccessAt to a later time")
	assert.WithinDuration(t, time.Now(), session.LastAccessAt, time.Second, "Touch should set LastAccessAt to approximately now")
}

func TestSession_RemainingTTL(t *testing.T) {
	session := &Session{ExpiresAt: time.Now().Add(10 * time.Minute)}

	ttl := session.RemainingTTL()
	assert.GreaterOrEqual(t, ttl, 9*time.Minute)
	assert.LessOrEqual(t, ttl, 10*time.Minute)

	// Test expired session
	session.ExpiresAt = time.Now().Add(-5 * time.Minute)
	ttl = session.RemainingTTL()
	assert.Less(t, ttl, time.Duration(0), "RemainingTTL for expired session should be negative")
}

func TestSession_SetTokens(t *testing.T) {
	session := &Session{}

	session.SetTokens("access-token", "refresh-token", "id-token", time.Hour)

	assert.Equal(t, "access-token", session.AccessToken)
	assert.Equal(t, "refresh-token", session.RefreshToken)
	assert.Equal(t, "id-token", session.IDToken)
	assert.WithinDuration(t, time.Now().Add(time.Hour), session.ExpiresAt, time.Second)
}

func TestSession_ToSessionData(t *testing.T) {
	now := time.Now()
	session := &Session{
		ID: "session-123",
		User: &User{
			ID:       "user-456",
			Email:    "test@example.com",
			Name:     "Test User",
			Roles:    []string{"admin"},
			Groups:   []string{"engineering"},
			TenantID: "tenant-1",
		},
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		IDToken:      "id-token",
		ExpiresAt:    now.Add(time.Hour),
		CreatedAt:    now,
	}

	data := session.ToSessionData()

	require.NotNil(t, data)
	assert.Equal(t, "session-123", data.ID)
	assert.Equal(t, "user-456", data.UserID)
	assert.Equal(t, "test@example.com", data.Email)
	assert.Equal(t, "Test User", data.Name)
	assert.Equal(t, []string{"admin"}, data.Roles)
	assert.Equal(t, []string{"engineering"}, data.Groups)
	assert.Equal(t, "tenant-1", data.TenantID)
	assert.Equal(t, "access-token", data.AccessToken)
	assert.Equal(t, "refresh-token", data.RefreshToken)
	assert.Equal(t, "id-token", data.IDToken)
}

func TestSession_ToSessionData_NilUser(t *testing.T) {
	session := &Session{
		ID:   "session-123",
		User: nil,
	}

	data := session.ToSessionData()
	assert.Nil(t, data, "ToSessionData should return nil when User is nil")
}

func TestSessionData_ToSession(t *testing.T) {
	now := time.Now()
	data := &SessionData{
		ID:           "session-123",
		UserID:       "user-456",
		Email:        "test@example.com",
		Name:         "Test User",
		Roles:        []string{"admin", "user"},
		Groups:       []string{"engineering"},
		TenantID:     "tenant-1",
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		IDToken:      "id-token",
		ExpiresAt:    now.Add(time.Hour).Unix(),
		CreatedAt:    now.Unix(),
	}

	session := data.ToSession()

	require.NotNil(t, session)
	assert.Equal(t, "session-123", session.ID)
	require.NotNil(t, session.User)
	assert.Equal(t, "user-456", session.User.ID)
	assert.Equal(t, "test@example.com", session.User.Email)
	assert.Equal(t, "Test User", session.User.Name)
	assert.Len(t, session.User.Roles, 2)
	assert.Len(t, session.User.Groups, 1)
	assert.Equal(t, "tenant-1", session.User.TenantID)
	assert.Equal(t, "access-token", session.AccessToken)
	assert.Equal(t, "refresh-token", session.RefreshToken)
	assert.Equal(t, "id-token", session.IDToken)
	assert.False(t, session.LastAccessAt.IsZero(), "LastAccessAt should be set")
}

func TestSession_Struct(t *testing.T) {
	now := time.Now()
	session := &Session{
		ID:           "session-123",
		User:         &User{ID: "user-1"},
		AccessToken:  "at",
		RefreshToken: "rt",
		IDToken:      "it",
		TokenType:    "Bearer",
		ExpiresAt:    now.Add(time.Hour),
		CreatedAt:    now,
		LastAccessAt: now,
		ReturnTo:     "https://app.example.com",
	}

	assert.Equal(t, "Bearer", session.TokenType)
	assert.Equal(t, "https://app.example.com", session.ReturnTo)
}

func TestSessionData_Struct(t *testing.T) {
	data := &SessionData{
		ID:           "session-123",
		UserID:       "user-1",
		Email:        "test@example.com",
		Name:         "Test",
		Roles:        []string{"admin"},
		Groups:       []string{"eng"},
		TenantID:     "t1",
		AccessToken:  "at",
		RefreshToken: "rt",
		IDToken:      "it",
		ExpiresAt:    1234567890,
		CreatedAt:    1234567800,
	}

	assert.Equal(t, int64(1234567890), data.ExpiresAt)
	assert.Equal(t, int64(1234567800), data.CreatedAt)
}
