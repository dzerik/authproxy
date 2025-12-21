package model

import (
	"testing"
	"time"
)

func TestNewSession(t *testing.T) {
	user := &User{
		ID:    "user-123",
		Email: "test@example.com",
	}

	session := NewSession("session-456", user)

	if session == nil {
		t.Fatal("NewSession returned nil")
	}
	if session.ID != "session-456" {
		t.Errorf("ID = %s, want session-456", session.ID)
	}
	if session.User != user {
		t.Error("User not set correctly")
	}
	if session.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
	if session.LastAccessAt.IsZero() {
		t.Error("LastAccessAt should be set")
	}
	if session.CreatedAt != session.LastAccessAt {
		t.Error("CreatedAt and LastAccessAt should be equal on creation")
	}
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
			result := session.IsExpired()
			if result != tt.expected {
				t.Errorf("IsExpired() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestSession_IsAccessTokenExpired(t *testing.T) {
	session := &Session{ExpiresAt: time.Now().Add(-time.Hour)}
	if !session.IsAccessTokenExpired() {
		t.Error("IsAccessTokenExpired should return true for expired session")
	}

	session.ExpiresAt = time.Now().Add(time.Hour)
	if session.IsAccessTokenExpired() {
		t.Error("IsAccessTokenExpired should return false for valid session")
	}
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
			result := session.NeedsRefresh(threshold)
			if result != tt.expected {
				t.Errorf("NeedsRefresh(%v) = %v, want %v", threshold, result, tt.expected)
			}
		})
	}
}

func TestSession_Touch(t *testing.T) {
	session := &Session{
		LastAccessAt: time.Now().Add(-time.Hour),
	}

	oldLastAccess := session.LastAccessAt
	session.Touch()

	if session.LastAccessAt.Before(oldLastAccess) {
		t.Error("Touch should update LastAccessAt to a later time")
	}
	if time.Since(session.LastAccessAt) > time.Second {
		t.Error("Touch should set LastAccessAt to approximately now")
	}
}

func TestSession_RemainingTTL(t *testing.T) {
	session := &Session{ExpiresAt: time.Now().Add(10 * time.Minute)}

	ttl := session.RemainingTTL()
	if ttl < 9*time.Minute || ttl > 10*time.Minute {
		t.Errorf("RemainingTTL() = %v, want approximately 10 minutes", ttl)
	}

	// Test expired session
	session.ExpiresAt = time.Now().Add(-5 * time.Minute)
	ttl = session.RemainingTTL()
	if ttl > 0 {
		t.Errorf("RemainingTTL() for expired session = %v, want negative", ttl)
	}
}

func TestSession_SetTokens(t *testing.T) {
	session := &Session{}

	session.SetTokens("access-token", "refresh-token", "id-token", time.Hour)

	if session.AccessToken != "access-token" {
		t.Errorf("AccessToken = %s, want access-token", session.AccessToken)
	}
	if session.RefreshToken != "refresh-token" {
		t.Errorf("RefreshToken = %s, want refresh-token", session.RefreshToken)
	}
	if session.IDToken != "id-token" {
		t.Errorf("IDToken = %s, want id-token", session.IDToken)
	}

	expectedExpiry := time.Now().Add(time.Hour)
	if session.ExpiresAt.Sub(expectedExpiry) > time.Second {
		t.Errorf("ExpiresAt = %v, want approximately %v", session.ExpiresAt, expectedExpiry)
	}
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

	if data == nil {
		t.Fatal("ToSessionData returned nil")
	}
	if data.ID != "session-123" {
		t.Errorf("ID = %s, want session-123", data.ID)
	}
	if data.UserID != "user-456" {
		t.Errorf("UserID = %s, want user-456", data.UserID)
	}
	if data.Email != "test@example.com" {
		t.Errorf("Email = %s, want test@example.com", data.Email)
	}
	if data.Name != "Test User" {
		t.Errorf("Name = %s, want Test User", data.Name)
	}
	if len(data.Roles) != 1 || data.Roles[0] != "admin" {
		t.Errorf("Roles = %v, want [admin]", data.Roles)
	}
	if len(data.Groups) != 1 || data.Groups[0] != "engineering" {
		t.Errorf("Groups = %v, want [engineering]", data.Groups)
	}
	if data.TenantID != "tenant-1" {
		t.Errorf("TenantID = %s, want tenant-1", data.TenantID)
	}
	if data.AccessToken != "access-token" {
		t.Errorf("AccessToken = %s, want access-token", data.AccessToken)
	}
	if data.RefreshToken != "refresh-token" {
		t.Errorf("RefreshToken = %s, want refresh-token", data.RefreshToken)
	}
	if data.IDToken != "id-token" {
		t.Errorf("IDToken = %s, want id-token", data.IDToken)
	}
}

func TestSession_ToSessionData_NilUser(t *testing.T) {
	session := &Session{
		ID:   "session-123",
		User: nil,
	}

	data := session.ToSessionData()
	if data != nil {
		t.Error("ToSessionData should return nil when User is nil")
	}
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

	if session == nil {
		t.Fatal("ToSession returned nil")
	}
	if session.ID != "session-123" {
		t.Errorf("ID = %s, want session-123", session.ID)
	}
	if session.User == nil {
		t.Fatal("User should not be nil")
	}
	if session.User.ID != "user-456" {
		t.Errorf("User.ID = %s, want user-456", session.User.ID)
	}
	if session.User.Email != "test@example.com" {
		t.Errorf("User.Email = %s, want test@example.com", session.User.Email)
	}
	if session.User.Name != "Test User" {
		t.Errorf("User.Name = %s, want Test User", session.User.Name)
	}
	if len(session.User.Roles) != 2 {
		t.Errorf("User.Roles = %v, want 2 roles", session.User.Roles)
	}
	if len(session.User.Groups) != 1 {
		t.Errorf("User.Groups = %v, want 1 group", session.User.Groups)
	}
	if session.User.TenantID != "tenant-1" {
		t.Errorf("User.TenantID = %s, want tenant-1", session.User.TenantID)
	}
	if session.AccessToken != "access-token" {
		t.Errorf("AccessToken = %s, want access-token", session.AccessToken)
	}
	if session.RefreshToken != "refresh-token" {
		t.Errorf("RefreshToken = %s, want refresh-token", session.RefreshToken)
	}
	if session.IDToken != "id-token" {
		t.Errorf("IDToken = %s, want id-token", session.IDToken)
	}
	if session.LastAccessAt.IsZero() {
		t.Error("LastAccessAt should be set")
	}
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

	if session.TokenType != "Bearer" {
		t.Errorf("TokenType = %s, want Bearer", session.TokenType)
	}
	if session.ReturnTo != "https://app.example.com" {
		t.Errorf("ReturnTo = %s, want https://app.example.com", session.ReturnTo)
	}
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

	if data.ExpiresAt != 1234567890 {
		t.Errorf("ExpiresAt = %d, want 1234567890", data.ExpiresAt)
	}
	if data.CreatedAt != 1234567800 {
		t.Errorf("CreatedAt = %d, want 1234567800", data.CreatedAt)
	}
}
