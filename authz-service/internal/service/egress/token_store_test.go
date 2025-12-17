package egress

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestMemoryTokenStore_SetAndGet(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := NewMemoryTokenStore(logger)
	ctx := context.Background()

	// Store credentials
	creds := &Credentials{
		Type:        CredentialTypeOAuth2,
		AccessToken: "test-token",
		ExpiresAt:   time.Now().Add(time.Hour),
		Headers: map[string]string{
			"Authorization": "Bearer test-token",
		},
	}

	err := store.Set(ctx, "target1", creds)
	require.NoError(t, err)

	// Retrieve credentials
	retrieved, err := store.Get(ctx, "target1")
	require.NoError(t, err)
	require.NotNil(t, retrieved)

	assert.Equal(t, creds.Type, retrieved.Type)
	assert.Equal(t, creds.AccessToken, retrieved.AccessToken)
	assert.Equal(t, creds.Headers["Authorization"], retrieved.Headers["Authorization"])
}

func TestMemoryTokenStore_GetNonexistent(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := NewMemoryTokenStore(logger)
	ctx := context.Background()

	// Try to get nonexistent credentials
	creds, err := store.Get(ctx, "nonexistent")
	require.NoError(t, err)
	assert.Nil(t, creds)
}

func TestMemoryTokenStore_GetExpired(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := NewMemoryTokenStore(logger)
	ctx := context.Background()

	// Store expired credentials
	creds := &Credentials{
		Type:        CredentialTypeOAuth2,
		AccessToken: "expired-token",
		ExpiresAt:   time.Now().Add(-time.Hour), // Already expired
	}

	err := store.Set(ctx, "target1", creds)
	require.NoError(t, err)

	// Should return nil for expired credentials
	retrieved, err := store.Get(ctx, "target1")
	require.NoError(t, err)
	assert.Nil(t, retrieved)
}

func TestMemoryTokenStore_Delete(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := NewMemoryTokenStore(logger)
	ctx := context.Background()

	// Store credentials
	creds := &Credentials{
		Type:        CredentialTypeAPIKey,
		AccessToken: "api-key",
	}

	err := store.Set(ctx, "target1", creds)
	require.NoError(t, err)

	// Verify it exists
	retrieved, err := store.Get(ctx, "target1")
	require.NoError(t, err)
	require.NotNil(t, retrieved)

	// Delete it
	err = store.Delete(ctx, "target1")
	require.NoError(t, err)

	// Verify it's gone
	retrieved, err = store.Get(ctx, "target1")
	require.NoError(t, err)
	assert.Nil(t, retrieved)
}

func TestMemoryTokenStore_Health(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := NewMemoryTokenStore(logger)
	ctx := context.Background()

	// Health should always be nil for memory store
	err := store.Health(ctx)
	assert.NoError(t, err)
}

func TestMemoryTokenStore_Close(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := NewMemoryTokenStore(logger)

	// Close should be a no-op
	err := store.Close()
	assert.NoError(t, err)
}

func TestMemoryTokenStore_Overwrite(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := NewMemoryTokenStore(logger)
	ctx := context.Background()

	// Store initial credentials
	creds1 := &Credentials{
		Type:        CredentialTypeOAuth2,
		AccessToken: "token1",
		ExpiresAt:   time.Now().Add(time.Hour),
	}

	err := store.Set(ctx, "target1", creds1)
	require.NoError(t, err)

	// Overwrite with new credentials
	creds2 := &Credentials{
		Type:        CredentialTypeOAuth2,
		AccessToken: "token2",
		ExpiresAt:   time.Now().Add(2 * time.Hour),
	}

	err = store.Set(ctx, "target1", creds2)
	require.NoError(t, err)

	// Retrieve should return new credentials
	retrieved, err := store.Get(ctx, "target1")
	require.NoError(t, err)
	require.NotNil(t, retrieved)

	assert.Equal(t, "token2", retrieved.AccessToken)
}

func TestMemoryTokenStore_MultipleTargets(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := NewMemoryTokenStore(logger)
	ctx := context.Background()

	// Store credentials for multiple targets
	targets := []struct {
		name  string
		token string
	}{
		{"target1", "token1"},
		{"target2", "token2"},
		{"target3", "token3"},
	}

	for _, target := range targets {
		creds := &Credentials{
			Type:        CredentialTypeBearer,
			AccessToken: target.token,
			ExpiresAt:   time.Now().Add(time.Hour),
		}
		err := store.Set(ctx, target.name, creds)
		require.NoError(t, err)
	}

	// Verify each target has correct credentials
	for _, target := range targets {
		retrieved, err := store.Get(ctx, target.name)
		require.NoError(t, err)
		require.NotNil(t, retrieved)
		assert.Equal(t, target.token, retrieved.AccessToken)
	}
}

func TestMemoryTokenStore_ConcurrentAccess(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := NewMemoryTokenStore(logger)
	ctx := context.Background()

	// Run concurrent operations
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func(i int) {
			creds := &Credentials{
				Type:        CredentialTypeOAuth2,
				AccessToken: "concurrent-token",
				ExpiresAt:   time.Now().Add(time.Hour),
			}

			// Write
			err := store.Set(ctx, "concurrent-target", creds)
			assert.NoError(t, err)

			// Read
			_, err = store.Get(ctx, "concurrent-target")
			assert.NoError(t, err)

			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}
