package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateRandomBytes(t *testing.T) {
	tests := []struct {
		name string
		n    int
	}{
		{"1 byte", 1},
		{"16 bytes", 16},
		{"32 bytes", 32},
		{"64 bytes", 64},
		{"256 bytes", 256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := GenerateRandomBytes(tt.n)
			require.NoError(t, err)

			assert.Len(t, b, tt.n)
		})
	}
}

func TestGenerateRandomBytes_Unique(t *testing.T) {
	seen := make(map[string]bool)

	for i := 0; i < 100; i++ {
		b, err := GenerateRandomBytes(32)
		require.NoError(t, err)

		key := string(b)
		assert.False(t, seen[key], "got duplicate random bytes")
		seen[key] = true
	}
}

func TestGenerateRandomString(t *testing.T) {
	tests := []struct {
		name        string
		n           int
		expectedLen int // base64 encoded length
	}{
		{"16 bytes", 16, 22}, // 16 * 4/3 = 21.3, rounded up with padding removed
		{"32 bytes", 32, 43}, // 32 * 4/3 = 42.7
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := GenerateRandomString(tt.n)
			require.NoError(t, err)

			// Verify it's valid base64 URL encoding
			decoded, err := base64.URLEncoding.DecodeString(s)
			require.NoError(t, err, "not valid base64 URL encoded")

			assert.Len(t, decoded, tt.n)
		})
	}
}

func TestGenerateRandomString_Unique(t *testing.T) {
	seen := make(map[string]bool)

	for i := 0; i < 100; i++ {
		s, err := GenerateRandomString(16)
		require.NoError(t, err)

		assert.False(t, seen[s], "got duplicate random string")
		seen[s] = true
	}
}

func TestGenerateRandomHex(t *testing.T) {
	tests := []struct {
		name        string
		n           int
		expectedLen int // hex encoded length = n * 2
	}{
		{"8 bytes", 8, 16},
		{"16 bytes", 16, 32},
		{"32 bytes", 32, 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := GenerateRandomHex(tt.n)
			require.NoError(t, err)

			assert.Len(t, s, tt.expectedLen)

			// Verify it's valid hex
			decoded, err := hex.DecodeString(s)
			require.NoError(t, err, "not valid hex")

			assert.Len(t, decoded, tt.n)
		})
	}
}

func TestGenerateRandomHex_Unique(t *testing.T) {
	seen := make(map[string]bool)

	for i := 0; i < 100; i++ {
		s, err := GenerateRandomHex(16)
		require.NoError(t, err)

		assert.False(t, seen[s], "got duplicate random hex")
		seen[s] = true
	}
}

func TestGenerateSessionID(t *testing.T) {
	id, err := GenerateSessionID()
	require.NoError(t, err)

	// Should be base64 URL encoded 32 bytes
	decoded, err := base64.URLEncoding.DecodeString(id)
	require.NoError(t, err, "session ID is not valid base64 URL encoded")

	assert.Len(t, decoded, 32)
}

func TestGenerateSessionID_Unique(t *testing.T) {
	seen := make(map[string]bool)

	for i := 0; i < 100; i++ {
		id, err := GenerateSessionID()
		require.NoError(t, err)

		assert.False(t, seen[id], "got duplicate session ID")
		seen[id] = true
	}
}

func TestGenerateStateToken(t *testing.T) {
	token, err := GenerateStateToken()
	require.NoError(t, err)

	// Should be base64 URL encoded 16 bytes
	decoded, err := base64.URLEncoding.DecodeString(token)
	require.NoError(t, err, "state token is not valid base64 URL encoded")

	assert.Len(t, decoded, 16)
}

func TestGenerateNonce(t *testing.T) {
	nonce, err := GenerateNonce()
	require.NoError(t, err)

	// Should be base64 URL encoded 16 bytes
	decoded, err := base64.URLEncoding.DecodeString(nonce)
	require.NoError(t, err, "nonce is not valid base64 URL encoded")

	assert.Len(t, decoded, 16)
}

func TestMustGenerateSessionID(t *testing.T) {
	// Should not panic
	id := MustGenerateSessionID()
	assert.NotEmpty(t, id)

	// Verify it's valid
	decoded, err := base64.URLEncoding.DecodeString(id)
	require.NoError(t, err, "session ID is not valid base64 URL encoded")

	assert.Len(t, decoded, 32)
}

func TestMustGenerateStateToken(t *testing.T) {
	// Should not panic
	token := MustGenerateStateToken()
	assert.NotEmpty(t, token)

	// Verify it's valid
	decoded, err := base64.URLEncoding.DecodeString(token)
	require.NoError(t, err, "state token is not valid base64 URL encoded")

	assert.Len(t, decoded, 16)
}

func BenchmarkGenerateRandomBytes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateRandomBytes(32)
	}
}

func BenchmarkGenerateSessionID(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateSessionID()
	}
}

func BenchmarkGenerateStateToken(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateStateToken()
	}
}
