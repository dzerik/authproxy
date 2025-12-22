package crypto

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEncryptor(t *testing.T) {
	t.Run("valid 32-byte key", func(t *testing.T) {
		key := make([]byte, 32)
		enc, err := NewEncryptor(key)
		require.NoError(t, err)
		require.NotNil(t, enc)
	})

	t.Run("key too short", func(t *testing.T) {
		key := make([]byte, 16)
		_, err := NewEncryptor(key)
		assert.Equal(t, ErrInvalidKeySize, err)
	})

	t.Run("key too long", func(t *testing.T) {
		key := make([]byte, 64)
		_, err := NewEncryptor(key)
		assert.Equal(t, ErrInvalidKeySize, err)
	})

	t.Run("empty key", func(t *testing.T) {
		_, err := NewEncryptor([]byte{})
		assert.Equal(t, ErrInvalidKeySize, err)
	})
}

func TestNewEncryptorFromString(t *testing.T) {
	t.Run("32-byte string key", func(t *testing.T) {
		// Use a string that's not valid base64 to ensure it's used directly
		keyStr := "abcdefghijklmnopqrstuvwxyz!@#$%^" // 32 bytes, not valid base64
		enc, err := NewEncryptorFromString(keyStr)
		require.NoError(t, err)
		require.NotNil(t, enc)
	})

	t.Run("base64 encoded key", func(t *testing.T) {
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i)
		}
		keyStr := base64.StdEncoding.EncodeToString(key)

		enc, err := NewEncryptorFromString(keyStr)
		require.NoError(t, err)
		require.NotNil(t, enc)
	})

	t.Run("invalid key size", func(t *testing.T) {
		keyStr := "short"
		_, err := NewEncryptorFromString(keyStr)
		assert.Error(t, err)
	})
}

func TestEncryptor_EncryptDecrypt(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	enc, err := NewEncryptor(key)
	require.NoError(t, err)

	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{"simple text", []byte("Hello, World!")},
		{"empty", []byte("")},
		{"binary data", []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}},
		{"unicode", []byte("Привет, мир! 你好世界 🎉")},
		{"large data", bytes.Repeat([]byte("A"), 10000)},
		{"special chars", []byte("!@#$%^&*()_+-=[]{}|;':\",./<>?")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt
			ciphertext, err := enc.Encrypt(tc.plaintext)
			require.NoError(t, err)

			// Should be base64 encoded
			_, err = base64.URLEncoding.DecodeString(ciphertext)
			require.NoError(t, err, "ciphertext is not valid base64")

			// Decrypt
			decrypted, err := enc.Decrypt(ciphertext)
			require.NoError(t, err)

			// Compare
			assert.True(t, bytes.Equal(decrypted, tc.plaintext), "decrypted != plaintext\ngot: %v\nwant: %v", decrypted, tc.plaintext)
		})
	}
}

func TestEncryptor_EncryptString(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	enc, err := NewEncryptor(key)
	require.NoError(t, err)

	plaintext := "Hello, World!"
	ciphertext, err := enc.EncryptString(plaintext)
	require.NoError(t, err)

	decrypted, err := enc.DecryptString(ciphertext)
	require.NoError(t, err)

	assert.Equal(t, plaintext, decrypted)
}

func TestEncryptor_DecryptErrors(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	enc, err := NewEncryptor(key)
	require.NoError(t, err)

	t.Run("invalid base64", func(t *testing.T) {
		_, err := enc.Decrypt("not-valid-base64!!!")
		assert.Error(t, err)
	})

	t.Run("ciphertext too short", func(t *testing.T) {
		shortData := base64.URLEncoding.EncodeToString([]byte("short"))
		_, err := enc.Decrypt(shortData)
		assert.Equal(t, ErrCiphertextTooShort, err)
	})

	t.Run("wrong key", func(t *testing.T) {
		// Encrypt with one key
		plaintext := []byte("secret data")
		ciphertext, _ := enc.Encrypt(plaintext)

		// Try to decrypt with different key
		otherKey := []byte("98765432109876543210987654321098")
		otherEnc, _ := NewEncryptor(otherKey)

		_, err := otherEnc.Decrypt(ciphertext)
		assert.Equal(t, ErrDecryptionFailed, err)
	})

	t.Run("tampered ciphertext", func(t *testing.T) {
		plaintext := []byte("secret data")
		ciphertext, _ := enc.Encrypt(plaintext)

		// Decode, tamper, re-encode
		decoded, _ := base64.URLEncoding.DecodeString(ciphertext)
		decoded[len(decoded)-1] ^= 0xFF // flip bits in last byte
		tampered := base64.URLEncoding.EncodeToString(decoded)

		_, err := enc.Decrypt(tampered)
		assert.Equal(t, ErrDecryptionFailed, err)
	})
}

func TestEncryptor_UniqueCiphertexts(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	enc, err := NewEncryptor(key)
	require.NoError(t, err)

	plaintext := []byte("same data")
	ciphertexts := make(map[string]bool)

	// Encrypt same data multiple times
	for i := 0; i < 100; i++ {
		ct, err := enc.Encrypt(plaintext)
		require.NoError(t, err)

		assert.False(t, ciphertexts[ct], "got duplicate ciphertext - nonce should be unique")
		ciphertexts[ct] = true
	}
}

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)

	assert.Len(t, key, 32)

	// Generate another and check they're different
	key2, err := GenerateKey()
	require.NoError(t, err)

	assert.False(t, bytes.Equal(key, key2), "generated keys should be unique")
}

func TestGenerateKeyString(t *testing.T) {
	keyStr, err := GenerateKeyString()
	require.NoError(t, err)

	// Should be valid base64
	key, err := base64.StdEncoding.DecodeString(keyStr)
	require.NoError(t, err, "generated key string is not valid base64")

	assert.Len(t, key, 32)

	// Should work with NewEncryptorFromString
	enc, err := NewEncryptorFromString(keyStr)
	require.NoError(t, err, "NewEncryptorFromString failed with generated key")

	// Test encryption/decryption
	plaintext := "test data"
	ciphertext, err := enc.EncryptString(plaintext)
	require.NoError(t, err)

	decrypted, err := enc.DecryptString(ciphertext)
	require.NoError(t, err)

	assert.Equal(t, plaintext, decrypted)
}

func BenchmarkEncrypt(b *testing.B) {
	key := []byte("12345678901234567890123456789012")
	enc, _ := NewEncryptor(key)
	data := []byte("benchmark test data that is somewhat realistic in size for a session")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = enc.Encrypt(data)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key := []byte("12345678901234567890123456789012")
	enc, _ := NewEncryptor(key)
	data := []byte("benchmark test data that is somewhat realistic in size for a session")
	ciphertext, _ := enc.Encrypt(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = enc.Decrypt(ciphertext)
	}
}

func TestErrors(t *testing.T) {
	t.Run("ErrInvalidKeySize", func(t *testing.T) {
		assert.Contains(t, ErrInvalidKeySize.Error(), "32 bytes")
	})

	t.Run("ErrCiphertextTooShort", func(t *testing.T) {
		assert.NotEmpty(t, ErrCiphertextTooShort.Error())
	})

	t.Run("ErrDecryptionFailed", func(t *testing.T) {
		assert.NotEmpty(t, ErrDecryptionFailed.Error())
	})
}
