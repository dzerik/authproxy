package crypto

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestNewEncryptor(t *testing.T) {
	t.Run("valid 32-byte key", func(t *testing.T) {
		key := make([]byte, 32)
		enc, err := NewEncryptor(key)
		if err != nil {
			t.Errorf("NewEncryptor failed: %v", err)
		}
		if enc == nil {
			t.Error("NewEncryptor returned nil")
		}
	})

	t.Run("key too short", func(t *testing.T) {
		key := make([]byte, 16)
		_, err := NewEncryptor(key)
		if err != ErrInvalidKeySize {
			t.Errorf("expected ErrInvalidKeySize, got %v", err)
		}
	})

	t.Run("key too long", func(t *testing.T) {
		key := make([]byte, 64)
		_, err := NewEncryptor(key)
		if err != ErrInvalidKeySize {
			t.Errorf("expected ErrInvalidKeySize, got %v", err)
		}
	})

	t.Run("empty key", func(t *testing.T) {
		_, err := NewEncryptor([]byte{})
		if err != ErrInvalidKeySize {
			t.Errorf("expected ErrInvalidKeySize, got %v", err)
		}
	})
}

func TestNewEncryptorFromString(t *testing.T) {
	t.Run("32-byte string key", func(t *testing.T) {
		// Use a string that's not valid base64 to ensure it's used directly
		keyStr := "abcdefghijklmnopqrstuvwxyz!@#$%^" // 32 bytes, not valid base64
		enc, err := NewEncryptorFromString(keyStr)
		if err != nil {
			t.Errorf("NewEncryptorFromString failed: %v", err)
		}
		if enc == nil {
			t.Error("NewEncryptorFromString returned nil")
		}
	})

	t.Run("base64 encoded key", func(t *testing.T) {
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i)
		}
		keyStr := base64.StdEncoding.EncodeToString(key)

		enc, err := NewEncryptorFromString(keyStr)
		if err != nil {
			t.Errorf("NewEncryptorFromString failed: %v", err)
		}
		if enc == nil {
			t.Error("NewEncryptorFromString returned nil")
		}
	})

	t.Run("invalid key size", func(t *testing.T) {
		keyStr := "short"
		_, err := NewEncryptorFromString(keyStr)
		if err == nil {
			t.Error("expected error for invalid key size")
		}
	})
}

func TestEncryptor_EncryptDecrypt(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor failed: %v", err)
	}

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
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			// Should be base64 encoded
			if _, err := base64.URLEncoding.DecodeString(ciphertext); err != nil {
				t.Errorf("ciphertext is not valid base64: %v", err)
			}

			// Decrypt
			decrypted, err := enc.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			// Compare
			if !bytes.Equal(decrypted, tc.plaintext) {
				t.Errorf("decrypted != plaintext\ngot: %v\nwant: %v", decrypted, tc.plaintext)
			}
		})
	}
}

func TestEncryptor_EncryptString(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor failed: %v", err)
	}

	plaintext := "Hello, World!"
	ciphertext, err := enc.EncryptString(plaintext)
	if err != nil {
		t.Fatalf("EncryptString failed: %v", err)
	}

	decrypted, err := enc.DecryptString(ciphertext)
	if err != nil {
		t.Fatalf("DecryptString failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("decrypted = %s, want %s", decrypted, plaintext)
	}
}

func TestEncryptor_DecryptErrors(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor failed: %v", err)
	}

	t.Run("invalid base64", func(t *testing.T) {
		_, err := enc.Decrypt("not-valid-base64!!!")
		if err == nil {
			t.Error("expected error for invalid base64")
		}
	})

	t.Run("ciphertext too short", func(t *testing.T) {
		shortData := base64.URLEncoding.EncodeToString([]byte("short"))
		_, err := enc.Decrypt(shortData)
		if err != ErrCiphertextTooShort {
			t.Errorf("expected ErrCiphertextTooShort, got %v", err)
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		// Encrypt with one key
		plaintext := []byte("secret data")
		ciphertext, _ := enc.Encrypt(plaintext)

		// Try to decrypt with different key
		otherKey := []byte("98765432109876543210987654321098")
		otherEnc, _ := NewEncryptor(otherKey)

		_, err := otherEnc.Decrypt(ciphertext)
		if err != ErrDecryptionFailed {
			t.Errorf("expected ErrDecryptionFailed, got %v", err)
		}
	})

	t.Run("tampered ciphertext", func(t *testing.T) {
		plaintext := []byte("secret data")
		ciphertext, _ := enc.Encrypt(plaintext)

		// Decode, tamper, re-encode
		decoded, _ := base64.URLEncoding.DecodeString(ciphertext)
		decoded[len(decoded)-1] ^= 0xFF // flip bits in last byte
		tampered := base64.URLEncoding.EncodeToString(decoded)

		_, err := enc.Decrypt(tampered)
		if err != ErrDecryptionFailed {
			t.Errorf("expected ErrDecryptionFailed, got %v", err)
		}
	})
}

func TestEncryptor_UniqueCiphertexts(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor failed: %v", err)
	}

	plaintext := []byte("same data")
	ciphertexts := make(map[string]bool)

	// Encrypt same data multiple times
	for i := 0; i < 100; i++ {
		ct, err := enc.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		if ciphertexts[ct] {
			t.Error("got duplicate ciphertext - nonce should be unique")
		}
		ciphertexts[ct] = true
	}
}

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}

	// Generate another and check they're different
	key2, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if bytes.Equal(key, key2) {
		t.Error("generated keys should be unique")
	}
}

func TestGenerateKeyString(t *testing.T) {
	keyStr, err := GenerateKeyString()
	if err != nil {
		t.Fatalf("GenerateKeyString failed: %v", err)
	}

	// Should be valid base64
	key, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		t.Errorf("generated key string is not valid base64: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("decoded key length = %d, want 32", len(key))
	}

	// Should work with NewEncryptorFromString
	enc, err := NewEncryptorFromString(keyStr)
	if err != nil {
		t.Errorf("NewEncryptorFromString failed with generated key: %v", err)
	}

	// Test encryption/decryption
	plaintext := "test data"
	ciphertext, err := enc.EncryptString(plaintext)
	if err != nil {
		t.Fatalf("EncryptString failed: %v", err)
	}

	decrypted, err := enc.DecryptString(ciphertext)
	if err != nil {
		t.Fatalf("DecryptString failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("decrypted = %s, want %s", decrypted, plaintext)
	}
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
		if !strings.Contains(ErrInvalidKeySize.Error(), "32 bytes") {
			t.Error("ErrInvalidKeySize should mention 32 bytes")
		}
	})

	t.Run("ErrCiphertextTooShort", func(t *testing.T) {
		if ErrCiphertextTooShort.Error() == "" {
			t.Error("ErrCiphertextTooShort should have message")
		}
	})

	t.Run("ErrDecryptionFailed", func(t *testing.T) {
		if ErrDecryptionFailed.Error() == "" {
			t.Error("ErrDecryptionFailed should have message")
		}
	})
}
