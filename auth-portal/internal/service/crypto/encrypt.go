package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

var (
	ErrInvalidKeySize    = errors.New("invalid key size: must be 32 bytes for AES-256")
	ErrCiphertextTooShort = errors.New("ciphertext too short")
	ErrDecryptionFailed  = errors.New("decryption failed")
)

// Encryptor provides AES-256-GCM encryption/decryption
type Encryptor struct {
	aead cipher.AEAD
}

// NewEncryptor creates a new Encryptor with the given key
// Key must be 32 bytes for AES-256
func NewEncryptor(key []byte) (*Encryptor, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &Encryptor{aead: aead}, nil
}

// NewEncryptorFromString creates a new Encryptor from a base64-encoded key
func NewEncryptorFromString(keyStr string) (*Encryptor, error) {
	// Try base64 decoding first
	key, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		// If not base64, use the string directly as bytes
		key = []byte(keyStr)
	}
	return NewEncryptor(key)
}

// Encrypt encrypts plaintext using AES-256-GCM
// Returns base64-encoded ciphertext (nonce prepended)
func (e *Encryptor) Encrypt(plaintext []byte) (string, error) {
	// Generate random nonce
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and append to nonce
	ciphertext := e.aead.Seal(nonce, nonce, plaintext, nil)

	// Encode as base64
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// EncryptString encrypts a string
func (e *Encryptor) EncryptString(plaintext string) (string, error) {
	return e.Encrypt([]byte(plaintext))
}

// Decrypt decrypts base64-encoded ciphertext
func (e *Encryptor) Decrypt(ciphertextB64 string) ([]byte, error) {
	// Decode from base64
	ciphertext, err := base64.URLEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	// Check minimum size (nonce + at least 1 byte of data + tag)
	nonceSize := e.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrCiphertextTooShort
	}

	// Split nonce and ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt
	plaintext, err := e.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// DecryptString decrypts to a string
func (e *Encryptor) DecryptString(ciphertextB64 string) (string, error) {
	plaintext, err := e.Decrypt(ciphertextB64)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// GenerateKey generates a random 32-byte key for AES-256
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return key, nil
}

// GenerateKeyString generates a random key and returns it as base64
func GenerateKeyString() (string, error) {
	key, err := GenerateKey()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}
