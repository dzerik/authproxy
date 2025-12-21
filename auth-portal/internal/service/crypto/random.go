package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

// GenerateRandomBytes generates n random bytes
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return b, nil
}

// GenerateRandomString generates a random string of n bytes encoded as base64
func GenerateRandomString(n int) (string, error) {
	b, err := GenerateRandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// GenerateRandomHex generates a random hex string of n bytes
func GenerateRandomHex(n int) (string, error) {
	b, err := GenerateRandomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GenerateSessionID generates a random session ID (32 bytes, base64 encoded)
func GenerateSessionID() (string, error) {
	return GenerateRandomString(32)
}

// GenerateStateToken generates a random state token for OAuth (16 bytes, base64 encoded)
func GenerateStateToken() (string, error) {
	return GenerateRandomString(16)
}

// GenerateNonce generates a random nonce for OIDC (16 bytes, base64 encoded)
func GenerateNonce() (string, error) {
	return GenerateRandomString(16)
}

// MustGenerateSessionID generates a session ID or panics
func MustGenerateSessionID() string {
	id, err := GenerateSessionID()
	if err != nil {
		panic(err)
	}
	return id
}

// MustGenerateStateToken generates a state token or panics
func MustGenerateStateToken() string {
	token, err := GenerateStateToken()
	if err != nil {
		panic(err)
	}
	return token
}
