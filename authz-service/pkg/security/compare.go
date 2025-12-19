// Package security provides security utilities for the authorization service.
package security

import (
	"crypto/subtle"
)

// SecureCompare performs a constant-time comparison of two strings.
// This should be used when comparing secrets (API keys, tokens, etc.)
// to prevent timing attacks.
func SecureCompare(a, b string) bool {
	// subtle.ConstantTimeCompare returns 1 if the two slices are equal, 0 otherwise.
	// It runs in constant time regardless of the contents of the slices.
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// SecureCompareBytes performs a constant-time comparison of two byte slices.
func SecureCompareBytes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// SecureCompareHash compares a value with a stored hash in constant time.
// This is useful when comparing password hashes or HMAC values.
func SecureCompareHash(computed, stored []byte) bool {
	if len(computed) != len(stored) {
		// Still do the comparison to prevent length-based timing attacks
		// but always return false
		subtle.ConstantTimeCompare(computed, stored)
		return false
	}
	return subtle.ConstantTimeCompare(computed, stored) == 1
}
