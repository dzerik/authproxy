package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
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
			if err != nil {
				t.Fatalf("GenerateRandomBytes(%d) failed: %v", tt.n, err)
			}

			if len(b) != tt.n {
				t.Errorf("len = %d, want %d", len(b), tt.n)
			}
		})
	}
}

func TestGenerateRandomBytes_Unique(t *testing.T) {
	seen := make(map[string]bool)

	for i := 0; i < 100; i++ {
		b, err := GenerateRandomBytes(32)
		if err != nil {
			t.Fatalf("GenerateRandomBytes failed: %v", err)
		}

		key := string(b)
		if seen[key] {
			t.Error("got duplicate random bytes")
		}
		seen[key] = true
	}
}

func TestGenerateRandomString(t *testing.T) {
	tests := []struct {
		name          string
		n             int
		expectedLen   int // base64 encoded length
	}{
		{"16 bytes", 16, 22}, // 16 * 4/3 = 21.3, rounded up with padding removed
		{"32 bytes", 32, 43}, // 32 * 4/3 = 42.7
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := GenerateRandomString(tt.n)
			if err != nil {
				t.Fatalf("GenerateRandomString(%d) failed: %v", tt.n, err)
			}

			// Verify it's valid base64 URL encoding
			decoded, err := base64.URLEncoding.DecodeString(s)
			if err != nil {
				t.Errorf("not valid base64 URL encoded: %v", err)
			}

			if len(decoded) != tt.n {
				t.Errorf("decoded length = %d, want %d", len(decoded), tt.n)
			}
		})
	}
}

func TestGenerateRandomString_Unique(t *testing.T) {
	seen := make(map[string]bool)

	for i := 0; i < 100; i++ {
		s, err := GenerateRandomString(16)
		if err != nil {
			t.Fatalf("GenerateRandomString failed: %v", err)
		}

		if seen[s] {
			t.Error("got duplicate random string")
		}
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
			if err != nil {
				t.Fatalf("GenerateRandomHex(%d) failed: %v", tt.n, err)
			}

			if len(s) != tt.expectedLen {
				t.Errorf("length = %d, want %d", len(s), tt.expectedLen)
			}

			// Verify it's valid hex
			decoded, err := hex.DecodeString(s)
			if err != nil {
				t.Errorf("not valid hex: %v", err)
			}

			if len(decoded) != tt.n {
				t.Errorf("decoded length = %d, want %d", len(decoded), tt.n)
			}
		})
	}
}

func TestGenerateRandomHex_Unique(t *testing.T) {
	seen := make(map[string]bool)

	for i := 0; i < 100; i++ {
		s, err := GenerateRandomHex(16)
		if err != nil {
			t.Fatalf("GenerateRandomHex failed: %v", err)
		}

		if seen[s] {
			t.Error("got duplicate random hex")
		}
		seen[s] = true
	}
}

func TestGenerateSessionID(t *testing.T) {
	id, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID failed: %v", err)
	}

	// Should be base64 URL encoded 32 bytes
	decoded, err := base64.URLEncoding.DecodeString(id)
	if err != nil {
		t.Errorf("session ID is not valid base64 URL encoded: %v", err)
	}

	if len(decoded) != 32 {
		t.Errorf("decoded session ID length = %d, want 32", len(decoded))
	}
}

func TestGenerateSessionID_Unique(t *testing.T) {
	seen := make(map[string]bool)

	for i := 0; i < 100; i++ {
		id, err := GenerateSessionID()
		if err != nil {
			t.Fatalf("GenerateSessionID failed: %v", err)
		}

		if seen[id] {
			t.Error("got duplicate session ID")
		}
		seen[id] = true
	}
}

func TestGenerateStateToken(t *testing.T) {
	token, err := GenerateStateToken()
	if err != nil {
		t.Fatalf("GenerateStateToken failed: %v", err)
	}

	// Should be base64 URL encoded 16 bytes
	decoded, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		t.Errorf("state token is not valid base64 URL encoded: %v", err)
	}

	if len(decoded) != 16 {
		t.Errorf("decoded state token length = %d, want 16", len(decoded))
	}
}

func TestGenerateNonce(t *testing.T) {
	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce failed: %v", err)
	}

	// Should be base64 URL encoded 16 bytes
	decoded, err := base64.URLEncoding.DecodeString(nonce)
	if err != nil {
		t.Errorf("nonce is not valid base64 URL encoded: %v", err)
	}

	if len(decoded) != 16 {
		t.Errorf("decoded nonce length = %d, want 16", len(decoded))
	}
}

func TestMustGenerateSessionID(t *testing.T) {
	// Should not panic
	id := MustGenerateSessionID()
	if id == "" {
		t.Error("MustGenerateSessionID returned empty string")
	}

	// Verify it's valid
	decoded, err := base64.URLEncoding.DecodeString(id)
	if err != nil {
		t.Errorf("session ID is not valid base64 URL encoded: %v", err)
	}

	if len(decoded) != 32 {
		t.Errorf("decoded session ID length = %d, want 32", len(decoded))
	}
}

func TestMustGenerateStateToken(t *testing.T) {
	// Should not panic
	token := MustGenerateStateToken()
	if token == "" {
		t.Error("MustGenerateStateToken returned empty string")
	}

	// Verify it's valid
	decoded, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		t.Errorf("state token is not valid base64 URL encoded: %v", err)
	}

	if len(decoded) != 16 {
		t.Errorf("decoded state token length = %d, want 16", len(decoded))
	}
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
