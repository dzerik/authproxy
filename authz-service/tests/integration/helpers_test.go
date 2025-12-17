// Package integration contains integration tests for the authz-service.
package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestKeyPair holds RSA key pair for testing.
type TestKeyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	KeyID      string
}

// NewTestKeyPair generates a new RSA key pair for testing.
func NewTestKeyPair() (*TestKeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &TestKeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		KeyID:      "test-key-1",
	}, nil
}

// JWKS returns the JWKS JSON for this key pair.
func (kp *TestKeyPair) JWKS() []byte {
	n := base64.RawURLEncoding.EncodeToString(kp.PublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(kp.PublicKey.E)).Bytes())

	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": kp.KeyID,
				"n":   n,
				"e":   e,
			},
		},
	}

	data, _ := json.Marshal(jwks)
	return data
}

// SignToken creates a signed JWT with the given claims.
func (kp *TestKeyPair) SignToken(claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kp.KeyID
	return token.SignedString(kp.PrivateKey)
}

// NewTestClaims creates standard test claims.
func NewTestClaims(issuer, subject string, roles []string, scopes []string) jwt.MapClaims {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   issuer,
		"sub":   subject,
		"aud":   []string{"authz-service"},
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"nbf":   now.Unix(),
		"jti":   fmt.Sprintf("test-token-%d", now.UnixNano()),
		"scope": joinScopes(scopes),
	}

	// Add roles in different formats (Keycloak-style)
	if len(roles) > 0 {
		claims["realm_access"] = map[string]any{
			"roles": roles,
		}
	}

	return claims
}

// NewAgentClaims creates claims for an LLM agent token.
func NewAgentClaims(issuer, agentID, model string) jwt.MapClaims {
	claims := NewTestClaims(issuer, agentID, []string{"agent"}, []string{"read", "write"})
	claims["agent_type"] = "llm_agent"
	claims["agent_name"] = "Test Agent"
	claims["agent_model"] = model
	claims["agent_provider"] = "test-provider"
	claims["session_id"] = "test-session-123"
	return claims
}

// NewDelegatedClaims creates claims with delegation chain.
func NewDelegatedClaims(issuer, subject, actorSubject string) jwt.MapClaims {
	claims := NewTestClaims(issuer, subject, []string{"user"}, []string{"read"})
	claims["act"] = map[string]any{
		"sub":       actorSubject,
		"client_id": "agent-client",
		"type":      "llm_agent",
	}
	return claims
}

func joinScopes(scopes []string) string {
	result := ""
	for i, s := range scopes {
		if i > 0 {
			result += " "
		}
		result += s
	}
	return result
}

// MockJWKSServer creates a test server that serves JWKS.
func MockJWKSServer(t *testing.T, keyPair *TestKeyPair) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	// JWKS endpoint
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(keyPair.JWKS())
	})

	// OpenID Connect discovery endpoint
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// URL will be set dynamically in the handler
	})

	server := httptest.NewServer(mux)

	// Update the handler to use actual server URL
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		config := map[string]any{
			"issuer":                 server.URL,
			"jwks_uri":               server.URL + "/.well-known/jwks.json",
			"authorization_endpoint": server.URL + "/auth",
			"token_endpoint":         server.URL + "/token",
		}
		json.NewEncoder(w).Encode(config)
	})

	return server
}

// MockOPASidecar creates a test server that mimics OPA sidecar.
func MockOPASidecar(t *testing.T, allowedPaths map[string]bool) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var input struct {
			Input map[string]any `json:"input"`
		}

		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Extract path from input
		path := "/"
		if req, ok := input.Input["request"].(map[string]any); ok {
			if p, ok := req["path"].(string); ok {
				path = p
			}
		}

		// Check if path is allowed
		allowed := false
		for pattern, isAllowed := range allowedPaths {
			if matchPath(pattern, path) {
				allowed = isAllowed
				break
			}
		}

		response := map[string]any{
			"result": map[string]any{
				"allow": allowed,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
}

func matchPath(pattern, path string) bool {
	if pattern == path {
		return true
	}
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(path) >= len(prefix) && path[:len(prefix)] == prefix
	}
	return false
}

// NewTestContext returns a context with timeout.
func NewTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}
