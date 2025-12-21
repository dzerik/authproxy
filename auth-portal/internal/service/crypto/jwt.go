package crypto

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrTokenExpired     = errors.New("token expired")
	ErrInvalidAlgorithm = errors.New("invalid algorithm")
	ErrMissingKey       = errors.New("missing signing key")
)

// JWTManager handles JWT signing and verification
type JWTManager struct {
	algorithm  string
	hmacKey    []byte
	rsaPrivate *rsa.PrivateKey
	rsaPublic  *rsa.PublicKey
	issuer     string
}

// JWTConfig represents JWT configuration
type JWTConfig struct {
	Algorithm  string // HS256 or RS256
	SigningKey string // For HS256
	PrivateKey string // Path to private key for RS256
	PublicKey  string // Path to public key for RS256
	Issuer     string
}

// SessionClaims represents claims in a session JWT
type SessionClaims struct {
	jwt.RegisteredClaims
	UserID   string   `json:"uid"`
	Email    string   `json:"email"`
	Name     string   `json:"name"`
	Roles    []string `json:"roles,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	TenantID string   `json:"tid,omitempty"`
}

// NewJWTManager creates a new JWT manager
func NewJWTManager(cfg JWTConfig) (*JWTManager, error) {
	m := &JWTManager{
		algorithm: cfg.Algorithm,
		issuer:    cfg.Issuer,
	}

	switch cfg.Algorithm {
	case "HS256", "":
		if cfg.SigningKey == "" {
			return nil, ErrMissingKey
		}
		m.hmacKey = []byte(cfg.SigningKey)
		m.algorithm = "HS256"

	case "RS256":
		if cfg.PrivateKey != "" {
			keyData, err := os.ReadFile(cfg.PrivateKey)
			if err != nil {
				return nil, fmt.Errorf("failed to read private key: %w", err)
			}
			privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
			if err != nil {
				return nil, fmt.Errorf("failed to parse private key: %w", err)
			}
			m.rsaPrivate = privateKey
			m.rsaPublic = &privateKey.PublicKey
		}

		if cfg.PublicKey != "" && m.rsaPublic == nil {
			keyData, err := os.ReadFile(cfg.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("failed to read public key: %w", err)
			}
			publicKey, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
			if err != nil {
				return nil, fmt.Errorf("failed to parse public key: %w", err)
			}
			m.rsaPublic = publicKey
		}

		if m.rsaPrivate == nil && m.rsaPublic == nil {
			return nil, ErrMissingKey
		}

	default:
		return nil, ErrInvalidAlgorithm
	}

	return m, nil
}

// Sign creates a signed JWT with the given claims
func (m *JWTManager) Sign(claims *SessionClaims) (string, error) {
	if claims.Issuer == "" && m.issuer != "" {
		claims.Issuer = m.issuer
	}

	var token *jwt.Token
	switch m.algorithm {
	case "HS256":
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		return token.SignedString(m.hmacKey)

	case "RS256":
		if m.rsaPrivate == nil {
			return "", errors.New("private key required for signing")
		}
		token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		return token.SignedString(m.rsaPrivate)

	default:
		return "", ErrInvalidAlgorithm
	}
}

// Verify verifies a JWT and returns the claims
func (m *JWTManager) Verify(tokenString string) (*SessionClaims, error) {
	claims := &SessionClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		switch m.algorithm {
		case "HS256":
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return m.hmacKey, nil

		case "RS256":
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return m.rsaPublic, nil

		default:
			return nil, ErrInvalidAlgorithm
		}
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// CreateSessionClaims creates claims for a session JWT
func CreateSessionClaims(sessionID, userID, email, name string, roles, groups []string, ttl time.Duration) *SessionClaims {
	now := time.Now()
	return &SessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        sessionID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
		},
		UserID: userID,
		Email:  email,
		Name:   name,
		Roles:  roles,
		Groups: groups,
	}
}
