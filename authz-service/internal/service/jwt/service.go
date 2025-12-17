package jwt

import (
	"context"
	"strings"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/internal/domain"
	"github.com/your-org/authz-service/pkg/errors"
)

// Service provides JWT validation capabilities.
type Service struct {
	jwksProvider *JWKSProvider
	validator    *Validator
	cfg          config.JWTConfig
}

// NewService creates a new JWT service.
func NewService(cfg config.JWTConfig) *Service {
	jwksProvider := NewJWKSProvider(cfg.Issuers, cfg.JWKSCache)
	validator := NewValidator(jwksProvider, cfg)

	return &Service{
		jwksProvider: jwksProvider,
		validator:    validator,
		cfg:          cfg,
	}
}

// Start initializes the JWT service.
func (s *Service) Start(ctx context.Context) error {
	return s.jwksProvider.Start(ctx)
}

// Stop stops the JWT service.
func (s *Service) Stop() {
	s.jwksProvider.Stop()
}

// ValidateToken validates a JWT token and returns token information.
func (s *Service) ValidateToken(ctx context.Context, tokenString string) (*domain.TokenInfo, error) {
	return s.validator.Validate(ctx, tokenString)
}

// ExtractToken extracts a bearer token from the Authorization header.
func (s *Service) ExtractToken(authHeader string) (string, error) {
	if authHeader == "" {
		return "", errors.ErrTokenMissing
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		return "", errors.ErrTokenMalformed
	}

	if !strings.EqualFold(parts[0], "Bearer") {
		return "", errors.ErrTokenMalformed
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", errors.ErrTokenMissing
	}

	return token, nil
}

// ValidateFromHeader extracts and validates a token from the Authorization header.
func (s *Service) ValidateFromHeader(ctx context.Context, authHeader string) (*domain.TokenInfo, error) {
	token, err := s.ExtractToken(authHeader)
	if err != nil {
		return nil, err
	}

	return s.ValidateToken(ctx, token)
}
