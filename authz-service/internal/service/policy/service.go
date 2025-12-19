package policy

import (
	"context"
	"hash/fnv"
	"strconv"
	"strings"
	"time"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/internal/domain"
	"github.com/your-org/authz-service/pkg/errors"
	"github.com/your-org/authz-service/pkg/logger"
	"github.com/your-org/authz-service/pkg/resilience/circuitbreaker"
)

// Service provides policy evaluation with caching support.
type Service struct {
	engine            Engine
	fallbackEngine    Engine
	cache             Cache
	enhancers         []AuthorizationEnhancer
	decisionEnhancers []DecisionEnhancer
	cfg               config.PolicyConfig
	cbManager         *circuitbreaker.Manager
}

// Cache defines the interface for decision caching.
type Cache interface {
	Get(ctx context.Context, key string) (*domain.Decision, bool)
	Set(ctx context.Context, key string, decision *domain.Decision, ttl time.Duration)
}

// ServiceOption is a functional option for configuring the service.
type ServiceOption func(*Service)

// WithCache sets the cache for the service.
func WithCache(cache Cache) ServiceOption {
	return func(s *Service) {
		s.cache = cache
	}
}

// WithEnhancer adds an authorization enhancer.
func WithEnhancer(enhancer AuthorizationEnhancer) ServiceOption {
	return func(s *Service) {
		s.enhancers = append(s.enhancers, enhancer)
	}
}

// WithDecisionEnhancer adds a decision enhancer.
func WithDecisionEnhancer(enhancer DecisionEnhancer) ServiceOption {
	return func(s *Service) {
		s.decisionEnhancers = append(s.decisionEnhancers, enhancer)
	}
}

// WithCircuitBreaker sets the circuit breaker manager for the service.
func WithCircuitBreaker(cbManager *circuitbreaker.Manager) ServiceOption {
	return func(s *Service) {
		s.cbManager = cbManager
	}
}

// NewService creates a new policy service.
func NewService(cfg config.PolicyConfig, opts ...ServiceOption) (*Service, error) {
	s := &Service{
		cfg: cfg,
	}

	// Apply options
	for _, opt := range opts {
		opt(s)
	}

	// Create primary engine
	switch cfg.Engine {
	case "builtin":
		engine, err := NewBuiltinEngine(cfg.Builtin)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create builtin engine")
		}
		s.engine = engine
	case "opa-sidecar":
		// Use circuit breaker if configured
		var opaEngine *OPASidecarEngine
		var opaErr error
		if s.cbManager != nil {
			opaEngine, opaErr = NewOPASidecarEngineWithCB(cfg.OPA, s.cbManager)
		} else {
			opaEngine, opaErr = NewOPASidecarEngine(cfg.OPA)
		}
		if opaErr != nil {
			return nil, errors.Wrap(opaErr, "failed to create OPA sidecar engine")
		}
		s.engine = opaEngine
	case "opa-embedded":
		s.engine = NewOPAEmbeddedEngine(cfg.OPAEmbedded)
	default:
		engine, err := NewBuiltinEngine(cfg.Builtin)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create builtin engine")
		}
		s.engine = engine
	}

	// Create fallback engine if configured
	if cfg.Fallback.Enabled && cfg.Fallback.Engine != cfg.Engine {
		switch cfg.Fallback.Engine {
		case "builtin":
			engine, err := NewBuiltinEngine(cfg.Builtin)
			if err != nil {
				return nil, errors.Wrap(err, "failed to create fallback builtin engine")
			}
			s.fallbackEngine = engine
		}
	}

	return s, nil
}

// Start initializes the policy service.
func (s *Service) Start(ctx context.Context) error {
	if err := s.engine.Start(ctx); err != nil {
		return errors.Wrap(err, "failed to start primary engine")
	}

	if s.fallbackEngine != nil {
		if err := s.fallbackEngine.Start(ctx); err != nil {
			logger.Warn("failed to start fallback engine",
				logger.Err(err),
			)
		}
	}

	logger.Info("policy service started",
		logger.String("engine", s.engine.Name()),
	)

	return nil
}

// Stop shuts down the policy service.
func (s *Service) Stop() error {
	if err := s.engine.Stop(); err != nil {
		logger.Warn("error stopping primary engine", logger.Err(err))
	}
	if s.fallbackEngine != nil {
		if err := s.fallbackEngine.Stop(); err != nil {
			logger.Warn("error stopping fallback engine", logger.Err(err))
		}
	}
	return nil
}

// Evaluate evaluates the policy input and returns a decision.
func (s *Service) Evaluate(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
	start := time.Now()

	// Apply authorization enhancers (extension point for agents)
	for _, enhancer := range s.enhancers {
		if err := enhancer.Enhance(ctx, input); err != nil {
			logger.Warn("enhancer failed", logger.Err(err))
		}
	}

	// Check cache
	if s.cache != nil {
		cacheKey := s.computeCacheKey(input)
		if decision, found := s.cache.Get(ctx, cacheKey); found {
			decision.Cached = true
			logger.Debug("cache hit",
				logger.String("key", cacheKey),
			)
			return decision, nil
		}
	}

	// Evaluate with primary engine
	decision, err := s.engine.Evaluate(ctx, input)
	if err != nil {
		// Try fallback if available
		if s.fallbackEngine != nil && s.cfg.Fallback.Enabled {
			logger.Warn("primary engine failed, trying fallback",
				logger.Err(err),
			)
			decision, err = s.fallbackEngine.Evaluate(ctx, input)
			if err != nil {
				return s.applyFallbackBehavior(), nil
			}
			decision.WithReason("evaluated by fallback engine")
		} else {
			return nil, err
		}
	}

	// Apply decision enhancers
	for _, enhancer := range s.decisionEnhancers {
		if err := enhancer.Enhance(ctx, input, decision); err != nil {
			logger.Warn("decision enhancer failed", logger.Err(err))
		}
	}

	// Cache the decision
	if s.cache != nil && decision != nil {
		cacheKey := s.computeCacheKey(input)
		s.cache.Set(ctx, cacheKey, decision, 0) // TTL handled by cache implementation
	}

	decision.EvaluatedAt = time.Now()

	logger.Debug("policy evaluated",
		logger.Bool("allowed", decision.Allowed),
		logger.Duration("duration", time.Since(start)),
	)

	return decision, nil
}

// applyFallbackBehavior applies the fallback behavior when all engines fail.
func (s *Service) applyFallbackBehavior() *domain.Decision {
	switch s.cfg.Fallback.Behavior {
	case "allow":
		return domain.Allow("fallback: all engines failed, allowing").
			WithMetadata("fallback", true)
	default: // "deny"
		return domain.Deny("fallback: all engines failed, denying").
			WithMetadata("fallback", true)
	}
}

// computeCacheKey generates a cache key from the policy input.
// Uses FNV-1a hash for fast, non-cryptographic hashing.
func (s *Service) computeCacheKey(input *domain.PolicyInput) string {
	// Pre-allocate builder with estimated capacity
	var b strings.Builder
	b.Grow(128)

	// Build key from request fields
	b.WriteString(input.Request.Method)
	b.WriteByte('|')
	b.WriteString(input.Request.Path)

	if input.Token != nil {
		b.WriteByte('|')
		b.WriteString(input.Token.Subject)
		// Sort roles/scopes for deterministic keys
		if len(input.Token.Roles) > 0 {
			b.WriteByte('|')
			b.WriteString(strings.Join(input.Token.Roles, ","))
		}
		if len(input.Token.Scopes) > 0 {
			b.WriteByte('|')
			b.WriteString(strings.Join(input.Token.Scopes, ","))
		}
	}

	// Use FNV-1a hash for fast hashing
	h := fnv.New64a()
	h.Write([]byte(b.String()))
	return strconv.FormatUint(h.Sum64(), 36)
}

// Healthy returns true if the service is healthy.
func (s *Service) Healthy(ctx context.Context) bool {
	return s.engine.Healthy(ctx)
}

// EngineName returns the name of the primary engine.
func (s *Service) EngineName() string {
	return s.engine.Name()
}

// Reload reloads the policy engine configuration.
func (s *Service) Reload(ctx context.Context) error {
	logger.Info("reloading policy engine")

	// If the engine supports reloading, reload it
	if reloader, ok := s.engine.(Reloader); ok {
		if err := reloader.Reload(ctx); err != nil {
			return errors.Wrap(err, "failed to reload engine")
		}
	}

	// Reload fallback engine if it supports reloading
	if s.fallbackEngine != nil {
		if reloader, ok := s.fallbackEngine.(Reloader); ok {
			if err := reloader.Reload(ctx); err != nil {
				logger.Warn("failed to reload fallback engine", logger.Err(err))
			}
		}
	}

	logger.Info("policy engine reloaded successfully")
	return nil
}

// Reloader is an interface for engines that support hot-reloading.
type Reloader interface {
	Reload(ctx context.Context) error
}
