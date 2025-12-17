package cache

import (
	"context"
	"time"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/internal/domain"
	"github.com/your-org/authz-service/pkg/logger"
)

// Service provides multi-level caching for authorization decisions.
type Service struct {
	l1      *L1Cache
	l2      *L2RedisCache
	cfg     config.CacheConfig
	enabled bool
}

// NewService creates a new cache service.
func NewService(cfg config.CacheConfig) *Service {
	var l1 *L1Cache
	if cfg.L1.Enabled {
		l1 = NewL1Cache(cfg.L1)
	}

	var l2 *L2RedisCache
	if cfg.L2.Enabled {
		var err error
		l2, err = NewL2RedisCache(cfg.L2)
		if err != nil {
			logger.Warn("failed to create L2 cache", logger.Err(err))
		}
	}

	return &Service{
		l1:      l1,
		l2:      l2,
		cfg:     cfg,
		enabled: cfg.L1.Enabled || cfg.L2.Enabled,
	}
}

// Start initializes the cache service.
func (s *Service) Start(ctx context.Context) error {
	if s.l1 != nil {
		// Start cleanup every minute
		s.l1.StartCleanup(ctx, time.Minute)
	}

	if s.l2 != nil {
		if err := s.l2.Start(ctx); err != nil {
			logger.Warn("L2 cache start failed, continuing without it", logger.Err(err))
		}
	}

	logger.Info("cache service started",
		logger.Bool("l1_enabled", s.cfg.L1.Enabled),
		logger.Bool("l2_enabled", s.l2 != nil && s.l2.Enabled()),
	)

	return nil
}

// Stop shuts down the cache service.
func (s *Service) Stop() error {
	if s.l2 != nil {
		return s.l2.Stop()
	}
	return nil
}

// Get retrieves a decision from the cache.
// It checks L1 first, then L2 (if configured).
func (s *Service) Get(ctx context.Context, key string) (*domain.Decision, bool) {
	if !s.enabled {
		return nil, false
	}

	// Try L1 first
	if s.l1 != nil {
		if decision, found := s.l1.Get(ctx, key); found {
			return decision, true
		}
	}

	// Try L2 (Redis) if L1 miss
	if s.l2 != nil && s.l2.Enabled() {
		if decision, found := s.l2.Get(ctx, key); found {
			// Backfill L1
			if s.l1 != nil {
				s.l1.Set(ctx, key, decision, 0)
			}
			return decision, true
		}
	}

	return nil, false
}

// Set stores a decision in the cache.
func (s *Service) Set(ctx context.Context, key string, decision *domain.Decision, ttl time.Duration) {
	if !s.enabled {
		return
	}

	// Set in L1
	if s.l1 != nil {
		s.l1.Set(ctx, key, decision, ttl)
	}

	// Set in L2 (Redis)
	if s.l2 != nil && s.l2.Enabled() {
		s.l2.Set(ctx, key, decision, ttl)
	}
}

// Delete removes a key from all cache levels.
func (s *Service) Delete(ctx context.Context, key string) {
	if s.l1 != nil {
		s.l1.Delete(ctx, key)
	}
	if s.l2 != nil && s.l2.Enabled() {
		s.l2.Delete(ctx, key)
	}
}

// Clear removes all entries from all cache levels.
func (s *Service) Clear(ctx context.Context) {
	if s.l1 != nil {
		s.l1.Clear(ctx)
	}
	if s.l2 != nil && s.l2.Enabled() {
		s.l2.Clear(ctx)
	}
}

// Stats returns cache statistics.
func (s *Service) Stats() map[string]CacheStats {
	stats := make(map[string]CacheStats)

	if s.l1 != nil {
		stats["l1"] = s.l1.Stats()
	}

	if s.l2 != nil && s.l2.Enabled() {
		stats["l2"] = s.l2.Stats()
	}

	return stats
}

// Enabled returns true if caching is enabled.
func (s *Service) Enabled() bool {
	return s.enabled
}

// Healthy checks if cache backends are healthy.
func (s *Service) Healthy(ctx context.Context) bool {
	if s.l2 != nil && s.l2.Enabled() {
		return s.l2.Healthy(ctx)
	}
	return true
}
