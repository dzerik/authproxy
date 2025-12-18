package policy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/internal/domain"
)

// =============================================================================
// Mock Engine
// =============================================================================

type mockEngine struct {
	name         string
	evaluateFunc func(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error)
	startErr     error
	stopErr      error
	healthy      bool
	started      bool
	stopped      bool
}

func (m *mockEngine) Name() string {
	return m.name
}

func (m *mockEngine) Evaluate(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
	if m.evaluateFunc != nil {
		return m.evaluateFunc(ctx, input)
	}
	return domain.Allow("mock allow"), nil
}

func (m *mockEngine) Start(ctx context.Context) error {
	m.started = true
	return m.startErr
}

func (m *mockEngine) Stop() error {
	m.stopped = true
	return m.stopErr
}

func (m *mockEngine) Healthy(ctx context.Context) bool {
	return m.healthy
}

// mockReloadableEngine implements Engine and Reloader interfaces
type mockReloadableEngine struct {
	mockEngine
	reloaded  bool
	reloadErr error
}

func (m *mockReloadableEngine) Reload(ctx context.Context) error {
	m.reloaded = true
	return m.reloadErr
}

// =============================================================================
// Mock Cache
// =============================================================================

type mockCache struct {
	store map[string]*domain.Decision
}

func newMockCache() *mockCache {
	return &mockCache{store: make(map[string]*domain.Decision)}
}

func (m *mockCache) Get(ctx context.Context, key string) (*domain.Decision, bool) {
	d, ok := m.store[key]
	return d, ok
}

func (m *mockCache) Set(ctx context.Context, key string, decision *domain.Decision, ttl time.Duration) {
	m.store[key] = decision
}

// =============================================================================
// Mock Enhancers
// =============================================================================

type mockAuthEnhancer struct {
	enhanceFunc func(ctx context.Context, input *domain.PolicyInput) error
	called      int
}

func (m *mockAuthEnhancer) Enhance(ctx context.Context, input *domain.PolicyInput) error {
	m.called++
	if m.enhanceFunc != nil {
		return m.enhanceFunc(ctx, input)
	}
	return nil
}

type mockDecisionEnhancer struct {
	enhanceFunc func(ctx context.Context, input *domain.PolicyInput, decision *domain.Decision) error
	called      int
}

func (m *mockDecisionEnhancer) Enhance(ctx context.Context, input *domain.PolicyInput, decision *domain.Decision) error {
	m.called++
	if m.enhanceFunc != nil {
		return m.enhanceFunc(ctx, input, decision)
	}
	return nil
}

// =============================================================================
// NewService Tests
// =============================================================================

func TestNewService_BuiltinEngine(t *testing.T) {
	cfg := config.PolicyConfig{
		Engine: "builtin",
		Builtin: config.BuiltinPolicyConfig{
			RulesPath: "/tmp/test-rules.yaml",
		},
	}

	svc, err := NewService(cfg)
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.Equal(t, "builtin", svc.engine.Name())
}

func TestNewService_DefaultEngine(t *testing.T) {
	cfg := config.PolicyConfig{
		Engine: "unknown", // Should default to builtin
		Builtin: config.BuiltinPolicyConfig{
			RulesPath: "/tmp/test-rules.yaml",
		},
	}

	svc, err := NewService(cfg)
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.Equal(t, "builtin", svc.engine.Name())
}

func TestNewService_OPASidecar(t *testing.T) {
	cfg := config.PolicyConfig{
		Engine: "opa-sidecar",
		OPA: config.OPAConfig{
			URL:        "http://localhost:8181",
			PolicyPath: "/v1/data/authz/allow",
		},
	}

	svc, err := NewService(cfg)
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.Equal(t, "opa-sidecar", svc.engine.Name())
}

func TestNewService_WithOptions(t *testing.T) {
	cfg := config.PolicyConfig{
		Engine: "builtin",
		Builtin: config.BuiltinPolicyConfig{
			RulesPath: "/tmp/test-rules.yaml",
		},
	}

	cache := newMockCache()
	authEnhancer := &mockAuthEnhancer{}
	decisionEnhancer := &mockDecisionEnhancer{}

	svc, err := NewService(cfg,
		WithCache(cache),
		WithEnhancer(authEnhancer),
		WithDecisionEnhancer(decisionEnhancer),
	)

	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.Equal(t, cache, svc.cache)
	assert.Len(t, svc.enhancers, 1)
	assert.Len(t, svc.decisionEnhancers, 1)
}

func TestNewService_WithFallbackEngine(t *testing.T) {
	cfg := config.PolicyConfig{
		Engine: "opa-sidecar",
		OPA: config.OPAConfig{
			URL:        "http://localhost:8181",
			PolicyPath: "/v1/data/authz/allow",
		},
		Fallback: config.FallbackConfig{
			Enabled: true,
			Engine:  "builtin",
		},
		Builtin: config.BuiltinPolicyConfig{
			RulesPath: "/tmp/test-rules.yaml",
		},
	}

	svc, err := NewService(cfg)
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.NotNil(t, svc.fallbackEngine)
}

// =============================================================================
// Start/Stop Tests
// =============================================================================

func TestService_Start_Success(t *testing.T) {
	engine := &mockEngine{name: "test", healthy: true}
	svc := &Service{engine: engine, cfg: config.PolicyConfig{}}

	err := svc.Start(context.Background())
	require.NoError(t, err)
	assert.True(t, engine.started)
}

func TestService_Start_EngineError(t *testing.T) {
	engine := &mockEngine{name: "test", startErr: errors.New("start failed")}
	svc := &Service{engine: engine, cfg: config.PolicyConfig{}}

	err := svc.Start(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "start failed")
}

func TestService_Start_WithFallback(t *testing.T) {
	primary := &mockEngine{name: "primary", healthy: true}
	fallback := &mockEngine{name: "fallback", healthy: true}
	svc := &Service{engine: primary, fallbackEngine: fallback, cfg: config.PolicyConfig{}}

	err := svc.Start(context.Background())
	require.NoError(t, err)
	assert.True(t, primary.started)
	assert.True(t, fallback.started)
}

func TestService_Start_FallbackError(t *testing.T) {
	primary := &mockEngine{name: "primary", healthy: true}
	fallback := &mockEngine{name: "fallback", startErr: errors.New("fallback failed")}
	svc := &Service{engine: primary, fallbackEngine: fallback, cfg: config.PolicyConfig{}}

	// Should not return error if primary succeeds but fallback fails
	err := svc.Start(context.Background())
	require.NoError(t, err)
}

func TestService_Stop_Success(t *testing.T) {
	engine := &mockEngine{name: "test"}
	svc := &Service{engine: engine, cfg: config.PolicyConfig{}}

	err := svc.Stop()
	require.NoError(t, err)
	assert.True(t, engine.stopped)
}

func TestService_Stop_WithFallback(t *testing.T) {
	primary := &mockEngine{name: "primary"}
	fallback := &mockEngine{name: "fallback"}
	svc := &Service{engine: primary, fallbackEngine: fallback, cfg: config.PolicyConfig{}}

	err := svc.Stop()
	require.NoError(t, err)
	assert.True(t, primary.stopped)
	assert.True(t, fallback.stopped)
}

func TestService_Stop_WithErrors(t *testing.T) {
	primary := &mockEngine{name: "primary", stopErr: errors.New("stop error")}
	fallback := &mockEngine{name: "fallback", stopErr: errors.New("stop error")}
	svc := &Service{engine: primary, fallbackEngine: fallback, cfg: config.PolicyConfig{}}

	// Should still return nil even if stop fails (errors are just logged)
	err := svc.Stop()
	require.NoError(t, err)
}

// =============================================================================
// Evaluate Tests
// =============================================================================

func TestService_Evaluate_Allow(t *testing.T) {
	engine := &mockEngine{
		name: "test",
		evaluateFunc: func(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
			return domain.Allow("test allow"), nil
		},
	}
	svc := &Service{engine: engine, cfg: config.PolicyConfig{}}

	input := &domain.PolicyInput{
		Request: domain.RequestInfo{
			Method: "GET",
			Path:   "/api/test",
		},
	}

	decision, err := svc.Evaluate(context.Background(), input)
	require.NoError(t, err)
	require.NotNil(t, decision)
	assert.True(t, decision.Allowed)
}

func TestService_Evaluate_Deny(t *testing.T) {
	engine := &mockEngine{
		name: "test",
		evaluateFunc: func(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
			return domain.Deny("test deny"), nil
		},
	}
	svc := &Service{engine: engine, cfg: config.PolicyConfig{}}

	input := &domain.PolicyInput{
		Request: domain.RequestInfo{
			Method: "GET",
			Path:   "/api/test",
		},
	}

	decision, err := svc.Evaluate(context.Background(), input)
	require.NoError(t, err)
	require.NotNil(t, decision)
	assert.False(t, decision.Allowed)
}

func TestService_Evaluate_WithCache_Hit(t *testing.T) {
	evalCount := 0
	engine := &mockEngine{
		name: "test",
		evaluateFunc: func(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
			evalCount++
			return domain.Allow("test"), nil
		},
	}
	cache := newMockCache()
	svc := &Service{engine: engine, cache: cache, cfg: config.PolicyConfig{}}

	input := &domain.PolicyInput{
		Request: domain.RequestInfo{
			Method: "GET",
			Path:   "/api/test",
		},
	}

	// First call - should evaluate and cache
	_, err := svc.Evaluate(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, 1, evalCount)

	// Second call - should hit cache
	decision, err := svc.Evaluate(context.Background(), input)
	require.NoError(t, err)
	assert.True(t, decision.Cached)
	assert.Equal(t, 1, evalCount) // Should not have evaluated again
}

func TestService_Evaluate_WithEnhancers(t *testing.T) {
	engine := &mockEngine{
		name: "test",
		evaluateFunc: func(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
			return domain.Allow("test"), nil
		},
	}
	authEnhancer := &mockAuthEnhancer{}
	decisionEnhancer := &mockDecisionEnhancer{
		enhanceFunc: func(ctx context.Context, input *domain.PolicyInput, decision *domain.Decision) error {
			decision.WithMetadata("enhanced", true)
			return nil
		},
	}
	svc := &Service{
		engine:            engine,
		enhancers:         []AuthorizationEnhancer{authEnhancer},
		decisionEnhancers: []DecisionEnhancer{decisionEnhancer},
		cfg:               config.PolicyConfig{},
	}

	input := &domain.PolicyInput{
		Request: domain.RequestInfo{
			Method: "GET",
			Path:   "/api/test",
		},
	}

	decision, err := svc.Evaluate(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, 1, authEnhancer.called)
	assert.Equal(t, 1, decisionEnhancer.called)
	assert.Equal(t, true, decision.Metadata["enhanced"])
}

func TestService_Evaluate_EnhancerError(t *testing.T) {
	engine := &mockEngine{
		name: "test",
		evaluateFunc: func(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
			return domain.Allow("test"), nil
		},
	}
	authEnhancer := &mockAuthEnhancer{
		enhanceFunc: func(ctx context.Context, input *domain.PolicyInput) error {
			return errors.New("enhancer error")
		},
	}
	svc := &Service{
		engine:    engine,
		enhancers: []AuthorizationEnhancer{authEnhancer},
		cfg:       config.PolicyConfig{},
	}

	input := &domain.PolicyInput{
		Request: domain.RequestInfo{
			Method: "GET",
			Path:   "/api/test",
		},
	}

	// Should still succeed - enhancer errors are logged but don't fail
	decision, err := svc.Evaluate(context.Background(), input)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestService_Evaluate_WithFallback(t *testing.T) {
	primary := &mockEngine{
		name: "primary",
		evaluateFunc: func(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
			return nil, errors.New("primary failed")
		},
	}
	fallback := &mockEngine{
		name: "fallback",
		evaluateFunc: func(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
			return domain.Allow("fallback allow"), nil
		},
	}
	svc := &Service{
		engine:         primary,
		fallbackEngine: fallback,
		cfg: config.PolicyConfig{
			Fallback: config.FallbackConfig{
				Enabled: true,
			},
		},
	}

	input := &domain.PolicyInput{
		Request: domain.RequestInfo{
			Method: "GET",
			Path:   "/api/test",
		},
	}

	decision, err := svc.Evaluate(context.Background(), input)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestService_Evaluate_FallbackBehavior_Deny(t *testing.T) {
	primary := &mockEngine{
		name: "primary",
		evaluateFunc: func(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
			return nil, errors.New("primary failed")
		},
	}
	fallback := &mockEngine{
		name: "fallback",
		evaluateFunc: func(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
			return nil, errors.New("fallback also failed")
		},
	}
	svc := &Service{
		engine:         primary,
		fallbackEngine: fallback,
		cfg: config.PolicyConfig{
			Fallback: config.FallbackConfig{
				Enabled:  true,
				Behavior: "deny",
			},
		},
	}

	input := &domain.PolicyInput{
		Request: domain.RequestInfo{
			Method: "GET",
			Path:   "/api/test",
		},
	}

	decision, err := svc.Evaluate(context.Background(), input)
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
	assert.Equal(t, true, decision.Metadata["fallback"])
}

func TestService_Evaluate_FallbackBehavior_Allow(t *testing.T) {
	primary := &mockEngine{
		name: "primary",
		evaluateFunc: func(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
			return nil, errors.New("primary failed")
		},
	}
	fallback := &mockEngine{
		name: "fallback",
		evaluateFunc: func(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
			return nil, errors.New("fallback also failed")
		},
	}
	svc := &Service{
		engine:         primary,
		fallbackEngine: fallback,
		cfg: config.PolicyConfig{
			Fallback: config.FallbackConfig{
				Enabled:  true,
				Behavior: "allow",
			},
		},
	}

	input := &domain.PolicyInput{
		Request: domain.RequestInfo{
			Method: "GET",
			Path:   "/api/test",
		},
	}

	decision, err := svc.Evaluate(context.Background(), input)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, true, decision.Metadata["fallback"])
}

func TestService_Evaluate_NoFallback_ReturnsError(t *testing.T) {
	engine := &mockEngine{
		name: "test",
		evaluateFunc: func(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
			return nil, errors.New("evaluation failed")
		},
	}
	svc := &Service{
		engine: engine,
		cfg:    config.PolicyConfig{},
	}

	input := &domain.PolicyInput{
		Request: domain.RequestInfo{
			Method: "GET",
			Path:   "/api/test",
		},
	}

	decision, err := svc.Evaluate(context.Background(), input)
	require.Error(t, err)
	assert.Nil(t, decision)
}

// =============================================================================
// Other Methods Tests
// =============================================================================

func TestService_Healthy(t *testing.T) {
	engine := &mockEngine{name: "test", healthy: true}
	svc := &Service{engine: engine, cfg: config.PolicyConfig{}}

	assert.True(t, svc.Healthy(context.Background()))

	engine.healthy = false
	assert.False(t, svc.Healthy(context.Background()))
}

func TestService_EngineName(t *testing.T) {
	engine := &mockEngine{name: "test-engine"}
	svc := &Service{engine: engine, cfg: config.PolicyConfig{}}

	assert.Equal(t, "test-engine", svc.EngineName())
}

func TestService_Reload(t *testing.T) {
	engine := &mockReloadableEngine{
		mockEngine: mockEngine{name: "test"},
	}
	svc := &Service{engine: engine, cfg: config.PolicyConfig{}}

	err := svc.Reload(context.Background())
	require.NoError(t, err)
	assert.True(t, engine.reloaded)
}

func TestService_Reload_NonReloadableEngine(t *testing.T) {
	engine := &mockEngine{name: "test"}
	svc := &Service{engine: engine, cfg: config.PolicyConfig{}}

	// Should not error even if engine doesn't implement Reloader
	err := svc.Reload(context.Background())
	require.NoError(t, err)
}

func TestService_Reload_WithFallback(t *testing.T) {
	primary := &mockReloadableEngine{
		mockEngine: mockEngine{name: "primary"},
	}
	fallback := &mockReloadableEngine{
		mockEngine: mockEngine{name: "fallback"},
	}
	svc := &Service{
		engine:         primary,
		fallbackEngine: fallback,
		cfg:            config.PolicyConfig{},
	}

	err := svc.Reload(context.Background())
	require.NoError(t, err)
	assert.True(t, primary.reloaded)
	assert.True(t, fallback.reloaded)
}

func TestService_Reload_FallbackError(t *testing.T) {
	primary := &mockReloadableEngine{
		mockEngine: mockEngine{name: "primary"},
	}
	fallback := &mockReloadableEngine{
		mockEngine: mockEngine{name: "fallback"},
		reloadErr:  errors.New("reload failed"),
	}
	svc := &Service{
		engine:         primary,
		fallbackEngine: fallback,
		cfg:            config.PolicyConfig{},
	}

	// Should succeed even if fallback reload fails
	err := svc.Reload(context.Background())
	require.NoError(t, err)
}

func TestService_Reload_PrimaryError(t *testing.T) {
	primary := &mockReloadableEngine{
		mockEngine: mockEngine{name: "primary"},
		reloadErr:  errors.New("reload failed"),
	}
	svc := &Service{
		engine: primary,
		cfg:    config.PolicyConfig{},
	}

	err := svc.Reload(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reload failed")
}

// =============================================================================
// Cache Key Tests
// =============================================================================

func TestService_ComputeCacheKey(t *testing.T) {
	svc := &Service{cfg: config.PolicyConfig{}}

	input1 := &domain.PolicyInput{
		Request: domain.RequestInfo{
			Method: "GET",
			Path:   "/api/test",
		},
	}
	input2 := &domain.PolicyInput{
		Request: domain.RequestInfo{
			Method: "GET",
			Path:   "/api/test",
		},
	}
	input3 := &domain.PolicyInput{
		Request: domain.RequestInfo{
			Method: "POST",
			Path:   "/api/test",
		},
	}

	key1 := svc.computeCacheKey(input1)
	key2 := svc.computeCacheKey(input2)
	key3 := svc.computeCacheKey(input3)

	// Same inputs should produce same keys
	assert.Equal(t, key1, key2)
	// Different inputs should produce different keys
	assert.NotEqual(t, key1, key3)
}

func TestService_ComputeCacheKey_WithToken(t *testing.T) {
	svc := &Service{cfg: config.PolicyConfig{}}

	input := &domain.PolicyInput{
		Request: domain.RequestInfo{
			Method: "GET",
			Path:   "/api/test",
		},
		Token: &domain.TokenInfo{
			Subject: "user123",
			Roles:   []string{"admin"},
			Scopes:  []string{"read"},
		},
	}

	key := svc.computeCacheKey(input)
	assert.NotEmpty(t, key)

	// Different user should produce different key
	input.Token.Subject = "user456"
	key2 := svc.computeCacheKey(input)
	assert.NotEqual(t, key, key2)
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkService_Evaluate(b *testing.B) {
	engine := &mockEngine{
		name: "test",
		evaluateFunc: func(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
			return domain.Allow("test"), nil
		},
	}
	svc := &Service{engine: engine, cfg: config.PolicyConfig{}}

	input := &domain.PolicyInput{
		Request: domain.RequestInfo{
			Method: "GET",
			Path:   "/api/test",
		},
	}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = svc.Evaluate(ctx, input)
	}
}

func BenchmarkService_Evaluate_WithCache(b *testing.B) {
	engine := &mockEngine{
		name: "test",
		evaluateFunc: func(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
			return domain.Allow("test"), nil
		},
	}
	cache := newMockCache()
	svc := &Service{engine: engine, cache: cache, cfg: config.PolicyConfig{}}

	input := &domain.PolicyInput{
		Request: domain.RequestInfo{
			Method: "GET",
			Path:   "/api/test",
		},
	}
	ctx := context.Background()

	// Warm up cache
	_, _ = svc.Evaluate(ctx, input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = svc.Evaluate(ctx, input)
	}
}

func BenchmarkService_ComputeCacheKey(b *testing.B) {
	svc := &Service{cfg: config.PolicyConfig{}}
	input := &domain.PolicyInput{
		Request: domain.RequestInfo{
			Method: "GET",
			Path:   "/api/users/123/profile",
		},
		Token: &domain.TokenInfo{
			Subject: "user123",
			Roles:   []string{"admin", "user"},
			Scopes:  []string{"read", "write"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		svc.computeCacheKey(input)
	}
}
