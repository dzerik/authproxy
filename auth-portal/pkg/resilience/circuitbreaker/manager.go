// Package circuitbreaker provides circuit breaker functionality using sony/gobreaker.
package circuitbreaker

import (
	"context"
	"sync"
	"time"

	"github.com/sony/gobreaker/v2"
	"go.uber.org/zap"

	"github.com/dzerik/auth-portal/pkg/logger"
)

// State represents the circuit breaker state.
type State = gobreaker.State

// States
const (
	StateClosed   = gobreaker.StateClosed
	StateHalfOpen = gobreaker.StateHalfOpen
	StateOpen     = gobreaker.StateOpen
)

// Config holds circuit breaker configuration.
type Config struct {
	// Enabled enables circuit breaker
	Enabled bool `yaml:"enabled" mapstructure:"enabled"`
	// Default settings for all circuit breakers
	Default Settings `yaml:"default" mapstructure:"default"`
	// Services holds per-service circuit breaker settings
	Services map[string]Settings `yaml:"services" mapstructure:"services"`
}

// Settings holds settings for a single circuit breaker.
type Settings struct {
	// MaxRequests is the maximum number of requests in half-open state
	MaxRequests uint32 `yaml:"max_requests" mapstructure:"max_requests"`
	// Interval is the cyclic period for clearing counts in closed state
	Interval time.Duration `yaml:"interval" mapstructure:"interval"`
	// Timeout is the period of open state before switching to half-open
	Timeout time.Duration `yaml:"timeout" mapstructure:"timeout"`
	// FailureThreshold is the number of consecutive failures to open circuit
	FailureThreshold uint32 `yaml:"failure_threshold" mapstructure:"failure_threshold"`
	// SuccessThreshold is the number of consecutive successes to close circuit
	SuccessThreshold uint32 `yaml:"success_threshold" mapstructure:"success_threshold"`
	// OnStateChange enables logging on state changes
	OnStateChange bool `yaml:"on_state_change" mapstructure:"on_state_change"`
}

// DefaultConfig returns default circuit breaker configuration.
func DefaultConfig() Config {
	return Config{
		Enabled: true,
		Default: Settings{
			MaxRequests:      3,
			Interval:         60 * time.Second,
			Timeout:          30 * time.Second,
			FailureThreshold: 5,
			SuccessThreshold: 2,
			OnStateChange:    true,
		},
		Services: make(map[string]Settings),
	}
}

// Manager manages multiple circuit breakers for different services.
type Manager struct {
	cfg      Config
	breakers map[string]*gobreaker.CircuitBreaker[any]
	mu       sync.RWMutex
}

// NewManager creates a new circuit breaker manager.
func NewManager(cfg Config) *Manager {
	m := &Manager{
		cfg:      cfg,
		breakers: make(map[string]*gobreaker.CircuitBreaker[any]),
	}

	// Pre-create breakers for configured services
	for name, settings := range cfg.Services {
		m.breakers[name] = m.createBreaker(name, settings)
	}

	return m
}

// Get returns or creates a circuit breaker for the given service name.
func (m *Manager) Get(name string) *gobreaker.CircuitBreaker[any] {
	m.mu.RLock()
	cb, exists := m.breakers[name]
	m.mu.RUnlock()

	if exists {
		return cb
	}

	// Create new breaker with default settings
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	if cb, exists = m.breakers[name]; exists {
		return cb
	}

	settings := m.cfg.Default
	if svcSettings, ok := m.cfg.Services[name]; ok {
		settings = svcSettings
	}

	cb = m.createBreaker(name, settings)
	m.breakers[name] = cb
	return cb
}

// createBreaker creates a new circuit breaker with the given settings.
func (m *Manager) createBreaker(name string, settings Settings) *gobreaker.CircuitBreaker[any] {
	return gobreaker.NewCircuitBreaker[any](gobreaker.Settings{
		Name:        name,
		MaxRequests: settings.MaxRequests,
		Interval:    settings.Interval,
		Timeout:     settings.Timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= uint32(settings.FailureThreshold)
		},
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			if settings.OnStateChange {
				logger.Warn("circuit breaker state changed",
					zap.String("service", name),
					zap.String("from", stateToString(from)),
					zap.String("to", stateToString(to)),
				)
			}
		},
	})
}

// Execute executes a function with circuit breaker protection.
func (m *Manager) Execute(ctx context.Context, name string, fn func() (any, error)) (any, error) {
	cb := m.Get(name)
	return cb.Execute(fn)
}

// ExecuteTyped executes a typed function with circuit breaker protection.
func ExecuteTyped[T any](m *Manager, ctx context.Context, name string, fn func() (T, error)) (T, error) {
	cb := m.Get(name)
	result, err := cb.Execute(func() (any, error) {
		return fn()
	})
	if err != nil {
		var zero T
		return zero, err
	}
	return result.(T), nil
}

// State returns the current state of a circuit breaker.
func (m *Manager) State(name string) gobreaker.State {
	cb := m.Get(name)
	return cb.State()
}

// Counts returns the current counts for a circuit breaker.
func (m *Manager) Counts(name string) gobreaker.Counts {
	cb := m.Get(name)
	return cb.Counts()
}

// States returns all circuit breaker states.
func (m *Manager) States() map[string]gobreaker.State {
	m.mu.RLock()
	defer m.mu.RUnlock()

	states := make(map[string]gobreaker.State, len(m.breakers))
	for name, cb := range m.breakers {
		states[name] = cb.State()
	}
	return states
}

// IsOpen checks if the circuit breaker for a service is open.
func (m *Manager) IsOpen(name string) bool {
	return m.State(name) == StateOpen
}

// stateToString converts circuit breaker state to string.
func stateToString(state gobreaker.State) string {
	switch state {
	case gobreaker.StateClosed:
		return "closed"
	case gobreaker.StateHalfOpen:
		return "half-open"
	case gobreaker.StateOpen:
		return "open"
	default:
		return "unknown"
	}
}
