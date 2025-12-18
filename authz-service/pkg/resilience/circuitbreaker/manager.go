// Package circuitbreaker provides circuit breaker functionality using sony/gobreaker.
package circuitbreaker

import (
	"context"
	"sync"

	"github.com/sony/gobreaker/v2"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/pkg/logger"
)

// State represents the circuit breaker state.
type State = gobreaker.State

// States
const (
	StateClosed    = gobreaker.StateClosed
	StateHalfOpen  = gobreaker.StateHalfOpen
	StateOpen      = gobreaker.StateOpen
)

// Manager manages multiple circuit breakers for different services.
type Manager struct {
	cfg      config.CircuitBreakerConfig
	breakers map[string]*gobreaker.CircuitBreaker[any]
	mu       sync.RWMutex
}

// NewManager creates a new circuit breaker manager.
func NewManager(cfg config.CircuitBreakerConfig) *Manager {
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
func (m *Manager) createBreaker(name string, settings config.CircuitBreakerSettings) *gobreaker.CircuitBreaker[any] {
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
					logger.String("service", name),
					logger.String("from", stateToString(from)),
					logger.String("to", stateToString(to)),
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
