package circuitbreaker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.True(t, cfg.Enabled)
	assert.Equal(t, uint32(3), cfg.Default.MaxRequests)
	assert.Equal(t, 60*time.Second, cfg.Default.Interval)
	assert.Equal(t, 30*time.Second, cfg.Default.Timeout)
	assert.Equal(t, uint32(5), cfg.Default.FailureThreshold)
	assert.Equal(t, uint32(2), cfg.Default.SuccessThreshold)
	assert.True(t, cfg.Default.OnStateChange)
	assert.NotNil(t, cfg.Services)
}

func TestNewManager(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg)

	require.NotNil(t, m)
	assert.NotNil(t, m.breakers)
}

func TestNewManager_PreCreatedBreakers(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Services = map[string]Settings{
		"service-a": {
			MaxRequests:      5,
			Interval:         30 * time.Second,
			Timeout:          10 * time.Second,
			FailureThreshold: 3,
			SuccessThreshold: 1,
		},
		"service-b": {
			MaxRequests:      10,
			Interval:         60 * time.Second,
			Timeout:          20 * time.Second,
			FailureThreshold: 5,
			SuccessThreshold: 2,
		},
	}

	m := NewManager(cfg)

	// Check that breakers are pre-created
	assert.Len(t, m.breakers, 2)

	// Check specific breakers exist
	_, exists := m.breakers["service-a"]
	assert.True(t, exists)
	_, exists = m.breakers["service-b"]
	assert.True(t, exists)
}

func TestManager_Get(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg)

	cb := m.Get("test-service")

	require.NotNil(t, cb)

	// Getting same service should return same breaker
	cb2 := m.Get("test-service")
	assert.Equal(t, cb, cb2)

	// Different service should get different breaker
	cb3 := m.Get("other-service")
	assert.NotEqual(t, cb, cb3)
}

func TestManager_Get_ServiceSettings(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Services = map[string]Settings{
		"custom-service": {
			MaxRequests:      10,
			Interval:         120 * time.Second,
			Timeout:          60 * time.Second,
			FailureThreshold: 10,
			SuccessThreshold: 5,
		},
	}

	m := NewManager(cfg)

	// Get the pre-created breaker with custom settings
	cb := m.Get("custom-service")
	require.NotNil(t, cb)

	// Get a service without custom settings (should use defaults)
	cb2 := m.Get("default-service")
	require.NotNil(t, cb2)
}

func TestManager_Get_ConcurrentAccess(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg)

	const numGoroutines = 100
	var wg sync.WaitGroup

	// Concurrent gets for same service
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			cb := m.Get("concurrent-service")
			require.NotNil(t, cb)
		}()
	}
	wg.Wait()

	// Should still have only one breaker for this service
	m.mu.RLock()
	count := 0
	for name := range m.breakers {
		if name == "concurrent-service" {
			count++
		}
	}
	m.mu.RUnlock()

	assert.Equal(t, 1, count)
}

func TestManager_Execute_Success(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg)

	result, err := m.Execute(context.Background(), "test-service", func() (any, error) {
		return "success", nil
	})

	require.NoError(t, err)
	assert.Equal(t, "success", result)
}

func TestManager_Execute_Failure(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg)

	expectedErr := errors.New("test error")

	result, err := m.Execute(context.Background(), "test-service", func() (any, error) {
		return nil, expectedErr
	})

	assert.Equal(t, expectedErr, err)
	assert.Nil(t, result)
}

func TestManager_Execute_CircuitOpens(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Default.FailureThreshold = 2
	cfg.Default.Timeout = 1 * time.Second
	m := NewManager(cfg)

	testErr := errors.New("test error")

	// Execute failures to open the circuit
	for i := 0; i < 3; i++ {
		_, _ = m.Execute(context.Background(), "failing-service", func() (any, error) {
			return nil, testErr
		})
	}

	// Circuit should be open now
	assert.Equal(t, StateOpen, m.State("failing-service"))
}

func TestExecuteTyped(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg)

	t.Run("success", func(t *testing.T) {
		result, err := ExecuteTyped[string](m, context.Background(), "typed-service", func() (string, error) {
			return "typed result", nil
		})

		require.NoError(t, err)
		assert.Equal(t, "typed result", result)
	})

	t.Run("failure", func(t *testing.T) {
		expectedErr := errors.New("typed error")

		result, err := ExecuteTyped[string](m, context.Background(), "typed-service", func() (string, error) {
			return "", expectedErr
		})

		assert.Equal(t, expectedErr, err)
		assert.Empty(t, result)
	})

	t.Run("int type", func(t *testing.T) {
		result, err := ExecuteTyped[int](m, context.Background(), "int-service", func() (int, error) {
			return 42, nil
		})

		require.NoError(t, err)
		assert.Equal(t, 42, result)
	})
}

func TestManager_State(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg)

	// New circuit should be closed
	state := m.State("new-service")
	assert.Equal(t, StateClosed, state)
}

func TestManager_Counts(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg)

	// Execute some successful requests
	for i := 0; i < 5; i++ {
		_, _ = m.Execute(context.Background(), "count-service", func() (any, error) {
			return nil, nil
		})
	}

	counts := m.Counts("count-service")
	assert.GreaterOrEqual(t, counts.Requests, uint32(5))
}

func TestManager_States(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Services = map[string]Settings{
		"service-a": cfg.Default,
		"service-b": cfg.Default,
	}
	m := NewManager(cfg)

	// Also create a dynamic one
	_ = m.Get("service-c")

	states := m.States()

	assert.GreaterOrEqual(t, len(states), 2)

	for name, state := range states {
		assert.Equal(t, StateClosed, state, "Service %s state should be closed", name)
	}
}

func TestManager_IsOpen(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Default.FailureThreshold = 1
	m := NewManager(cfg)

	// Initially should be closed
	assert.False(t, m.IsOpen("test-service"))

	// Fail the circuit
	_, _ = m.Execute(context.Background(), "test-service", func() (any, error) {
		return nil, errors.New("failure")
	})

	// Should be open now
	assert.True(t, m.IsOpen("test-service"))
}

func TestStateToString(t *testing.T) {
	tests := []struct {
		state    State
		expected string
	}{
		{StateClosed, "closed"},
		{StateHalfOpen, "half-open"},
		{StateOpen, "open"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := stateToString(tt.state)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSettings(t *testing.T) {
	settings := Settings{
		MaxRequests:      10,
		Interval:         30 * time.Second,
		Timeout:          15 * time.Second,
		FailureThreshold: 5,
		SuccessThreshold: 2,
		OnStateChange:    true,
	}

	assert.Equal(t, uint32(10), settings.MaxRequests)
	assert.Equal(t, 30*time.Second, settings.Interval)
	assert.Equal(t, 15*time.Second, settings.Timeout)
	assert.Equal(t, uint32(5), settings.FailureThreshold)
	assert.Equal(t, uint32(2), settings.SuccessThreshold)
	assert.True(t, settings.OnStateChange)
}

func TestConfig(t *testing.T) {
	cfg := Config{
		Enabled: true,
		Default: Settings{
			MaxRequests:      5,
			FailureThreshold: 3,
		},
		Services: map[string]Settings{
			"custom": {
				MaxRequests:      10,
				FailureThreshold: 5,
			},
		},
	}

	assert.True(t, cfg.Enabled)
	assert.Equal(t, uint32(5), cfg.Default.MaxRequests)

	svc, ok := cfg.Services["custom"]
	require.True(t, ok)
	assert.Equal(t, uint32(10), svc.MaxRequests)
}

func BenchmarkManager_Get(b *testing.B) {
	cfg := DefaultConfig()
	m := NewManager(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.Get("bench-service")
	}
}

func BenchmarkManager_Execute(b *testing.B) {
	cfg := DefaultConfig()
	m := NewManager(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.Execute(context.Background(), "bench-service", func() (any, error) {
			return nil, nil
		})
	}
}

func BenchmarkManager_GetConcurrent(b *testing.B) {
	cfg := DefaultConfig()
	m := NewManager(cfg)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = m.Get("bench-service")
		}
	})
}
