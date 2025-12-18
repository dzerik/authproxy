package circuitbreaker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sony/gobreaker/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/your-org/authz-service/internal/config"
)

func TestNewManager(t *testing.T) {
	cfg := config.CircuitBreakerConfig{
		Enabled: true,
		Default: config.CircuitBreakerSettings{
			MaxRequests:      3,
			Interval:         time.Minute,
			Timeout:          30 * time.Second,
			FailureThreshold: 5,
		},
	}

	manager := NewManager(cfg)

	require.NotNil(t, manager)
	assert.Equal(t, cfg, manager.cfg)
	assert.NotNil(t, manager.breakers)
}

func TestNewManager_WithServices(t *testing.T) {
	cfg := config.CircuitBreakerConfig{
		Enabled: true,
		Default: config.CircuitBreakerSettings{
			MaxRequests:      3,
			FailureThreshold: 5,
		},
		Services: map[string]config.CircuitBreakerSettings{
			"keycloak": {
				MaxRequests:      5,
				Timeout:          60 * time.Second,
				FailureThreshold: 10,
			},
			"opa": {
				MaxRequests:      2,
				Timeout:          15 * time.Second,
				FailureThreshold: 3,
			},
		},
	}

	manager := NewManager(cfg)

	require.NotNil(t, manager)
	// Pre-created breakers for configured services
	assert.Len(t, manager.breakers, 2)

	// Check that both services have breakers
	keycloakCB := manager.Get("keycloak")
	assert.NotNil(t, keycloakCB)
	assert.Equal(t, "keycloak", keycloakCB.Name())

	opaCB := manager.Get("opa")
	assert.NotNil(t, opaCB)
	assert.Equal(t, "opa", opaCB.Name())
}

func TestManager_Get_ExistingBreaker(t *testing.T) {
	cfg := config.CircuitBreakerConfig{
		Enabled: true,
		Default: config.CircuitBreakerSettings{
			MaxRequests:      3,
			FailureThreshold: 5,
		},
		Services: map[string]config.CircuitBreakerSettings{
			"existing": {
				MaxRequests:      10,
				FailureThreshold: 3,
			},
		},
	}

	manager := NewManager(cfg)

	// Get existing breaker multiple times
	cb1 := manager.Get("existing")
	cb2 := manager.Get("existing")

	// Should return the same instance
	assert.Same(t, cb1, cb2)
}

func TestManager_Get_NewBreaker(t *testing.T) {
	cfg := config.CircuitBreakerConfig{
		Enabled: true,
		Default: config.CircuitBreakerSettings{
			MaxRequests:      3,
			FailureThreshold: 5,
		},
	}

	manager := NewManager(cfg)

	// Get a new breaker that doesn't exist
	cb := manager.Get("new-service")

	require.NotNil(t, cb)
	assert.Equal(t, "new-service", cb.Name())

	// Should be added to breakers map
	assert.Len(t, manager.breakers, 1)

	// Getting again should return same instance
	cb2 := manager.Get("new-service")
	assert.Same(t, cb, cb2)
}

func TestManager_Get_Concurrent(t *testing.T) {
	cfg := config.CircuitBreakerConfig{
		Enabled: true,
		Default: config.CircuitBreakerSettings{
			MaxRequests:      3,
			FailureThreshold: 5,
		},
	}

	manager := NewManager(cfg)

	var wg sync.WaitGroup
	breakers := make([]*gobreaker.CircuitBreaker[any], 100)

	// Concurrently get the same breaker
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			breakers[idx] = manager.Get("concurrent-service")
		}(i)
	}

	wg.Wait()

	// All should be the same instance
	first := breakers[0]
	for i := 1; i < 100; i++ {
		assert.Same(t, first, breakers[i], "breaker at index %d should be same instance", i)
	}

	// Only one breaker should be created
	assert.Len(t, manager.breakers, 1)
}

func TestManager_Execute_Success(t *testing.T) {
	cfg := config.CircuitBreakerConfig{
		Enabled: true,
		Default: config.CircuitBreakerSettings{
			MaxRequests:      3,
			FailureThreshold: 5,
		},
	}

	manager := NewManager(cfg)
	ctx := context.Background()

	result, err := manager.Execute(ctx, "test-service", func() (any, error) {
		return "success", nil
	})

	require.NoError(t, err)
	assert.Equal(t, "success", result)
}

func TestManager_Execute_Error(t *testing.T) {
	cfg := config.CircuitBreakerConfig{
		Enabled: true,
		Default: config.CircuitBreakerSettings{
			MaxRequests:      3,
			FailureThreshold: 5,
		},
	}

	manager := NewManager(cfg)
	ctx := context.Background()

	expectedErr := errors.New("test error")
	result, err := manager.Execute(ctx, "test-service", func() (any, error) {
		return nil, expectedErr
	})

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, result)
}

func TestManager_Execute_CircuitOpen(t *testing.T) {
	cfg := config.CircuitBreakerConfig{
		Enabled: true,
		Default: config.CircuitBreakerSettings{
			MaxRequests:      1,
			Interval:         time.Minute,
			Timeout:          5 * time.Second,
			FailureThreshold: 2, // Open after 2 failures
		},
	}

	manager := NewManager(cfg)
	ctx := context.Background()

	testErr := errors.New("service unavailable")

	// Cause failures to trip the circuit
	for i := 0; i < 3; i++ {
		manager.Execute(ctx, "failing-service", func() (any, error) {
			return nil, testErr
		})
	}

	// Circuit should be open now
	state := manager.State("failing-service")
	assert.Equal(t, gobreaker.StateOpen, state)

	// Next call should fail with circuit open error
	_, err := manager.Execute(ctx, "failing-service", func() (any, error) {
		return "should not be called", nil
	})

	assert.Error(t, err)
	assert.Equal(t, gobreaker.ErrOpenState, err)
}

func TestExecuteTyped_Success(t *testing.T) {
	cfg := config.CircuitBreakerConfig{
		Enabled: true,
		Default: config.CircuitBreakerSettings{
			MaxRequests:      3,
			FailureThreshold: 5,
		},
	}

	manager := NewManager(cfg)
	ctx := context.Background()

	type Response struct {
		Data string
	}

	result, err := ExecuteTyped[Response](manager, ctx, "typed-service", func() (Response, error) {
		return Response{Data: "hello"}, nil
	})

	require.NoError(t, err)
	assert.Equal(t, "hello", result.Data)
}

func TestExecuteTyped_Error(t *testing.T) {
	cfg := config.CircuitBreakerConfig{
		Enabled: true,
		Default: config.CircuitBreakerSettings{
			MaxRequests:      3,
			FailureThreshold: 5,
		},
	}

	manager := NewManager(cfg)
	ctx := context.Background()

	type Response struct {
		Data string
	}

	expectedErr := errors.New("typed error")
	result, err := ExecuteTyped[Response](manager, ctx, "typed-service", func() (Response, error) {
		return Response{}, expectedErr
	})

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Equal(t, Response{}, result)
}

func TestManager_State(t *testing.T) {
	cfg := config.CircuitBreakerConfig{
		Enabled: true,
		Default: config.CircuitBreakerSettings{
			MaxRequests:      3,
			FailureThreshold: 5,
		},
	}

	manager := NewManager(cfg)

	// Initial state should be closed
	state := manager.State("test-service")
	assert.Equal(t, gobreaker.StateClosed, state)
}

func TestManager_Counts(t *testing.T) {
	cfg := config.CircuitBreakerConfig{
		Enabled: true,
		Default: config.CircuitBreakerSettings{
			MaxRequests:      3,
			FailureThreshold: 5,
		},
	}

	manager := NewManager(cfg)
	ctx := context.Background()

	// Execute some successful calls
	for i := 0; i < 3; i++ {
		manager.Execute(ctx, "count-service", func() (any, error) {
			return "ok", nil
		})
	}

	// Execute some failures
	for i := 0; i < 2; i++ {
		manager.Execute(ctx, "count-service", func() (any, error) {
			return nil, errors.New("fail")
		})
	}

	counts := manager.Counts("count-service")
	assert.Equal(t, uint32(5), counts.Requests)
	assert.Equal(t, uint32(3), counts.TotalSuccesses)
	assert.Equal(t, uint32(2), counts.TotalFailures)
	assert.Equal(t, uint32(2), counts.ConsecutiveFailures)
}

func TestManager_States(t *testing.T) {
	cfg := config.CircuitBreakerConfig{
		Enabled: true,
		Default: config.CircuitBreakerSettings{
			MaxRequests:      1,
			FailureThreshold: 1,
			Timeout:          5 * time.Second,
		},
		Services: map[string]config.CircuitBreakerSettings{
			"service-a": {MaxRequests: 1, FailureThreshold: 1, Timeout: 5 * time.Second},
			"service-b": {MaxRequests: 1, FailureThreshold: 1, Timeout: 5 * time.Second},
		},
	}

	manager := NewManager(cfg)
	ctx := context.Background()

	// Trip service-a circuit
	manager.Execute(ctx, "service-a", func() (any, error) {
		return nil, errors.New("fail")
	})
	manager.Execute(ctx, "service-a", func() (any, error) {
		return nil, errors.New("fail")
	})

	states := manager.States()

	assert.Len(t, states, 2)
	assert.Equal(t, gobreaker.StateOpen, states["service-a"])
	assert.Equal(t, gobreaker.StateClosed, states["service-b"])
}

func TestStateToString(t *testing.T) {
	tests := []struct {
		state    gobreaker.State
		expected string
	}{
		{gobreaker.StateClosed, "closed"},
		{gobreaker.StateHalfOpen, "half-open"},
		{gobreaker.StateOpen, "open"},
		{gobreaker.State(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := stateToString(tt.state)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestManager_CircuitBreakerLifecycle(t *testing.T) {
	cfg := config.CircuitBreakerConfig{
		Enabled: true,
		Default: config.CircuitBreakerSettings{
			MaxRequests:      1,
			Interval:         time.Minute,
			Timeout:          100 * time.Millisecond, // Short timeout for testing
			FailureThreshold: 2,
			OnStateChange:    true,
		},
	}

	manager := NewManager(cfg)
	ctx := context.Background()

	// 1. Initial state should be closed
	assert.Equal(t, gobreaker.StateClosed, manager.State("lifecycle-test"))

	// 2. Cause failures to trip the circuit
	for i := 0; i < 3; i++ {
		manager.Execute(ctx, "lifecycle-test", func() (any, error) {
			return nil, errors.New("failure")
		})
	}

	// 3. Circuit should be open
	assert.Equal(t, gobreaker.StateOpen, manager.State("lifecycle-test"))

	// 4. Wait for timeout to transition to half-open
	time.Sleep(150 * time.Millisecond)

	// 5. Next request will transition to half-open
	// A successful request in half-open state should close the circuit
	_, err := manager.Execute(ctx, "lifecycle-test", func() (any, error) {
		return "success", nil
	})
	require.NoError(t, err)

	// 6. Circuit should be closed again
	assert.Equal(t, gobreaker.StateClosed, manager.State("lifecycle-test"))
}

func BenchmarkManager_Get(b *testing.B) {
	cfg := config.CircuitBreakerConfig{
		Enabled: true,
		Default: config.CircuitBreakerSettings{
			MaxRequests:      3,
			FailureThreshold: 5,
		},
	}

	manager := NewManager(cfg)

	// Pre-create the breaker
	manager.Get("benchmark-service")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.Get("benchmark-service")
	}
}

func BenchmarkManager_Execute_Success(b *testing.B) {
	cfg := config.CircuitBreakerConfig{
		Enabled: true,
		Default: config.CircuitBreakerSettings{
			MaxRequests:      3,
			FailureThreshold: 5,
		},
	}

	manager := NewManager(cfg)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.Execute(ctx, "benchmark-service", func() (any, error) {
			return "result", nil
		})
	}
}

func BenchmarkExecuteTyped(b *testing.B) {
	cfg := config.CircuitBreakerConfig{
		Enabled: true,
		Default: config.CircuitBreakerSettings{
			MaxRequests:      3,
			FailureThreshold: 5,
		},
	}

	manager := NewManager(cfg)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExecuteTyped[string](manager, ctx, "benchmark-service", func() (string, error) {
			return "result", nil
		})
	}
}

func BenchmarkManager_Get_Concurrent(b *testing.B) {
	cfg := config.CircuitBreakerConfig{
		Enabled: true,
		Default: config.CircuitBreakerSettings{
			MaxRequests:      3,
			FailureThreshold: 5,
		},
	}

	manager := NewManager(cfg)
	manager.Get("benchmark-service")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			manager.Get("benchmark-service")
		}
	})
}
