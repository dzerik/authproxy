package circuitbreaker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if !cfg.Enabled {
		t.Error("DefaultConfig should have Enabled = true")
	}

	if cfg.Default.MaxRequests != 3 {
		t.Errorf("DefaultConfig.Default.MaxRequests = %d, want 3", cfg.Default.MaxRequests)
	}

	if cfg.Default.Interval != 60*time.Second {
		t.Errorf("DefaultConfig.Default.Interval = %v, want 60s", cfg.Default.Interval)
	}

	if cfg.Default.Timeout != 30*time.Second {
		t.Errorf("DefaultConfig.Default.Timeout = %v, want 30s", cfg.Default.Timeout)
	}

	if cfg.Default.FailureThreshold != 5 {
		t.Errorf("DefaultConfig.Default.FailureThreshold = %d, want 5", cfg.Default.FailureThreshold)
	}

	if cfg.Default.SuccessThreshold != 2 {
		t.Errorf("DefaultConfig.Default.SuccessThreshold = %d, want 2", cfg.Default.SuccessThreshold)
	}

	if !cfg.Default.OnStateChange {
		t.Error("DefaultConfig.Default.OnStateChange should be true")
	}

	if cfg.Services == nil {
		t.Error("DefaultConfig.Services should not be nil")
	}
}

func TestNewManager(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg)

	if m == nil {
		t.Fatal("NewManager returned nil")
	}

	if m.breakers == nil {
		t.Error("NewManager should initialize breakers map")
	}
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
	if len(m.breakers) != 2 {
		t.Errorf("Expected 2 pre-created breakers, got %d", len(m.breakers))
	}

	// Check specific breakers exist
	if _, exists := m.breakers["service-a"]; !exists {
		t.Error("service-a breaker should be pre-created")
	}
	if _, exists := m.breakers["service-b"]; !exists {
		t.Error("service-b breaker should be pre-created")
	}
}

func TestManager_Get(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg)

	cb := m.Get("test-service")

	if cb == nil {
		t.Fatal("Get returned nil circuit breaker")
	}

	// Getting same service should return same breaker
	cb2 := m.Get("test-service")
	if cb != cb2 {
		t.Error("Get should return same breaker for same service name")
	}

	// Different service should get different breaker
	cb3 := m.Get("other-service")
	if cb == cb3 {
		t.Error("Get should return different breaker for different service name")
	}
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
	if cb == nil {
		t.Fatal("Get returned nil for custom-service")
	}

	// Get a service without custom settings (should use defaults)
	cb2 := m.Get("default-service")
	if cb2 == nil {
		t.Fatal("Get returned nil for default-service")
	}
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
			if cb == nil {
				t.Error("Get returned nil")
			}
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

	if count != 1 {
		t.Errorf("Expected 1 breaker for concurrent-service, got %d", count)
	}
}

func TestManager_Execute_Success(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg)

	result, err := m.Execute(context.Background(), "test-service", func() (any, error) {
		return "success", nil
	})

	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if result != "success" {
		t.Errorf("Execute result = %v, want 'success'", result)
	}
}

func TestManager_Execute_Failure(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg)

	expectedErr := errors.New("test error")

	result, err := m.Execute(context.Background(), "test-service", func() (any, error) {
		return nil, expectedErr
	})

	if err != expectedErr {
		t.Errorf("Execute error = %v, want %v", err, expectedErr)
	}

	if result != nil {
		t.Errorf("Execute result = %v, want nil", result)
	}
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
	if m.State("failing-service") != StateOpen {
		t.Errorf("Expected circuit to be open, got %v", m.State("failing-service"))
	}
}

func TestExecuteTyped(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg)

	t.Run("success", func(t *testing.T) {
		result, err := ExecuteTyped[string](m, context.Background(), "typed-service", func() (string, error) {
			return "typed result", nil
		})

		if err != nil {
			t.Fatalf("ExecuteTyped failed: %v", err)
		}

		if result != "typed result" {
			t.Errorf("ExecuteTyped result = %v, want 'typed result'", result)
		}
	})

	t.Run("failure", func(t *testing.T) {
		expectedErr := errors.New("typed error")

		result, err := ExecuteTyped[string](m, context.Background(), "typed-service", func() (string, error) {
			return "", expectedErr
		})

		if err != expectedErr {
			t.Errorf("ExecuteTyped error = %v, want %v", err, expectedErr)
		}

		if result != "" {
			t.Errorf("ExecuteTyped result = %v, want empty string", result)
		}
	})

	t.Run("int type", func(t *testing.T) {
		result, err := ExecuteTyped[int](m, context.Background(), "int-service", func() (int, error) {
			return 42, nil
		})

		if err != nil {
			t.Fatalf("ExecuteTyped failed: %v", err)
		}

		if result != 42 {
			t.Errorf("ExecuteTyped result = %v, want 42", result)
		}
	})
}

func TestManager_State(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg)

	// New circuit should be closed
	state := m.State("new-service")
	if state != StateClosed {
		t.Errorf("New circuit state = %v, want StateClosed", state)
	}
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
	if counts.Requests < 5 {
		t.Errorf("Counts.Requests = %d, want >= 5", counts.Requests)
	}
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

	if len(states) < 2 {
		t.Errorf("States() returned %d states, want >= 2", len(states))
	}

	for name, state := range states {
		if state != StateClosed {
			t.Errorf("Service %s state = %v, want StateClosed", name, state)
		}
	}
}

func TestManager_IsOpen(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Default.FailureThreshold = 1
	m := NewManager(cfg)

	// Initially should be closed
	if m.IsOpen("test-service") {
		t.Error("New circuit should not be open")
	}

	// Fail the circuit
	_, _ = m.Execute(context.Background(), "test-service", func() (any, error) {
		return nil, errors.New("failure")
	})

	// Should be open now
	if !m.IsOpen("test-service") {
		t.Error("Circuit should be open after failure")
	}
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
			if result != tt.expected {
				t.Errorf("stateToString(%v) = %s, want %s", tt.state, result, tt.expected)
			}
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

	if settings.MaxRequests != 10 {
		t.Errorf("MaxRequests = %d, want 10", settings.MaxRequests)
	}
	if settings.Interval != 30*time.Second {
		t.Errorf("Interval = %v, want 30s", settings.Interval)
	}
	if settings.Timeout != 15*time.Second {
		t.Errorf("Timeout = %v, want 15s", settings.Timeout)
	}
	if settings.FailureThreshold != 5 {
		t.Errorf("FailureThreshold = %d, want 5", settings.FailureThreshold)
	}
	if settings.SuccessThreshold != 2 {
		t.Errorf("SuccessThreshold = %d, want 2", settings.SuccessThreshold)
	}
	if !settings.OnStateChange {
		t.Error("OnStateChange should be true")
	}
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

	if !cfg.Enabled {
		t.Error("Config.Enabled should be true")
	}

	if cfg.Default.MaxRequests != 5 {
		t.Errorf("Config.Default.MaxRequests = %d, want 5", cfg.Default.MaxRequests)
	}

	if svc, ok := cfg.Services["custom"]; !ok {
		t.Error("Config.Services should contain 'custom'")
	} else if svc.MaxRequests != 10 {
		t.Errorf("Config.Services['custom'].MaxRequests = %d, want 10", svc.MaxRequests)
	}
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
