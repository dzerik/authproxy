package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNewListenerManager(t *testing.T) {
	m := NewListenerManager()

	require.NotNil(t, m)
	assert.Equal(t, 0, m.Count())
	assert.Equal(t, 30*time.Second, m.shutdownTimeout)
}

func TestNewListenerManager_WithOptions(t *testing.T) {
	log := zap.NewNop()

	m := NewListenerManager(
		WithShutdownTimeout(60*time.Second),
		WithListenerLogger(log),
	)

	require.NotNil(t, m)
	assert.Equal(t, 60*time.Second, m.shutdownTimeout)
}

func TestListenerManager_AddListener(t *testing.T) {
	m := NewListenerManager()
	ctx := context.Background()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	err := m.AddListener(ctx, ListenerConfig{
		Name:    "test-listener",
		Type:    ListenerTypeProxy,
		Address: "127.0.0.1:0", // Random port
		Handler: handler,
	})
	require.NoError(t, err)
	defer m.Shutdown(ctx)

	// Verify listener was added
	assert.Equal(t, 1, m.Count())
	assert.True(t, m.HasListener("test-listener"))

	// Wait for listener to start (goroutine switches status to running)
	time.Sleep(10 * time.Millisecond)

	// Verify listener info
	listeners := m.GetListeners()
	require.Len(t, listeners, 1)
	assert.Equal(t, "test-listener", listeners[0].Name)
	assert.Equal(t, "proxy", listeners[0].Type)
	assert.Equal(t, "running", listeners[0].Status)
}

func TestListenerManager_AddListener_DuplicateName(t *testing.T) {
	m := NewListenerManager()
	ctx := context.Background()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	err := m.AddListener(ctx, ListenerConfig{
		Name:    "test-listener",
		Type:    ListenerTypeProxy,
		Address: "127.0.0.1:0",
		Handler: handler,
	})
	require.NoError(t, err)
	defer m.Shutdown(ctx)

	// Try to add another listener with the same name
	err = m.AddListener(ctx, ListenerConfig{
		Name:    "test-listener",
		Type:    ListenerTypeProxy,
		Address: "127.0.0.1:0",
		Handler: handler,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestListenerManager_AddListener_Validation(t *testing.T) {
	m := NewListenerManager()
	ctx := context.Background()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	tests := []struct {
		name   string
		cfg    ListenerConfig
		errMsg string
	}{
		{
			name:   "empty name",
			cfg:    ListenerConfig{Address: ":8080", Handler: handler},
			errMsg: "name is required",
		},
		{
			name:   "empty address",
			cfg:    ListenerConfig{Name: "test", Handler: handler},
			errMsg: "address is required",
		},
		{
			name:   "nil handler",
			cfg:    ListenerConfig{Name: "test", Address: ":8080"},
			errMsg: "handler is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.AddListener(ctx, tt.cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestListenerManager_RemoveListener(t *testing.T) {
	m := NewListenerManager()
	ctx := context.Background()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	err := m.AddListener(ctx, ListenerConfig{
		Name:    "test-listener",
		Type:    ListenerTypeProxy,
		Address: "127.0.0.1:0",
		Handler: handler,
	})
	require.NoError(t, err)

	// Wait for listener to start
	time.Sleep(10 * time.Millisecond)

	// Remove the listener
	err = m.RemoveListener(ctx, "test-listener")
	require.NoError(t, err)

	// Verify listener was removed
	assert.Equal(t, 0, m.Count())
	assert.False(t, m.HasListener("test-listener"))
}

func TestListenerManager_RemoveListener_NotFound(t *testing.T) {
	m := NewListenerManager()
	ctx := context.Background()

	err := m.RemoveListener(ctx, "nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestListenerManager_UpdateHandler(t *testing.T) {
	m := NewListenerManager()
	ctx := context.Background()

	handler1 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("handler1"))
	})

	handler2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("handler2"))
	})

	err := m.AddListener(ctx, ListenerConfig{
		Name:    "test-listener",
		Type:    ListenerTypeProxy,
		Address: "127.0.0.1:0",
		Handler: handler1,
	})
	require.NoError(t, err)
	defer m.Shutdown(ctx)

	// Wait for listener to start
	time.Sleep(10 * time.Millisecond)

	// Update handler
	err = m.UpdateHandler("test-listener", handler2)
	require.NoError(t, err)
}

func TestListenerManager_UpdateHandler_NotFound(t *testing.T) {
	m := NewListenerManager()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	err := m.UpdateHandler("nonexistent", handler)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestListenerManager_GetListener(t *testing.T) {
	m := NewListenerManager()
	ctx := context.Background()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	err := m.AddListener(ctx, ListenerConfig{
		Name:    "test-listener",
		Type:    ListenerTypeEgress,
		Address: "127.0.0.1:0",
		Handler: handler,
		Metadata: map[string]string{
			"category": "external",
		},
	})
	require.NoError(t, err)
	defer m.Shutdown(ctx)

	// Wait for listener to start
	time.Sleep(10 * time.Millisecond)

	managed, exists := m.GetListener("test-listener")
	require.True(t, exists)
	require.NotNil(t, managed)

	assert.Equal(t, "test-listener", managed.Name)
	assert.Equal(t, ListenerTypeEgress, managed.Type)
	assert.Equal(t, "external", managed.Metadata["category"])
}

func TestListenerManager_GetListenerStats(t *testing.T) {
	m := NewListenerManager()
	ctx := context.Background()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	err := m.AddListener(ctx, ListenerConfig{
		Name:    "test-listener",
		Type:    ListenerTypeProxy,
		Address: "127.0.0.1:0",
		Handler: handler,
	})
	require.NoError(t, err)
	defer m.Shutdown(ctx)

	// Wait for listener to start
	time.Sleep(10 * time.Millisecond)

	stats, err := m.GetListenerStats("test-listener")
	require.NoError(t, err)
	require.NotNil(t, stats)

	assert.Equal(t, "test-listener", stats.Name)
	assert.Equal(t, "proxy", stats.Type)
	assert.Equal(t, "running", stats.Status)
	assert.NotEmpty(t, stats.Uptime)
}

func TestListenerManager_GetListenerStats_NotFound(t *testing.T) {
	m := NewListenerManager()

	stats, err := m.GetListenerStats("nonexistent")
	assert.Error(t, err)
	assert.Nil(t, stats)
}

func TestListenerManager_DrainListener(t *testing.T) {
	m := NewListenerManager()
	ctx := context.Background()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	err := m.AddListener(ctx, ListenerConfig{
		Name:    "test-listener",
		Type:    ListenerTypeProxy,
		Address: "127.0.0.1:0",
		Handler: handler,
	})
	require.NoError(t, err)
	defer m.Shutdown(ctx)

	// Wait for listener to start
	time.Sleep(10 * time.Millisecond)

	// Drain the listener
	err = m.DrainListener("test-listener")
	require.NoError(t, err)

	// Check status
	managed, _ := m.GetListener("test-listener")
	assert.Equal(t, ListenerStatusDraining, managed.Status)
}

func TestListenerManager_DrainListener_NotFound(t *testing.T) {
	m := NewListenerManager()

	err := m.DrainListener("nonexistent")
	assert.Error(t, err)
}

func TestListenerManager_Shutdown(t *testing.T) {
	m := NewListenerManager()
	ctx := context.Background()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	// Add multiple listeners
	for i := 0; i < 3; i++ {
		err := m.AddListener(ctx, ListenerConfig{
			Name:    "listener-" + string(rune('a'+i)),
			Type:    ListenerTypeProxy,
			Address: "127.0.0.1:0",
			Handler: handler,
		})
		require.NoError(t, err)
	}

	assert.Equal(t, 3, m.Count())

	// Shutdown all
	err := m.Shutdown(ctx)
	require.NoError(t, err)

	assert.Equal(t, 0, m.Count())
}

func TestSwappableHandler(t *testing.T) {
	handler1 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("handler1"))
	})

	handler2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("handler2"))
	})

	sh := newSwappableHandler(handler1)

	// Test initial handler
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	sh.ServeHTTP(w, req)
	assert.Equal(t, "handler1", w.Body.String())

	// Swap handler
	sh.Swap(handler2)

	// Test swapped handler
	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	w = httptest.NewRecorder()
	sh.ServeHTTP(w, req)
	assert.Equal(t, "handler2", w.Body.String())
}

func TestManagedListener_Metrics(t *testing.T) {
	m := NewListenerManager()
	ctx := context.Background()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	err := m.AddListener(ctx, ListenerConfig{
		Name:    "test-listener",
		Type:    ListenerTypeProxy,
		Address: "127.0.0.1:0",
		Handler: handler,
	})
	require.NoError(t, err)
	defer m.Shutdown(ctx)

	// Wait for listener to start
	time.Sleep(10 * time.Millisecond)

	managed, exists := m.GetListener("test-listener")
	require.True(t, exists)

	// Check initial metrics
	assert.Equal(t, int64(0), managed.GetRequestCount())
	assert.Equal(t, int64(0), managed.GetErrorCount())
	assert.Empty(t, managed.GetLastError())
	assert.True(t, managed.GetUptime() > 0)
}

func TestListenerManager_MultipleListenerTypes(t *testing.T) {
	m := NewListenerManager()
	ctx := context.Background()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	// Add different types of listeners
	types := []ListenerType{ListenerTypeProxy, ListenerTypeEgress, ListenerTypeCustom}
	for i, lt := range types {
		err := m.AddListener(ctx, ListenerConfig{
			Name:    "listener-" + string(rune('a'+i)),
			Type:    lt,
			Address: "127.0.0.1:0",
			Handler: handler,
		})
		require.NoError(t, err)
	}
	defer m.Shutdown(ctx)

	listeners := m.GetListeners()
	assert.Len(t, listeners, 3)

	// Verify types
	typeCount := make(map[string]int)
	for _, l := range listeners {
		typeCount[l.Type]++
	}
	assert.Equal(t, 1, typeCount["proxy"])
	assert.Equal(t, 1, typeCount["egress"])
	assert.Equal(t, 1, typeCount["custom"])
}
