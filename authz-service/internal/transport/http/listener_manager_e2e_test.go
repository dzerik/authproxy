package http

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// E2E tests for graceful operations of ListenerManager.

func TestListenerManager_E2E_DynamicListenerAddRemove(t *testing.T) {
	// Test: Dynamically add a listener, make requests, then remove it gracefully

	log := zap.NewNop()
	manager := NewListenerManager(
		WithShutdownTimeout(5*time.Second),
		WithListenerLogger(log),
	)
	defer manager.Shutdown(context.Background())

	ctx := context.Background()

	// Add a listener dynamically
	port := getAvailablePort(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("dynamic listener"))
	})

	err := manager.AddListener(ctx, ListenerConfig{
		Name:    "dynamic-test",
		Type:    ListenerTypeProxy,
		Address: fmt.Sprintf("127.0.0.1:%d", port),
		Handler: handler,
	})
	require.NoError(t, err)

	// Wait for listener to start
	time.Sleep(50 * time.Millisecond)

	// Make a request to verify it works
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/test", port))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "dynamic listener", string(body))

	// Remove the listener
	err = manager.RemoveListener(ctx, "dynamic-test")
	require.NoError(t, err)

	// Wait for shutdown
	time.Sleep(50 * time.Millisecond)

	// Verify listener is gone
	_, err = http.Get(fmt.Sprintf("http://127.0.0.1:%d/test", port))
	assert.Error(t, err, "expected connection refused after listener removal")
}

func TestListenerManager_E2E_HotSwapHandler(t *testing.T) {
	// Test: Hot-swap a handler without dropping requests

	log := zap.NewNop()
	manager := NewListenerManager(
		WithShutdownTimeout(5*time.Second),
		WithListenerLogger(log),
	)
	defer manager.Shutdown(context.Background())

	ctx := context.Background()
	port := getAvailablePort(t)

	// Initial handler
	handler1 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("handler-v1"))
	})

	err := manager.AddListener(ctx, ListenerConfig{
		Name:    "hotswap-test",
		Type:    ListenerTypeProxy,
		Address: fmt.Sprintf("127.0.0.1:%d", port),
		Handler: handler1,
	})
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	// Verify v1 handler works
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	assert.Equal(t, "handler-v1", string(body))

	// Hot-swap to v2 handler
	handler2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("handler-v2"))
	})

	err = manager.UpdateHandler("hotswap-test", handler2)
	require.NoError(t, err)

	// Verify v2 handler works (same port, no downtime)
	resp, err = http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	require.NoError(t, err)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	assert.Equal(t, "handler-v2", string(body))
}

func TestListenerManager_E2E_GracefulDrain(t *testing.T) {
	// Test: Drain a listener while requests are in-flight

	log := zap.NewNop()
	manager := NewListenerManager(
		WithShutdownTimeout(5*time.Second),
		WithListenerLogger(log),
	)
	defer manager.Shutdown(context.Background())

	ctx := context.Background()
	port := getAvailablePort(t)

	var requestsCompleted atomic.Int32

	// Handler that takes 200ms to complete
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		requestsCompleted.Add(1)
		w.Write([]byte("completed"))
	})

	err := manager.AddListener(ctx, ListenerConfig{
		Name:    "drain-test",
		Type:    ListenerTypeProxy,
		Address: fmt.Sprintf("127.0.0.1:%d", port),
		Handler: handler,
	})
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	// Start a slow request in background
	requestDone := make(chan struct{})
	go func() {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/slow", port))
		if err == nil {
			resp.Body.Close()
		}
		close(requestDone)
	}()

	// Give the request time to start
	time.Sleep(50 * time.Millisecond)

	// Start drain (triggers draining mode)
	err = manager.DrainListener("drain-test")
	require.NoError(t, err)

	// Wait for the slow request to complete
	<-requestDone

	// Request should complete successfully
	assert.Equal(t, int32(1), requestsCompleted.Load(), "request should complete during drain")
}

func TestListenerManager_E2E_ConcurrentRequests(t *testing.T) {
	// Test: Handle many concurrent requests without issues

	log := zap.NewNop()
	manager := NewListenerManager(
		WithShutdownTimeout(5*time.Second),
		WithListenerLogger(log),
	)
	defer manager.Shutdown(context.Background())

	ctx := context.Background()
	port := getAvailablePort(t)

	var requestCount atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusOK)
	})

	err := manager.AddListener(ctx, ListenerConfig{
		Name:    "concurrent-test",
		Type:    ListenerTypeProxy,
		Address: fmt.Sprintf("127.0.0.1:%d", port),
		Handler: handler,
	})
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	// Send 100 concurrent requests
	const numRequests = 100
	var wg sync.WaitGroup
	errors := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
			if err != nil {
				errors <- err
				return
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				errors <- fmt.Errorf("unexpected status: %d", resp.StatusCode)
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent request failed: %v", err)
	}

	assert.Equal(t, int32(numRequests), requestCount.Load())
}

func TestListenerManager_E2E_MultipleListeners(t *testing.T) {
	// Test: Multiple listeners on different ports

	log := zap.NewNop()
	manager := NewListenerManager(
		WithShutdownTimeout(5*time.Second),
		WithListenerLogger(log),
	)
	defer manager.Shutdown(context.Background())

	ctx := context.Background()
	port1 := getAvailablePort(t)
	port2 := getAvailablePort(t)
	port3 := getAvailablePort(t)

	// Add three different listeners
	listeners := []struct {
		name    string
		port    int
		message string
	}{
		{"listener-1", port1, "response from listener 1"},
		{"listener-2", port2, "response from listener 2"},
		{"listener-3", port3, "response from listener 3"},
	}

	for _, l := range listeners {
		msg := l.message
		err := manager.AddListener(ctx, ListenerConfig{
			Name:    l.name,
			Type:    ListenerTypeProxy,
			Address: fmt.Sprintf("127.0.0.1:%d", l.port),
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(msg))
			}),
		})
		require.NoError(t, err)
	}

	time.Sleep(100 * time.Millisecond)

	// Verify all listeners respond correctly
	for _, l := range listeners {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", l.port))
		require.NoError(t, err)

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		assert.Equal(t, l.message, string(body), "listener %s should return correct message", l.name)
	}

	// Verify GetListeners returns all
	infos := manager.GetListeners()
	assert.Len(t, infos, 3)
}

func TestListenerManager_E2E_GracefulShutdown(t *testing.T) {
	// Test: Graceful shutdown waits for all in-flight requests

	log := zap.NewNop()
	manager := NewListenerManager(
		WithShutdownTimeout(5*time.Second),
		WithListenerLogger(log),
	)

	ctx := context.Background()
	port := getAvailablePort(t)

	var requestCompleted atomic.Bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		requestCompleted.Store(true)
		w.Write([]byte("done"))
	})

	err := manager.AddListener(ctx, ListenerConfig{
		Name:    "shutdown-test",
		Type:    ListenerTypeProxy,
		Address: fmt.Sprintf("127.0.0.1:%d", port),
		Handler: handler,
	})
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	// Start a slow request
	requestDone := make(chan struct{})
	go func() {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
		if err == nil {
			resp.Body.Close()
		}
		close(requestDone)
	}()

	// Give request time to start
	time.Sleep(50 * time.Millisecond)

	// Shutdown should wait for request to complete
	shutdownStart := time.Now()
	err = manager.Shutdown(context.Background())
	shutdownDuration := time.Since(shutdownStart)
	require.NoError(t, err)

	// Wait for request goroutine
	<-requestDone

	// Shutdown should have waited for the request
	assert.True(t, shutdownDuration >= 200*time.Millisecond, "shutdown should wait for in-flight request")
	assert.True(t, requestCompleted.Load(), "request should complete during shutdown")
}

// getAvailablePort finds an available TCP port
func getAvailablePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}
