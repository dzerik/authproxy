package http

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/your-org/authz-service/pkg/logger"
)

// ErrListenerNotFound is returned when a listener is not found.
var ErrListenerNotFound = errors.New("listener not found")

// ListenerType represents the type of listener.
type ListenerType string

const (
	// ListenerTypeProxy is a reverse proxy listener.
	ListenerTypeProxy ListenerType = "proxy"
	// ListenerTypeEgress is an egress proxy listener.
	ListenerTypeEgress ListenerType = "egress"
	// ListenerTypeCustom is a custom listener.
	ListenerTypeCustom ListenerType = "custom"
)

// ListenerStatus represents the current status of a listener.
type ListenerStatus string

const (
	ListenerStatusStarting ListenerStatus = "starting"
	ListenerStatusRunning  ListenerStatus = "running"
	ListenerStatusDraining ListenerStatus = "draining"
	ListenerStatusStopped  ListenerStatus = "stopped"
	ListenerStatusError    ListenerStatus = "error"
)

// ListenerConfig holds configuration for creating a new listener.
type ListenerConfig struct {
	Name         string
	Type         ListenerType
	Address      string // host:port format
	Handler      http.Handler
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	// Metadata for tracking
	Metadata map[string]string
}

// ManagedListener represents a managed HTTP listener with lifecycle control.
type ManagedListener struct {
	Name     string
	Type     ListenerType
	Address  string
	Status   ListenerStatus
	Metadata map[string]string

	server   *http.Server
	listener net.Listener
	handler  *swappableHandler

	// Metrics
	startTime    time.Time
	requestCount atomic.Int64
	errorCount   atomic.Int64
	lastError    atomic.Value // stores string

	mu sync.RWMutex
}

// swappableHandler allows hot-swapping of the underlying handler.
type swappableHandler struct {
	handler atomic.Value // stores http.Handler
}

func newSwappableHandler(h http.Handler) *swappableHandler {
	sh := &swappableHandler{}
	sh.handler.Store(h)
	return sh
}

func (s *swappableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := s.handler.Load().(http.Handler)
	h.ServeHTTP(w, r)
}

func (s *swappableHandler) Swap(h http.Handler) {
	s.handler.Store(h)
}

// GetRequestCount returns the total request count.
func (m *ManagedListener) GetRequestCount() int64 {
	return m.requestCount.Load()
}

// GetErrorCount returns the total error count.
func (m *ManagedListener) GetErrorCount() int64 {
	return m.errorCount.Load()
}

// GetLastError returns the last error message.
func (m *ManagedListener) GetLastError() string {
	if v := m.lastError.Load(); v != nil {
		return v.(string)
	}
	return ""
}

// GetUptime returns the listener uptime.
func (m *ManagedListener) GetUptime() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.startTime.IsZero() {
		return 0
	}
	return time.Since(m.startTime)
}

// UpdateHandler hot-swaps the handler for this listener.
func (m *ManagedListener) UpdateHandler(h http.Handler) {
	if m.handler != nil {
		m.handler.Swap(h)
		logger.Info("listener handler updated",
			logger.String("name", m.Name),
			logger.String("address", m.Address))
	}
}

// ListenerManager manages multiple HTTP listeners dynamically.
type ListenerManager struct {
	listeners map[string]*ManagedListener
	mu        sync.RWMutex
	log       *zap.Logger

	// Shutdown coordination
	shutdownTimeout time.Duration
}

// ListenerManagerOption configures the ListenerManager.
type ListenerManagerOption func(*ListenerManager)

// WithShutdownTimeout sets the shutdown timeout for listeners.
func WithShutdownTimeout(d time.Duration) ListenerManagerOption {
	return func(m *ListenerManager) {
		m.shutdownTimeout = d
	}
}

// WithListenerLogger sets the logger for the manager.
func WithListenerLogger(log *zap.Logger) ListenerManagerOption {
	return func(m *ListenerManager) {
		m.log = log
	}
}

// NewListenerManager creates a new ListenerManager.
func NewListenerManager(opts ...ListenerManagerOption) *ListenerManager {
	m := &ListenerManager{
		listeners:       make(map[string]*ManagedListener),
		log:             zap.NewNop(),
		shutdownTimeout: 30 * time.Second,
	}

	for _, opt := range opts {
		opt(m)
	}

	m.log = m.log.Named("listener-manager")
	return m
}

// AddListener adds and starts a new listener.
func (m *ListenerManager) AddListener(ctx context.Context, cfg ListenerConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if listener already exists
	if _, exists := m.listeners[cfg.Name]; exists {
		return fmt.Errorf("listener %q already exists", cfg.Name)
	}

	// Validate config
	if cfg.Name == "" {
		return fmt.Errorf("listener name is required")
	}
	if cfg.Address == "" {
		return fmt.Errorf("listener address is required")
	}
	if cfg.Handler == nil {
		return fmt.Errorf("listener handler is required")
	}

	// Create network listener
	ln, err := net.Listen("tcp", cfg.Address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", cfg.Address, err)
	}

	// Create swappable handler for hot reload
	handler := newSwappableHandler(cfg.Handler)

	// Apply defaults
	readTimeout := cfg.ReadTimeout
	if readTimeout == 0 {
		readTimeout = 10 * time.Second
	}
	writeTimeout := cfg.WriteTimeout
	if writeTimeout == 0 {
		writeTimeout = 30 * time.Second
	}
	idleTimeout := cfg.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = 120 * time.Second
	}

	// Create HTTP server
	server := &http.Server{
		Handler:      handler,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	// Create managed listener
	managed := &ManagedListener{
		Name:     cfg.Name,
		Type:     cfg.Type,
		Address:  cfg.Address,
		Status:   ListenerStatusStarting,
		Metadata: cfg.Metadata,
		server:   server,
		listener: ln,
		handler:  handler,
	}

	// Start serving in goroutine
	go func() {
		managed.mu.Lock()
		managed.startTime = time.Now()
		managed.Status = ListenerStatusRunning
		managed.mu.Unlock()

		m.log.Info("listener started",
			zap.String("name", cfg.Name),
			zap.String("type", string(cfg.Type)),
			zap.String("address", cfg.Address))

		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			managed.mu.Lock()
			managed.Status = ListenerStatusError
			managed.lastError.Store(err.Error())
			managed.mu.Unlock()

			m.log.Error("listener error",
				zap.String("name", cfg.Name),
				zap.Error(err))
		}
	}()

	m.listeners[cfg.Name] = managed
	return nil
}

// RemoveListener gracefully removes a listener.
func (m *ListenerManager) RemoveListener(ctx context.Context, name string) error {
	m.mu.Lock()
	managed, exists := m.listeners[name]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("listener %q: %w", name, ErrListenerNotFound)
	}
	delete(m.listeners, name)
	m.mu.Unlock()

	return m.shutdownListener(ctx, managed)
}

// shutdownListener gracefully shuts down a single listener.
func (m *ListenerManager) shutdownListener(ctx context.Context, managed *ManagedListener) error {
	managed.mu.Lock()
	managed.Status = ListenerStatusDraining
	managed.mu.Unlock()

	m.log.Info("draining listener",
		zap.String("name", managed.Name),
		zap.String("address", managed.Address))

	// Create timeout context if not already set
	shutdownCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		shutdownCtx, cancel = context.WithTimeout(ctx, m.shutdownTimeout)
		defer cancel()
	}

	// Graceful shutdown
	if err := managed.server.Shutdown(shutdownCtx); err != nil {
		m.log.Error("listener shutdown error",
			zap.String("name", managed.Name),
			zap.Error(err))
		return err
	}

	managed.mu.Lock()
	managed.Status = ListenerStatusStopped
	managed.mu.Unlock()

	m.log.Info("listener stopped",
		zap.String("name", managed.Name))

	return nil
}

// UpdateHandler updates the handler for an existing listener.
func (m *ListenerManager) UpdateHandler(name string, handler http.Handler) error {
	m.mu.RLock()
	managed, exists := m.listeners[name]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("listener %q: %w", name, ErrListenerNotFound)
	}

	managed.UpdateHandler(handler)
	return nil
}

// GetListener returns a listener by name.
func (m *ListenerManager) GetListener(name string) (*ManagedListener, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	managed, exists := m.listeners[name]
	return managed, exists
}

// GetListeners returns information about all listeners.
func (m *ListenerManager) GetListeners() []ListenerInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	infos := make([]ListenerInfo, 0, len(m.listeners))
	for _, managed := range m.listeners {
		managed.mu.RLock()
		info := ListenerInfo{
			Name:    managed.Name,
			Type:    string(managed.Type),
			Address: managed.Address,
			Status:  string(managed.Status),
		}
		managed.mu.RUnlock()
		infos = append(infos, info)
	}

	return infos
}

// GetListenerStats returns detailed statistics for a listener.
func (m *ListenerManager) GetListenerStats(name string) (*ListenerStats, error) {
	m.mu.RLock()
	managed, exists := m.listeners[name]
	m.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("listener %q: %w", name, ErrListenerNotFound)
	}

	managed.mu.RLock()
	defer managed.mu.RUnlock()

	return &ListenerStats{
		Name:         managed.Name,
		Type:         string(managed.Type),
		Address:      managed.Address,
		Status:       string(managed.Status),
		Uptime:       managed.GetUptime().String(),
		RequestCount: managed.GetRequestCount(),
		ErrorCount:   managed.GetErrorCount(),
		LastError:    managed.GetLastError(),
		Metadata:     managed.Metadata,
	}, nil
}

// ListenerStats contains detailed listener statistics.
type ListenerStats struct {
	Name         string            `json:"name"`
	Type         string            `json:"type"`
	Address      string            `json:"address"`
	Status       string            `json:"status"`
	Uptime       string            `json:"uptime"`
	RequestCount int64             `json:"request_count"`
	ErrorCount   int64             `json:"error_count"`
	LastError    string            `json:"last_error,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// DrainListener puts a listener into drain mode (stops accepting new connections).
func (m *ListenerManager) DrainListener(name string) error {
	m.mu.RLock()
	managed, exists := m.listeners[name]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("listener %q: %w", name, ErrListenerNotFound)
	}

	managed.mu.Lock()
	if managed.Status == ListenerStatusRunning {
		managed.Status = ListenerStatusDraining
		m.log.Info("listener draining",
			zap.String("name", name))
	}
	managed.mu.Unlock()

	return nil
}

// Shutdown gracefully shuts down all listeners.
func (m *ListenerManager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	listeners := make([]*ManagedListener, 0, len(m.listeners))
	for _, managed := range m.listeners {
		listeners = append(listeners, managed)
	}
	m.listeners = make(map[string]*ManagedListener)
	m.mu.Unlock()

	m.log.Info("shutting down all listeners",
		zap.Int("count", len(listeners)))

	// Shutdown all listeners concurrently
	var wg sync.WaitGroup
	errors := make(chan error, len(listeners))

	for _, managed := range listeners {
		wg.Add(1)
		go func(l *ManagedListener) {
			defer wg.Done()
			if err := m.shutdownListener(ctx, l); err != nil {
				errors <- fmt.Errorf("listener %s: %w", l.Name, err)
			}
		}(managed)
	}

	wg.Wait()
	close(errors)

	// Collect errors
	var errs []error
	for err := range errors {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}

	m.log.Info("all listeners stopped")
	return nil
}

// Count returns the number of active listeners.
func (m *ListenerManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.listeners)
}

// HasListener checks if a listener exists.
func (m *ListenerManager) HasListener(name string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.listeners[name]
	return exists
}
