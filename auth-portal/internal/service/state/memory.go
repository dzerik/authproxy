package state

import (
	"sync"
	"time"
)

// MemoryStore stores OAuth state in memory.
// Suitable for single-instance deployments and development.
type MemoryStore struct {
	mu     sync.RWMutex
	states map[string]*OAuthState
	ttl    time.Duration
	done   chan struct{}
}

// NewMemoryStore creates a new in-memory state store
func NewMemoryStore(ttl time.Duration) *MemoryStore {
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	store := &MemoryStore{
		states: make(map[string]*OAuthState),
		ttl:    ttl,
		done:   make(chan struct{}),
	}
	// Start cleanup goroutine
	go store.cleanup()
	return store
}

// Set stores a new state token
func (s *MemoryStore) Set(state *OAuthState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[state.State] = state
	return nil
}

// Get retrieves and removes a state token (one-time use)
func (s *MemoryStore) Get(stateToken string) (*OAuthState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, exists := s.states[stateToken]
	if exists {
		delete(s.states, stateToken)
		// Check if expired
		if time.Since(state.CreatedAt) > s.ttl {
			return nil, false
		}
	}
	return state, exists
}

// Validate checks if a state token exists without removing it
func (s *MemoryStore) Validate(stateToken string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, exists := s.states[stateToken]
	if !exists {
		return false
	}
	// Check if expired
	return time.Since(state.CreatedAt) <= s.ttl
}

// Close stops the cleanup goroutine
func (s *MemoryStore) Close() error {
	close(s.done)
	return nil
}

// Name returns the store type name
func (s *MemoryStore) Name() string {
	return "memory"
}

// cleanup removes expired states
func (s *MemoryStore) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for key, state := range s.states {
				if now.Sub(state.CreatedAt) > s.ttl {
					delete(s.states, key)
				}
			}
			s.mu.Unlock()
		}
	}
}
