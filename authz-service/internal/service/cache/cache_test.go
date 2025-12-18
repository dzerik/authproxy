package cache

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/internal/domain"
)

// =============================================================================
// L1Cache Tests
// =============================================================================

func TestNewL1Cache(t *testing.T) {
	cfg := config.L1CacheConfig{
		Enabled: true,
		MaxSize: 100,
		TTL:     time.Minute,
	}

	cache := NewL1Cache(cfg)

	require.NotNil(t, cache)
	assert.Equal(t, 100, cache.capacity)
	assert.Equal(t, time.Minute, cache.ttl)
	assert.True(t, cache.enabled)
}

func TestL1Cache_Get_Disabled(t *testing.T) {
	cache := NewL1Cache(config.L1CacheConfig{Enabled: false})

	decision, found := cache.Get(context.Background(), "key")

	assert.False(t, found)
	assert.Nil(t, decision)
}

func TestL1Cache_Set_Disabled(t *testing.T) {
	cache := NewL1Cache(config.L1CacheConfig{Enabled: false, MaxSize: 10})

	cache.Set(context.Background(), "key", domain.Allow(), 0)

	// Should not store anything
	assert.Empty(t, cache.items)
}

func TestL1Cache_SetAndGet(t *testing.T) {
	cfg := config.L1CacheConfig{
		Enabled: true,
		MaxSize: 100,
		TTL:     time.Minute,
	}
	cache := NewL1Cache(cfg)
	ctx := context.Background()

	decision := domain.Allow("test reason")
	cache.Set(ctx, "test-key", decision, 0)

	result, found := cache.Get(ctx, "test-key")

	require.True(t, found)
	require.NotNil(t, result)
	assert.True(t, result.Allowed)
	assert.True(t, result.Cached) // Should be marked as cached
}

func TestL1Cache_Get_Expired(t *testing.T) {
	cfg := config.L1CacheConfig{
		Enabled: true,
		MaxSize: 100,
		TTL:     1 * time.Millisecond,
	}
	cache := NewL1Cache(cfg)
	ctx := context.Background()

	cache.Set(ctx, "key", domain.Allow(), 0)
	time.Sleep(10 * time.Millisecond)

	result, found := cache.Get(ctx, "key")

	assert.False(t, found)
	assert.Nil(t, result)
}

func TestL1Cache_Get_NotFound(t *testing.T) {
	cache := NewL1Cache(config.L1CacheConfig{Enabled: true, MaxSize: 100, TTL: time.Minute})
	ctx := context.Background()

	result, found := cache.Get(ctx, "nonexistent")

	assert.False(t, found)
	assert.Nil(t, result)
}

func TestL1Cache_Set_UpdateExisting(t *testing.T) {
	cache := NewL1Cache(config.L1CacheConfig{Enabled: true, MaxSize: 100, TTL: time.Minute})
	ctx := context.Background()

	cache.Set(ctx, "key", domain.Deny("reason1"), 0)
	cache.Set(ctx, "key", domain.Allow("reason2"), 0)

	result, found := cache.Get(ctx, "key")

	require.True(t, found)
	assert.True(t, result.Allowed) // Should be updated value
}

func TestL1Cache_Eviction(t *testing.T) {
	cache := NewL1Cache(config.L1CacheConfig{Enabled: true, MaxSize: 3, TTL: time.Minute})
	ctx := context.Background()

	// Add 4 items to a cache with capacity 3
	cache.Set(ctx, "key1", domain.Allow(), 0)
	cache.Set(ctx, "key2", domain.Allow(), 0)
	cache.Set(ctx, "key3", domain.Allow(), 0)
	cache.Set(ctx, "key4", domain.Allow(), 0) // Should evict key1

	// key1 should be evicted (LRU)
	_, found1 := cache.Get(ctx, "key1")
	assert.False(t, found1)

	// key2, key3, key4 should exist
	_, found2 := cache.Get(ctx, "key2")
	_, found3 := cache.Get(ctx, "key3")
	_, found4 := cache.Get(ctx, "key4")
	assert.True(t, found2)
	assert.True(t, found3)
	assert.True(t, found4)
}

func TestL1Cache_LRU_MoveToFront(t *testing.T) {
	cache := NewL1Cache(config.L1CacheConfig{Enabled: true, MaxSize: 3, TTL: time.Minute})
	ctx := context.Background()

	cache.Set(ctx, "key1", domain.Allow(), 0)
	cache.Set(ctx, "key2", domain.Allow(), 0)
	cache.Set(ctx, "key3", domain.Allow(), 0)

	// Access key1 to move it to front
	cache.Get(ctx, "key1")

	// Add new item, key2 should be evicted (now LRU)
	cache.Set(ctx, "key4", domain.Allow(), 0)

	_, found1 := cache.Get(ctx, "key1")
	_, found2 := cache.Get(ctx, "key2")

	assert.True(t, found1, "key1 should exist (was accessed)")
	assert.False(t, found2, "key2 should be evicted (LRU)")
}

func TestL1Cache_Delete(t *testing.T) {
	cache := NewL1Cache(config.L1CacheConfig{Enabled: true, MaxSize: 100, TTL: time.Minute})
	ctx := context.Background()

	cache.Set(ctx, "key", domain.Allow(), 0)
	cache.Delete(ctx, "key")

	_, found := cache.Get(ctx, "key")
	assert.False(t, found)
}

func TestL1Cache_Delete_Disabled(t *testing.T) {
	cache := NewL1Cache(config.L1CacheConfig{Enabled: false})
	ctx := context.Background()

	// Should not panic
	cache.Delete(ctx, "key")
}

func TestL1Cache_Delete_NonExistent(t *testing.T) {
	cache := NewL1Cache(config.L1CacheConfig{Enabled: true, MaxSize: 100, TTL: time.Minute})
	ctx := context.Background()

	// Should not panic
	cache.Delete(ctx, "nonexistent")
}

func TestL1Cache_Clear(t *testing.T) {
	cache := NewL1Cache(config.L1CacheConfig{Enabled: true, MaxSize: 100, TTL: time.Minute})
	ctx := context.Background()

	cache.Set(ctx, "key1", domain.Allow(), 0)
	cache.Set(ctx, "key2", domain.Allow(), 0)
	cache.Clear(ctx)

	_, found1 := cache.Get(ctx, "key1")
	_, found2 := cache.Get(ctx, "key2")

	assert.False(t, found1)
	assert.False(t, found2)
}

func TestL1Cache_Stats(t *testing.T) {
	cache := NewL1Cache(config.L1CacheConfig{Enabled: true, MaxSize: 100, TTL: time.Minute})
	ctx := context.Background()

	cache.Set(ctx, "key1", domain.Allow(), 0)
	cache.Set(ctx, "key2", domain.Allow(), 0)

	cache.Get(ctx, "key1") // Hit
	cache.Get(ctx, "key2") // Hit
	cache.Get(ctx, "key3") // Miss

	stats := cache.Stats()

	assert.Equal(t, 2, stats.Size)
	assert.Equal(t, 100, stats.Capacity)
	assert.Equal(t, int64(2), stats.Hits)
	assert.Equal(t, int64(1), stats.Misses)
	assert.InDelta(t, 0.666, stats.HitRate, 0.01)
}

func TestL1Cache_HitRate_NoRequests(t *testing.T) {
	cache := NewL1Cache(config.L1CacheConfig{Enabled: true, MaxSize: 100, TTL: time.Minute})

	stats := cache.Stats()

	assert.Equal(t, float64(0), stats.HitRate)
}

func TestL1Cache_Concurrent(t *testing.T) {
	cache := NewL1Cache(config.L1CacheConfig{Enabled: true, MaxSize: 1000, TTL: time.Minute})
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		key := string(rune('a' + i%26))

		go func(k string) {
			defer wg.Done()
			cache.Set(ctx, k, domain.Allow(), 0)
		}(key)

		go func(k string) {
			defer wg.Done()
			cache.Get(ctx, k)
		}(key)
	}

	wg.Wait()
	// Should not deadlock or panic
}

func TestL1Cache_CustomTTL(t *testing.T) {
	cache := NewL1Cache(config.L1CacheConfig{Enabled: true, MaxSize: 100, TTL: time.Hour})
	ctx := context.Background()

	// Set with custom short TTL
	cache.Set(ctx, "short-lived", domain.Allow(), 10*time.Millisecond)
	time.Sleep(50 * time.Millisecond)

	_, found := cache.Get(ctx, "short-lived")
	assert.False(t, found, "entry should have expired with custom TTL")
}

// =============================================================================
// CacheService Tests
// =============================================================================

func TestNewService(t *testing.T) {
	cfg := config.CacheConfig{
		L1: config.L1CacheConfig{
			Enabled: true,
			MaxSize: 100,
			TTL:     time.Minute,
		},
	}

	svc := NewService(cfg)

	require.NotNil(t, svc)
	assert.NotNil(t, svc.l1)
	assert.True(t, svc.enabled)
}

func TestService_Disabled(t *testing.T) {
	cfg := config.CacheConfig{
		L1: config.L1CacheConfig{Enabled: false},
		L2: config.L2CacheConfig{Enabled: false},
	}

	svc := NewService(cfg)

	assert.False(t, svc.enabled)
}

func TestService_Get_NotEnabled(t *testing.T) {
	svc := &Service{enabled: false}

	decision, found := svc.Get(context.Background(), "key")

	assert.False(t, found)
	assert.Nil(t, decision)
}

func TestService_Set_NotEnabled(t *testing.T) {
	svc := &Service{enabled: false}

	// Should not panic
	svc.Set(context.Background(), "key", domain.Allow(), 0)
}

func TestService_GetSet_L1Only(t *testing.T) {
	cfg := config.CacheConfig{
		L1: config.L1CacheConfig{
			Enabled: true,
			MaxSize: 100,
			TTL:     time.Minute,
		},
	}
	svc := NewService(cfg)
	ctx := context.Background()

	decision := domain.Allow("reason")
	svc.Set(ctx, "key", decision, 0)

	result, found := svc.Get(ctx, "key")

	require.True(t, found)
	assert.True(t, result.Allowed)
}

func TestService_Delete(t *testing.T) {
	cfg := config.CacheConfig{
		L1: config.L1CacheConfig{
			Enabled: true,
			MaxSize: 100,
			TTL:     time.Minute,
		},
	}
	svc := NewService(cfg)
	ctx := context.Background()

	svc.Set(ctx, "key", domain.Allow(), 0)
	svc.Delete(ctx, "key")

	_, found := svc.Get(ctx, "key")
	assert.False(t, found)
}

func TestService_Clear(t *testing.T) {
	cfg := config.CacheConfig{
		L1: config.L1CacheConfig{
			Enabled: true,
			MaxSize: 100,
			TTL:     time.Minute,
		},
	}
	svc := NewService(cfg)
	ctx := context.Background()

	svc.Set(ctx, "key1", domain.Allow(), 0)
	svc.Set(ctx, "key2", domain.Allow(), 0)
	svc.Clear(ctx)

	_, found1 := svc.Get(ctx, "key1")
	_, found2 := svc.Get(ctx, "key2")
	assert.False(t, found1)
	assert.False(t, found2)
}

func TestService_Stats(t *testing.T) {
	cfg := config.CacheConfig{
		L1: config.L1CacheConfig{
			Enabled: true,
			MaxSize: 100,
			TTL:     time.Minute,
		},
	}
	svc := NewService(cfg)
	ctx := context.Background()

	svc.Set(ctx, "key", domain.Allow(), 0)

	stats := svc.Stats()

	require.Contains(t, stats, "l1")
	assert.Equal(t, 1, stats["l1"].Size)
}

func TestService_Enabled(t *testing.T) {
	tests := []struct {
		name     string
		l1       bool
		l2       bool
		expected bool
	}{
		{"both disabled", false, false, false},
		{"l1 only", true, false, true},
		{"l2 only", false, true, true},
		{"both enabled", true, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.CacheConfig{
				L1: config.L1CacheConfig{Enabled: tt.l1, MaxSize: 10, TTL: time.Minute},
				L2: config.L2CacheConfig{Enabled: tt.l2},
			}
			svc := NewService(cfg)
			assert.Equal(t, tt.expected, svc.Enabled())
		})
	}
}

func TestService_Healthy_NoL2(t *testing.T) {
	cfg := config.CacheConfig{
		L1: config.L1CacheConfig{Enabled: true, MaxSize: 100, TTL: time.Minute},
	}
	svc := NewService(cfg)

	// Without L2, always healthy
	assert.True(t, svc.Healthy(context.Background()))
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkL1Cache_Get(b *testing.B) {
	cache := NewL1Cache(config.L1CacheConfig{Enabled: true, MaxSize: 10000, TTL: time.Minute})
	ctx := context.Background()

	cache.Set(ctx, "benchmark-key", domain.Allow(), 0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Get(ctx, "benchmark-key")
	}
}

func BenchmarkL1Cache_Set(b *testing.B) {
	cache := NewL1Cache(config.L1CacheConfig{Enabled: true, MaxSize: 100000, TTL: time.Minute})
	ctx := context.Background()
	decision := domain.Allow()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Set(ctx, "key", decision, 0)
	}
}

func BenchmarkL1Cache_Get_Concurrent(b *testing.B) {
	cache := NewL1Cache(config.L1CacheConfig{Enabled: true, MaxSize: 10000, TTL: time.Minute})
	ctx := context.Background()

	cache.Set(ctx, "benchmark-key", domain.Allow(), 0)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cache.Get(ctx, "benchmark-key")
		}
	})
}

func BenchmarkL1Cache_Set_Concurrent(b *testing.B) {
	cache := NewL1Cache(config.L1CacheConfig{Enabled: true, MaxSize: 100000, TTL: time.Minute})
	ctx := context.Background()
	decision := domain.Allow()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cache.Set(ctx, "key", decision, 0)
		}
	})
}

// =============================================================================
// L1Cache Cleanup Tests
// =============================================================================

func TestL1Cache_StartCleanup_Disabled(t *testing.T) {
	cache := NewL1Cache(config.L1CacheConfig{Enabled: false})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Should not panic when disabled
	cache.StartCleanup(ctx, time.Millisecond)
}

func TestL1Cache_StartCleanup_CleansExpiredEntries(t *testing.T) {
	cache := NewL1Cache(config.L1CacheConfig{Enabled: true, MaxSize: 100, TTL: 10 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Add entries
	cache.Set(ctx, "key1", domain.Allow(), 0)
	cache.Set(ctx, "key2", domain.Allow(), 0)

	// Start cleanup with short interval
	cache.StartCleanup(ctx, 20*time.Millisecond)

	// Wait for entries to expire and cleanup to run
	time.Sleep(100 * time.Millisecond)

	// Entries should be cleaned up
	stats := cache.Stats()
	assert.Equal(t, 0, stats.Size, "expired entries should be cleaned up")
}

func TestL1Cache_StartCleanup_ContextCancellation(t *testing.T) {
	cache := NewL1Cache(config.L1CacheConfig{Enabled: true, MaxSize: 100, TTL: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())

	// Start cleanup
	cache.StartCleanup(ctx, time.Second)

	// Cancel context
	cancel()

	// Give goroutine time to exit
	time.Sleep(50 * time.Millisecond)

	// Should not hang or panic
}

func TestL1Cache_CleanupExpired_DirectCall(t *testing.T) {
	cache := NewL1Cache(config.L1CacheConfig{Enabled: true, MaxSize: 100, TTL: 1 * time.Millisecond})
	ctx := context.Background()

	// Add entries
	cache.Set(ctx, "key1", domain.Allow(), 0)
	cache.Set(ctx, "key2", domain.Allow(), 0)
	cache.Set(ctx, "key3", domain.Allow(), time.Hour) // This one has long TTL

	// Wait for entries with short TTL to expire
	time.Sleep(20 * time.Millisecond)

	// Directly call cleanup
	cache.cleanupExpired()

	// Check results
	_, found1 := cache.Get(ctx, "key1")
	_, found2 := cache.Get(ctx, "key2")
	_, found3 := cache.Get(ctx, "key3")

	assert.False(t, found1, "key1 should be cleaned up")
	assert.False(t, found2, "key2 should be cleaned up")
	assert.True(t, found3, "key3 should still exist (long TTL)")
}

func TestL1Cache_CleanupExpired_Empty(t *testing.T) {
	cache := NewL1Cache(config.L1CacheConfig{Enabled: true, MaxSize: 100, TTL: time.Minute})

	// Should not panic on empty cache
	cache.cleanupExpired()

	stats := cache.Stats()
	assert.Equal(t, 0, stats.Size)
}

// =============================================================================
// CacheService Lifecycle Tests
// =============================================================================

func TestService_Start_L1Only(t *testing.T) {
	cfg := config.CacheConfig{
		L1: config.L1CacheConfig{
			Enabled: true,
			MaxSize: 100,
			TTL:     time.Minute,
		},
	}
	svc := NewService(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := svc.Start(ctx)
	require.NoError(t, err)
}

func TestService_Start_NilL1(t *testing.T) {
	cfg := config.CacheConfig{
		L1: config.L1CacheConfig{Enabled: false},
	}
	svc := NewService(cfg)
	ctx := context.Background()

	// Should not panic with nil L1
	err := svc.Start(ctx)
	require.NoError(t, err)
}

func TestService_Stop_L1Only(t *testing.T) {
	cfg := config.CacheConfig{
		L1: config.L1CacheConfig{
			Enabled: true,
			MaxSize: 100,
			TTL:     time.Minute,
		},
	}
	svc := NewService(cfg)
	ctx := context.Background()

	_ = svc.Start(ctx)
	err := svc.Stop()
	require.NoError(t, err)
}

func TestService_Stop_NilL2(t *testing.T) {
	cfg := config.CacheConfig{
		L1: config.L1CacheConfig{Enabled: true, MaxSize: 100, TTL: time.Minute},
	}
	svc := NewService(cfg)

	// Should not panic with nil L2
	err := svc.Stop()
	require.NoError(t, err)
}

func TestService_Delete_NotEnabled(t *testing.T) {
	svc := &Service{enabled: false}

	// Should not panic
	svc.Delete(context.Background(), "key")
}

func TestService_Clear_NotEnabled(t *testing.T) {
	svc := &Service{enabled: false}

	// Should not panic
	svc.Clear(context.Background())
}

func TestService_Stats_NotEnabled(t *testing.T) {
	svc := &Service{enabled: false}

	stats := svc.Stats()

	assert.Empty(t, stats)
}

func TestService_Healthy_NotEnabled(t *testing.T) {
	svc := &Service{enabled: false}

	assert.True(t, svc.Healthy(context.Background()))
}
