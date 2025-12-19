package config

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNewRemoteConfigSource(t *testing.T) {
	log := zap.NewNop()

	t.Run("valid settings", func(t *testing.T) {
		settings := RemoteSourceSettings{
			Endpoint: "http://localhost:8080",
		}
		source, err := NewRemoteConfigSource(settings, log)
		require.NoError(t, err)
		require.NotNil(t, source)
		defer source.Close()

		assert.Equal(t, "/api/v1/configs/authz/services", source.settings.Paths.Services)
		assert.Equal(t, "/api/v1/configs/authz/rules", source.settings.Paths.Rules)
	})

	t.Run("empty endpoint", func(t *testing.T) {
		settings := RemoteSourceSettings{}
		source, err := NewRemoteConfigSource(settings, log)
		require.Error(t, err)
		assert.Nil(t, source)
		assert.Contains(t, err.Error(), "endpoint is required")
	})

	t.Run("custom paths", func(t *testing.T) {
		settings := RemoteSourceSettings{
			Endpoint: "http://localhost:8080",
			Paths: RemotePathSettings{
				Services: "/custom/services",
				Rules:    "/custom/rules",
			},
		}
		source, err := NewRemoteConfigSource(settings, log)
		require.NoError(t, err)
		defer source.Close()

		assert.Equal(t, "/custom/services", source.settings.Paths.Services)
		assert.Equal(t, "/custom/rules", source.settings.Paths.Rules)
	})
}

func TestRemoteConfigSource_Load(t *testing.T) {
	log := zap.NewNop()

	t.Run("load services config", func(t *testing.T) {
		servicesConfig := ServicesConfig{
			Version: "test-v1",
		}
		configJSON, _ := json.Marshal(servicesConfig)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/api/v1/configs/authz/services", r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Config-Version", "v1.0.0")
			w.Write(configJSON)
		}))
		defer server.Close()

		settings := RemoteSourceSettings{
			Endpoint: server.URL,
		}
		source, err := NewRemoteConfigSource(settings, log)
		require.NoError(t, err)
		defer source.Close()

		ctx := context.Background()
		config, err := source.Load(ctx, ConfigTypeServices)
		require.NoError(t, err)

		svc, ok := config.(*ServicesConfig)
		require.True(t, ok)
		assert.Equal(t, "test-v1", svc.Version)
		assert.Equal(t, "v1.0.0", source.GetVersion(ConfigTypeServices))
	})

	t.Run("load rules config", func(t *testing.T) {
		rulesConfig := RulesConfig{
			Version: "rules-v1",
			Rules: []Rule{
				{Name: "test-rule", Effect: "allow"},
			},
		}
		configJSON, _ := json.Marshal(rulesConfig)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/api/v1/configs/authz/rules", r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			w.Write(configJSON)
		}))
		defer server.Close()

		settings := RemoteSourceSettings{
			Endpoint: server.URL,
		}
		source, err := NewRemoteConfigSource(settings, log)
		require.NoError(t, err)
		defer source.Close()

		ctx := context.Background()
		config, err := source.Load(ctx, ConfigTypeRules)
		require.NoError(t, err)

		rules, ok := config.(*RulesConfig)
		require.True(t, ok)
		assert.Equal(t, "rules-v1", rules.Version)
		assert.Len(t, rules.Rules, 1)
	})

	t.Run("server error with retry", func(t *testing.T) {
		var attempts atomic.Int32

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempt := attempts.Add(1)
			if attempt <= 2 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			// Third attempt succeeds
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(ServicesConfig{Version: "success"})
		}))
		defer server.Close()

		settings := RemoteSourceSettings{
			Endpoint: server.URL,
			Polling: PollingSettings{
				Retry: RetrySettings{
					MaxAttempts: 3,
					Backoff:     10 * time.Millisecond,
					MaxBackoff:  100 * time.Millisecond,
				},
			},
		}
		source, err := NewRemoteConfigSource(settings, log)
		require.NoError(t, err)
		defer source.Close()

		ctx := context.Background()
		config, err := source.Load(ctx, ConfigTypeServices)
		require.NoError(t, err)

		svc, ok := config.(*ServicesConfig)
		require.True(t, ok)
		assert.Equal(t, "success", svc.Version)
		assert.Equal(t, int32(3), attempts.Load())
	})

	t.Run("all retries fail", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		settings := RemoteSourceSettings{
			Endpoint: server.URL,
			Polling: PollingSettings{
				Retry: RetrySettings{
					MaxAttempts: 2,
					Backoff:     10 * time.Millisecond,
					MaxBackoff:  100 * time.Millisecond,
				},
			},
		}
		source, err := NewRemoteConfigSource(settings, log)
		require.NoError(t, err)
		defer source.Close()

		ctx := context.Background()
		_, err = source.Load(ctx, ConfigTypeServices)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load config after")
	})

	t.Run("unsupported config type", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		settings := RemoteSourceSettings{
			Endpoint: server.URL,
		}
		source, err := NewRemoteConfigSource(settings, log)
		require.NoError(t, err)
		defer source.Close()

		ctx := context.Background()
		_, err = source.Load(ctx, ConfigTypeEnvironment)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported config type")
	})
}

func TestRemoteConfigSource_Watch(t *testing.T) {
	log := zap.NewNop()

	t.Run("polling mode", func(t *testing.T) {
		var version atomic.Int32

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			v := version.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Config-Version", fmt.Sprintf("v%d", v))
			json.NewEncoder(w).Encode(ServicesConfig{Version: fmt.Sprintf("svc-v%d", v)})
		}))
		defer server.Close()

		settings := RemoteSourceSettings{
			Endpoint: server.URL,
			Polling: PollingSettings{
				Enabled:  true,
				Interval: 50 * time.Millisecond,
				Timeout:  5 * time.Second,
			},
		}
		source, err := NewRemoteConfigSource(settings, log)
		require.NoError(t, err)
		defer source.Close()

		// Load initial config
		ctx := context.Background()
		_, err = source.Load(ctx, ConfigTypeServices)
		require.NoError(t, err)

		// Start watching
		updates, err := source.Watch(ctx)
		require.NoError(t, err)
		require.NotNil(t, updates)

		// Wait for update
		select {
		case update := <-updates:
			assert.Equal(t, ConfigTypeServices, update.Type)
			assert.Equal(t, "polling", update.Source)
		case <-time.After(200 * time.Millisecond):
			t.Fatal("timeout waiting for update")
		}
	})

	t.Run("watching disabled", func(t *testing.T) {
		settings := RemoteSourceSettings{
			Endpoint: "http://localhost:8080",
			Polling: PollingSettings{
				Enabled: false,
			},
			Push: PushSettings{
				Enabled: false,
			},
		}
		source, err := NewRemoteConfigSource(settings, log)
		require.NoError(t, err)
		defer source.Close()

		ctx := context.Background()
		updates, err := source.Watch(ctx)
		require.NoError(t, err)
		assert.Nil(t, updates)
	})
}

func TestRemoteConfigSource_Auth(t *testing.T) {
	log := zap.NewNop()

	t.Run("token auth", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			assert.Equal(t, "Bearer test-token-123", auth)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(ServicesConfig{Version: "v1"})
		}))
		defer server.Close()

		settings := RemoteSourceSettings{
			Endpoint: server.URL,
			Auth: RemoteAuthSettings{
				Type:  "token",
				Token: "test-token-123",
			},
		}
		source, err := NewRemoteConfigSource(settings, log)
		require.NoError(t, err)
		defer source.Close()

		ctx := context.Background()
		_, err = source.Load(ctx, ConfigTypeServices)
		require.NoError(t, err)
	})
}

func TestRemoteConfigSource_Close(t *testing.T) {
	log := zap.NewNop()

	settings := RemoteSourceSettings{
		Endpoint: "http://localhost:8080",
	}
	source, err := NewRemoteConfigSource(settings, log)
	require.NoError(t, err)

	// Close should succeed
	err = source.Close()
	require.NoError(t, err)

	// Double close should succeed
	err = source.Close()
	require.NoError(t, err)
}

func TestRemoteConfigSource_GetVersion(t *testing.T) {
	log := zap.NewNop()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Config-Version", "v2.0.0")
		json.NewEncoder(w).Encode(ServicesConfig{Version: "test"})
	}))
	defer server.Close()

	settings := RemoteSourceSettings{
		Endpoint: server.URL,
	}
	source, err := NewRemoteConfigSource(settings, log)
	require.NoError(t, err)
	defer source.Close()

	// Before loading, version should be empty
	assert.Empty(t, source.GetVersion(ConfigTypeServices))

	// After loading, version should be set
	ctx := context.Background()
	_, err = source.Load(ctx, ConfigTypeServices)
	require.NoError(t, err)
	assert.Equal(t, "v2.0.0", source.GetVersion(ConfigTypeServices))
}
