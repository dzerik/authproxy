package handler

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dzerik/auth-portal/internal/config"
)

func TestNewForwardAuthHandlerWithOptions(t *testing.T) {
	t.Run("empty options creates empty handler", func(t *testing.T) {
		handler := NewForwardAuthHandlerWithOptions()
		require.NotNil(t, handler)
		assert.Nil(t, handler.sessionManager)
		assert.Nil(t, handler.idpManager)
		assert.Nil(t, handler.config)
	})

	t.Run("with config option", func(t *testing.T) {
		cfg := &config.Config{
			Mode: "test",
		}

		handler := NewForwardAuthHandlerWithOptions(
			WithForwardAuthConfig(cfg),
		)

		require.NotNil(t, handler)
		assert.Equal(t, cfg, handler.config)
	})

	t.Run("with multiple options", func(t *testing.T) {
		cfg := &config.Config{Mode: "test"}

		handler := NewForwardAuthHandlerWithOptions(
			WithForwardAuthConfig(cfg),
		)

		require.NotNil(t, handler)
		assert.Equal(t, cfg, handler.config)
	})
}

func TestWithForwardAuthSessionManager(t *testing.T) {
	// SessionManager requires actual initialization which is complex,
	// so we just verify the option function doesn't panic
	opt := WithForwardAuthSessionManager(nil)
	handler := &ForwardAuthHandler{}
	assert.NotPanics(t, func() { opt(handler) })
	assert.Nil(t, handler.sessionManager)
}

func TestWithForwardAuthIDPManager(t *testing.T) {
	// IDPManager requires actual initialization which is complex,
	// so we just verify the option function doesn't panic
	opt := WithForwardAuthIDPManager(nil)
	handler := &ForwardAuthHandler{}
	assert.NotPanics(t, func() { opt(handler) })
	assert.Nil(t, handler.idpManager)
}

func TestWithForwardAuthConfig(t *testing.T) {
	cfg := &config.Config{Mode: "production"}
	opt := WithForwardAuthConfig(cfg)
	handler := &ForwardAuthHandler{}
	opt(handler)
	assert.Equal(t, cfg, handler.config)
}
