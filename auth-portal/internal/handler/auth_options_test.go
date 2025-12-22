package handler

import (
	"html/template"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/service/state"
)

func TestNewAuthHandlerWithOptions(t *testing.T) {
	t.Run("empty options creates empty handler", func(t *testing.T) {
		handler := NewAuthHandlerWithOptions()
		require.NotNil(t, handler)
		assert.Nil(t, handler.idpManager)
		assert.Nil(t, handler.sessionManager)
		assert.Nil(t, handler.config)
		assert.Nil(t, handler.templates)
		assert.Nil(t, handler.stateStore)
	})

	t.Run("with config option", func(t *testing.T) {
		cfg := &config.Config{
			Mode: "test",
		}

		handler := NewAuthHandlerWithOptions(
			WithConfig(cfg),
		)

		require.NotNil(t, handler)
		assert.Equal(t, cfg, handler.config)
	})

	t.Run("with templates option", func(t *testing.T) {
		tmpl := template.New("test")

		handler := NewAuthHandlerWithOptions(
			WithTemplates(tmpl),
		)

		require.NotNil(t, handler)
		assert.Equal(t, tmpl, handler.templates)
	})

	t.Run("with state store option", func(t *testing.T) {
		store := state.NewMemoryStore(0)

		handler := NewAuthHandlerWithOptions(
			WithStateStore(store),
		)

		require.NotNil(t, handler)
		assert.Equal(t, store, handler.stateStore)
	})

	t.Run("with multiple options", func(t *testing.T) {
		cfg := &config.Config{Mode: "test"}
		tmpl := template.New("test")
		store := state.NewMemoryStore(0)

		handler := NewAuthHandlerWithOptions(
			WithConfig(cfg),
			WithTemplates(tmpl),
			WithStateStore(store),
		)

		require.NotNil(t, handler)
		assert.Equal(t, cfg, handler.config)
		assert.Equal(t, tmpl, handler.templates)
		assert.Equal(t, store, handler.stateStore)
	})
}

func TestWithIDPManager(t *testing.T) {
	// IDPManager requires actual initialization which is complex,
	// so we just verify the option function doesn't panic
	opt := WithIDPManager(nil)
	handler := &AuthHandler{}
	assert.NotPanics(t, func() { opt(handler) })
	assert.Nil(t, handler.idpManager)
}

func TestWithSessionManager(t *testing.T) {
	// SessionManager requires actual initialization which is complex,
	// so we just verify the option function doesn't panic
	opt := WithSessionManager(nil)
	handler := &AuthHandler{}
	assert.NotPanics(t, func() { opt(handler) })
	assert.Nil(t, handler.sessionManager)
}

func TestWithConfig(t *testing.T) {
	cfg := &config.Config{Mode: "production"}
	opt := WithConfig(cfg)
	handler := &AuthHandler{}
	opt(handler)
	assert.Equal(t, cfg, handler.config)
}

func TestWithTemplates(t *testing.T) {
	tmpl := template.New("custom")
	opt := WithTemplates(tmpl)
	handler := &AuthHandler{}
	opt(handler)
	assert.Equal(t, tmpl, handler.templates)
}

func TestWithStateStore(t *testing.T) {
	store := state.NewMemoryStore(0)
	opt := WithStateStore(store)
	handler := &AuthHandler{}
	opt(handler)
	assert.Equal(t, store, handler.stateStore)
}
