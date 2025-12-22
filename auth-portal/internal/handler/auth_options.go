package handler

import (
	"html/template"

	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/service/idp"
	"github.com/dzerik/auth-portal/internal/service/session"
	"github.com/dzerik/auth-portal/internal/service/state"
)

// AuthHandlerOption is a functional option for AuthHandler.
type AuthHandlerOption func(*AuthHandler)

// WithIDPManager sets the IdP manager for the auth handler.
func WithIDPManager(idpMgr *idp.Manager) AuthHandlerOption {
	return func(h *AuthHandler) {
		h.idpManager = idpMgr
	}
}

// WithSessionManager sets the session manager for the auth handler.
func WithSessionManager(sessionMgr *session.Manager) AuthHandlerOption {
	return func(h *AuthHandler) {
		h.sessionManager = sessionMgr
	}
}

// WithConfig sets the config for the auth handler.
func WithConfig(cfg *config.Config) AuthHandlerOption {
	return func(h *AuthHandler) {
		h.config = cfg
	}
}

// WithTemplates sets the templates for the auth handler.
func WithTemplates(templates *template.Template) AuthHandlerOption {
	return func(h *AuthHandler) {
		h.templates = templates
	}
}

// WithStateStore sets the state store for the auth handler.
func WithStateStore(stateStore state.Store) AuthHandlerOption {
	return func(h *AuthHandler) {
		h.stateStore = stateStore
	}
}

// NewAuthHandlerWithOptions creates a new auth handler using functional options.
// This is an alternative constructor that allows for more flexible configuration.
//
// Example usage:
//
//	handler := NewAuthHandlerWithOptions(
//	    WithIDPManager(idpMgr),
//	    WithSessionManager(sessionMgr),
//	    WithConfig(cfg),
//	    WithTemplates(templates),
//	    WithStateStore(stateStore),
//	)
func NewAuthHandlerWithOptions(opts ...AuthHandlerOption) *AuthHandler {
	h := &AuthHandler{}
	for _, opt := range opts {
		opt(h)
	}
	return h
}
