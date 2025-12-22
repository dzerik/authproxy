package handler

import (
	"github.com/dzerik/auth-portal/internal/config"
	"github.com/dzerik/auth-portal/internal/service/idp"
	"github.com/dzerik/auth-portal/internal/service/session"
)

// ForwardAuthHandlerOption is a functional option for ForwardAuthHandler.
type ForwardAuthHandlerOption func(*ForwardAuthHandler)

// WithForwardAuthSessionManager sets the session manager for the forward auth handler.
func WithForwardAuthSessionManager(sessionMgr *session.Manager) ForwardAuthHandlerOption {
	return func(h *ForwardAuthHandler) {
		h.sessionManager = sessionMgr
	}
}

// WithForwardAuthIDPManager sets the IdP manager for the forward auth handler.
func WithForwardAuthIDPManager(idpMgr *idp.Manager) ForwardAuthHandlerOption {
	return func(h *ForwardAuthHandler) {
		h.idpManager = idpMgr
	}
}

// WithForwardAuthConfig sets the config for the forward auth handler.
func WithForwardAuthConfig(cfg *config.Config) ForwardAuthHandlerOption {
	return func(h *ForwardAuthHandler) {
		h.config = cfg
	}
}

// NewForwardAuthHandlerWithOptions creates a new forward auth handler using functional options.
// This is an alternative constructor that allows for more flexible configuration.
//
// Example usage:
//
//	handler := NewForwardAuthHandlerWithOptions(
//	    WithForwardAuthSessionManager(sessionMgr),
//	    WithForwardAuthIDPManager(idpMgr),
//	    WithForwardAuthConfig(cfg),
//	)
func NewForwardAuthHandlerWithOptions(opts ...ForwardAuthHandlerOption) *ForwardAuthHandler {
	h := &ForwardAuthHandler{}
	for _, opt := range opts {
		opt(h)
	}
	return h
}
