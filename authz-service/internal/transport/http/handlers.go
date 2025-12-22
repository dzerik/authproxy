package http

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/your-org/authz-service/internal/domain"
	"github.com/your-org/authz-service/pkg/errors"
	"github.com/your-org/authz-service/pkg/logger"
)

// JWTService defines the interface for JWT validation operations.
type JWTService interface {
	ValidateFromHeader(ctx context.Context, authHeader string) (*domain.TokenInfo, error)
	ValidateToken(ctx context.Context, token string) (*domain.TokenInfo, error)
}

// PolicyService defines the interface for policy evaluation operations.
type PolicyService interface {
	Evaluate(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error)
	Healthy(ctx context.Context) bool
	Reload(ctx context.Context) error
}

// CacheService defines the interface for cache operations.
type CacheService interface {
	Clear(ctx context.Context)
	Stats() map[string]any
	Enabled() bool
}

// Handler contains HTTP handlers for the authorization service.
type Handler struct {
	jwtService    JWTService
	policyService PolicyService
	cacheService  CacheService
	version       string
}

// NewHandler creates a new HTTP handler.
func NewHandler(jwtService JWTService, policyService PolicyService, version string, opts ...HandlerOption) *Handler {
	h := &Handler{
		jwtService:    jwtService,
		policyService: policyService,
		version:       version,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// HandlerOption is a functional option for configuring the Handler.
type HandlerOption func(*Handler)

// WithCacheService sets the cache service for the handler.
func WithCacheService(cs CacheService) HandlerOption {
	return func(h *Handler) {
		h.cacheService = cs
	}
}

// Authorize handles authorization requests.
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := getRequestID(r)
	start := time.Now()

	// Parse request body
	var req AuthzRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request body", requestID)
		return
	}

	// Convert to policy input
	input := req.ToPolicyInput()

	// Extract and validate JWT token if present
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		// Check X-Forwarded-Authorization for proxied requests
		authHeader = r.Header.Get("X-Forwarded-Authorization")
	}

	if authHeader != "" {
		tokenInfo, err := h.jwtService.ValidateFromHeader(ctx, authHeader)
		if err != nil {
			var authzErr *errors.AuthzError
			if errors.As(err, &authzErr) {
				h.writeError(w, http.StatusUnauthorized, authzErr.Code, authzErr.Message, requestID)
			} else {
				h.writeError(w, http.StatusUnauthorized, errors.CodeTokenInvalid, err.Error(), requestID)
			}
			return
		}
		input.Token = tokenInfo
	}

	// Set context info
	input.Context.RequestID = requestID
	input.Context.Timestamp = time.Now().Unix()

	// Set source info
	input.Source.Address = getClientIP(r)

	// Evaluate policy
	decision, err := h.policyService.Evaluate(ctx, input)
	if err != nil {
		logger.Error("policy evaluation failed",
			logger.String("request_id", requestID),
			logger.Err(err),
		)
		h.writeError(w, http.StatusInternalServerError, errors.CodePolicyError, "policy evaluation failed", requestID)
		return
	}

	// Log the decision
	logger.Info("authorization decision",
		logger.String("request_id", requestID),
		logger.Bool("allowed", decision.Allowed),
		logger.String("method", input.Request.Method),
		logger.String("path", input.Request.Path),
		logger.Duration("duration", time.Since(start)),
	)

	// Return response
	resp := FromDecision(decision)
	h.writeJSON(w, http.StatusOK, resp)
}

// ValidateToken handles token validation requests.
func (h *Handler) ValidateToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := getRequestID(r)

	// Get token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		h.writeError(w, http.StatusBadRequest, errors.CodeTokenMissing, "Authorization header required", requestID)
		return
	}

	tokenInfo, err := h.jwtService.ValidateFromHeader(ctx, authHeader)
	if err != nil {
		var authzErr *errors.AuthzError
		if errors.As(err, &authzErr) {
			resp := &TokenInfoResponse{
				Valid:     false,
				Error:     authzErr.Message,
				ErrorCode: authzErr.Code,
			}
			h.writeJSON(w, http.StatusOK, resp)
		} else {
			resp := &TokenInfoResponse{
				Valid:     false,
				Error:     err.Error(),
				ErrorCode: errors.CodeTokenInvalid,
			}
			h.writeJSON(w, http.StatusOK, resp)
		}
		return
	}

	resp := FromTokenInfo(tokenInfo)
	h.writeJSON(w, http.StatusOK, resp)
}

// Health handles health check requests.
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	checks := make(map[string]CheckResult)

	// Check policy service
	if h.policyService.Healthy(ctx) {
		checks["policy"] = CheckResult{Status: "healthy"}
	} else {
		checks["policy"] = CheckResult{Status: "unhealthy", Message: "policy engine not ready"}
	}

	// Determine overall status
	status := "healthy"
	for _, check := range checks {
		if check.Status != "healthy" {
			status = "unhealthy"
			break
		}
	}

	resp := &HealthResponse{
		Status:    status,
		Checks:    checks,
		Version:   h.version,
		Timestamp: time.Now(),
	}

	statusCode := http.StatusOK
	if status != "healthy" {
		statusCode = http.StatusServiceUnavailable
	}

	h.writeJSON(w, statusCode, resp)
}

// Ready handles readiness check requests.
func (h *Handler) Ready(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if !h.policyService.Healthy(ctx) {
		h.writeError(w, http.StatusServiceUnavailable, "NOT_READY", "service not ready", "")
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// Live handles liveness check requests.
func (h *Handler) Live(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// AuthorizeBatch handles batch authorization requests.
func (h *Handler) AuthorizeBatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := getRequestID(r)
	start := time.Now()

	// Parse request body
	var req BatchAuthzRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request body", requestID)
		return
	}

	if len(req.Requests) == 0 {
		h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "requests array is empty", requestID)
		return
	}

	// Process each request
	responses := make([]AuthzResponse, 0, len(req.Requests))

	for _, authReq := range req.Requests {
		input := authReq.ToPolicyInput()

		// Use shared token if provided at batch level
		if req.Token != "" {
			tokenInfo, err := h.jwtService.ValidateFromHeader(ctx, "Bearer "+req.Token)
			if err == nil {
				input.Token = tokenInfo
			}
		}

		// Set context info
		input.Context.RequestID = requestID
		input.Context.Timestamp = time.Now().Unix()

		// Evaluate policy
		decision, err := h.policyService.Evaluate(ctx, input)
		if err != nil {
			responses = append(responses, AuthzResponse{
				Allowed:     false,
				Reasons:     []string{"policy evaluation failed"},
				EvaluatedAt: time.Now(),
			})
			continue
		}

		responses = append(responses, *FromDecision(decision))
	}

	// Log the batch decision
	allowedCount := 0
	for _, resp := range responses {
		if resp.Allowed {
			allowedCount++
		}
	}

	logger.Info("batch authorization decision",
		logger.String("request_id", requestID),
		logger.Int("total", len(responses)),
		logger.Int("allowed", allowedCount),
		logger.Duration("duration", time.Since(start)),
	)

	// Return response
	resp := &BatchAuthzResponse{
		Responses: responses,
	}
	h.writeJSON(w, http.StatusOK, resp)
}

// TokenExchange handles OAuth 2.0 token exchange requests (RFC 8693).
func (h *Handler) TokenExchange(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := getRequestID(r)

	// Parse request body (could be form or JSON)
	var req TokenExchangeRequest

	contentType := r.Header.Get("Content-Type")
	if contentType == "application/x-www-form-urlencoded" {
		if err := r.ParseForm(); err != nil {
			h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "failed to parse form", requestID)
			return
		}
		req = TokenExchangeRequest{
			SubjectToken:       r.FormValue("subject_token"),
			SubjectTokenType:   r.FormValue("subject_token_type"),
			ActorToken:         r.FormValue("actor_token"),
			ActorTokenType:     r.FormValue("actor_token_type"),
			RequestedTokenType: r.FormValue("requested_token_type"),
			Audience:           r.FormValue("audience"),
			Scope:              r.FormValue("scope"),
			Resource:           r.FormValue("resource"),
		}
	} else {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request body", requestID)
			return
		}
	}

	// Validate required fields
	if req.SubjectToken == "" {
		h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "subject_token is required", requestID)
		return
	}

	// Validate subject token
	tokenInfo, err := h.jwtService.ValidateToken(ctx, req.SubjectToken)
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, errors.CodeTokenInvalid, "invalid subject_token", requestID)
		return
	}

	// For now, return a placeholder response
	// In production, this would call Keycloak's token exchange endpoint
	logger.Info("token exchange request",
		logger.String("request_id", requestID),
		logger.String("subject", tokenInfo.Subject),
		logger.String("audience", req.Audience),
	)

	// TODO: Implement actual token exchange via Keycloak
	h.writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "token exchange not implemented", requestID)
}

// CacheInvalidate handles cache invalidation requests.
// POST /admin/cache/invalidate - clears L1 and L2 caches
func (h *Handler) CacheInvalidate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := getRequestID(r)

	// Parse request body (optional)
	var req CacheInvalidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// If no body, invalidate all
		req.Pattern = "*"
	}

	logger.Info("cache invalidation request",
		logger.String("request_id", requestID),
		logger.String("pattern", req.Pattern),
	)

	// Check if cache service is available
	if h.cacheService == nil {
		h.writeError(w, http.StatusServiceUnavailable, "CACHE_NOT_AVAILABLE", "cache service not configured", requestID)
		return
	}

	// Clear all caches
	h.cacheService.Clear(ctx)

	// Get stats after clearing
	stats := h.cacheService.Stats()

	logger.Info("cache invalidation completed",
		logger.String("request_id", requestID),
		logger.Any("stats", stats),
	)

	resp := &CacheInvalidateResponse{
		Success: true,
		Message: "cache invalidation completed (L1 and L2 cleared)",
		Stats:   stats,
	}
	h.writeJSON(w, http.StatusOK, resp)
}

// PolicyReload handles policy reload requests.
func (h *Handler) PolicyReload(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := getRequestID(r)

	logger.Info("policy reload request",
		logger.String("request_id", requestID),
	)

	// Reload policy
	if err := h.policyService.Reload(ctx); err != nil {
		h.writeError(w, http.StatusInternalServerError, "RELOAD_FAILED", err.Error(), requestID)
		return
	}

	resp := map[string]any{
		"success": true,
		"message": "policy reloaded successfully",
	}
	h.writeJSON(w, http.StatusOK, resp)
}

// Helper methods

func (h *Handler) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		logger.Error("failed to encode response", logger.Err(err))
	}
}

func (h *Handler) writeError(w http.ResponseWriter, status int, code, message, requestID string) {
	resp := &ErrorResponse{
		Error:     message,
		Code:      code,
		RequestID: requestID,
	}
	h.writeJSON(w, status, resp)
}

func getRequestID(r *http.Request) string {
	// Check for existing request ID
	if id := r.Header.Get("X-Request-ID"); id != "" {
		return id
	}
	if id := r.Header.Get("X-Correlation-ID"); id != "" {
		return id
	}
	// Generate new UUID
	return uuid.New().String()
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fall back to RemoteAddr
	return r.RemoteAddr
}

// RegisterRoutes registers all HTTP routes.
func (h *Handler) RegisterRoutes(r chi.Router) {
	// API routes
	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/authorize", h.Authorize)
		r.Post("/authz", h.Authorize) // Alias
		r.Get("/token/validate", h.ValidateToken)
		r.Post("/token/validate", h.ValidateToken)
	})

	// Health routes
	r.Get("/health", h.Health)
	r.Get("/healthz", h.Health)
	r.Get("/ready", h.Ready)
	r.Get("/readyz", h.Ready)
	r.Get("/live", h.Live)
	r.Get("/livez", h.Live)
}
