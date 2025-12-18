package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/internal/domain"
	"github.com/your-org/authz-service/pkg/errors"
	"github.com/your-org/authz-service/pkg/logger"
	"github.com/your-org/authz-service/pkg/resilience/circuitbreaker"
)

const (
	// OPACircuitBreakerName is the circuit breaker name for OPA sidecar.
	OPACircuitBreakerName = "opa-sidecar"
)

// OPASidecarEngine implements policy evaluation via OPA HTTP API.
type OPASidecarEngine struct {
	client     *http.Client
	url        string
	policyPath string
	retry      config.RetryConfig
	cbManager  *circuitbreaker.Manager
}

// opaRequest is the request body for OPA.
type opaRequest struct {
	Input *domain.PolicyInput `json:"input"`
}

// opaResponse is the response from OPA.
type opaResponse struct {
	Result       opaResult `json:"result,omitempty"`
	DecisionID   string    `json:"decision_id,omitempty"`
	Metrics      opaMetrics `json:"metrics,omitempty"`
}

// opaResult is the OPA evaluation result.
type opaResult struct {
	Allow   bool     `json:"allow"`
	Reasons []string `json:"reasons,omitempty"`
}

// opaMetrics contains OPA timing metrics.
type opaMetrics struct {
	TimerRegoQueryEvalNs int64 `json:"timer_rego_query_eval_ns,omitempty"`
}

// NewOPASidecarEngine creates a new OPA sidecar engine.
func NewOPASidecarEngine(cfg config.OPAConfig) *OPASidecarEngine {
	return &OPASidecarEngine{
		client: &http.Client{
			Timeout: cfg.Timeout,
		},
		url:        cfg.URL,
		policyPath: cfg.PolicyPath,
		retry:      cfg.Retry,
	}
}

// NewOPASidecarEngineWithCB creates a new OPA sidecar engine with circuit breaker.
func NewOPASidecarEngineWithCB(cfg config.OPAConfig, cbManager *circuitbreaker.Manager) *OPASidecarEngine {
	return &OPASidecarEngine{
		client: &http.Client{
			Timeout: cfg.Timeout,
		},
		url:        cfg.URL,
		policyPath: cfg.PolicyPath,
		retry:      cfg.Retry,
		cbManager:  cbManager,
	}
}

// SetCircuitBreaker sets the circuit breaker manager for the engine.
func (e *OPASidecarEngine) SetCircuitBreaker(cbManager *circuitbreaker.Manager) {
	e.cbManager = cbManager
}

// Name returns the engine name.
func (e *OPASidecarEngine) Name() string {
	return "opa-sidecar"
}

// Start initializes the OPA sidecar engine.
func (e *OPASidecarEngine) Start(ctx context.Context) error {
	// Verify OPA is reachable
	if !e.Healthy(ctx) {
		logger.Warn("OPA sidecar not reachable at startup",
			logger.String("url", e.url),
		)
	}

	logger.Info("OPA sidecar engine started",
		logger.String("url", e.url),
		logger.String("policy_path", e.policyPath),
	)

	return nil
}

// Stop shuts down the OPA sidecar engine.
func (e *OPASidecarEngine) Stop() error {
	return nil
}

// Healthy checks if OPA is reachable.
func (e *OPASidecarEngine) Healthy(ctx context.Context) bool {
	healthURL := e.url + "/health"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return false
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// Evaluate evaluates a policy using OPA HTTP API.
// If circuit breaker is configured, wraps the call with circuit breaker protection.
func (e *OPASidecarEngine) Evaluate(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
	// If circuit breaker is configured, use it
	if e.cbManager != nil {
		return e.evaluateWithCircuitBreaker(ctx, input)
	}

	return e.evaluateWithRetry(ctx, input)
}

// evaluateWithCircuitBreaker wraps evaluation with circuit breaker protection.
func (e *OPASidecarEngine) evaluateWithCircuitBreaker(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
	result, err := circuitbreaker.ExecuteTyped(e.cbManager, ctx, OPACircuitBreakerName, func() (*domain.Decision, error) {
		return e.evaluateWithRetry(ctx, input)
	})

	if err != nil {
		// Check if it's a circuit breaker open error
		logger.Warn("OPA circuit breaker error",
			logger.String("state", e.cbManager.State(OPACircuitBreakerName).String()),
			logger.Err(err),
		)
		return nil, errors.Wrap(errors.ErrServiceUnavailable, "OPA circuit breaker open: "+err.Error())
	}

	return result, nil
}

// evaluateWithRetry performs evaluation with retry logic.
func (e *OPASidecarEngine) evaluateWithRetry(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
	var lastErr error

	for attempt := 0; attempt < e.retry.MaxAttempts; attempt++ {
		decision, err := e.doEvaluate(ctx, input)
		if err == nil {
			return decision, nil
		}

		lastErr = err
		logger.Debug("OPA evaluation attempt failed",
			logger.Int("attempt", attempt+1),
			logger.Err(err),
		)

		// Calculate backoff
		backoff := e.calculateBackoff(attempt)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
	}

	return nil, errors.Wrap(errors.ErrPolicyEvaluation, lastErr.Error())
}

// doEvaluate performs a single OPA evaluation request.
func (e *OPASidecarEngine) doEvaluate(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
	// Build request
	reqBody := opaRequest{Input: input}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OPA request: %w", err)
	}

	url := e.url + e.policyPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create OPA request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OPA request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OPA response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OPA returned status %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse response
	var opaResp opaResponse
	if err := json.Unmarshal(respBody, &opaResp); err != nil {
		return nil, fmt.Errorf("failed to parse OPA response: %w", err)
	}

	// Build decision
	decision := &domain.Decision{
		Allowed:     opaResp.Result.Allow,
		Reasons:     opaResp.Result.Reasons,
		EvaluatedAt: time.Now(),
		Cached:      false,
		Metadata: map[string]any{
			"opa_decision_id": opaResp.DecisionID,
			"engine":          "opa-sidecar",
		},
	}

	if opaResp.Metrics.TimerRegoQueryEvalNs > 0 {
		decision.Metadata["opa_eval_time_ns"] = opaResp.Metrics.TimerRegoQueryEvalNs
	}

	return decision, nil
}

// calculateBackoff calculates the backoff duration for a retry attempt.
func (e *OPASidecarEngine) calculateBackoff(attempt int) time.Duration {
	backoff := e.retry.InitialBackoff
	for i := 0; i < attempt; i++ {
		backoff *= 2
		if backoff > e.retry.MaxBackoff {
			backoff = e.retry.MaxBackoff
			break
		}
	}
	return backoff
}
