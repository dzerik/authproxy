// Package policy provides policy evaluation engines.
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/internal/domain"
	"github.com/your-org/authz-service/pkg/logger"
)

// OPAEmbeddedEngine implements policy evaluation using OPA as an embedded Go library.
// This provides the lowest latency option (<100μs) for policy evaluation.
type OPAEmbeddedEngine struct {
	mu           sync.RWMutex
	query        rego.PreparedEvalQuery
	store        storage.Store
	cfg          config.OPAEmbeddedConfig
	policyDir    string
	dataDir      string
	decisionPath string
	watcher      *fsnotify.Watcher
	healthy      bool
	loadedAt     time.Time
}

// NewOPAEmbeddedEngine creates a new OPA embedded policy engine.
func NewOPAEmbeddedEngine(cfg config.OPAEmbeddedConfig) *OPAEmbeddedEngine {
	return &OPAEmbeddedEngine{
		cfg:          cfg,
		decisionPath: cfg.DecisionPath,
		policyDir:    cfg.PolicyDir,
		dataDir:      cfg.DataDir,
	}
}

// Name returns the engine name.
func (e *OPAEmbeddedEngine) Name() string {
	return "opa-embedded"
}

// Start initializes the OPA embedded engine.
func (e *OPAEmbeddedEngine) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Create in-memory store for data
	e.store = inmem.New()

	// Load data if data directory is specified
	if e.dataDir != "" {
		if err := e.loadData(ctx); err != nil {
			logger.Warn("failed to load OPA data, continuing without it",
				logger.String("data_dir", e.dataDir),
				logger.Err(err),
			)
		}
	}

	// Prepare the Rego query
	if err := e.prepareQuery(ctx); err != nil {
		return fmt.Errorf("failed to prepare OPA query: %w", err)
	}

	// Setup hot reload if enabled
	if e.cfg.HotReload {
		if err := e.setupWatcher(); err != nil {
			logger.Warn("failed to setup hot reload, continuing without it",
				logger.Err(err),
			)
		}
	}

	e.healthy = true
	e.loadedAt = time.Now()

	logger.Info("OPA embedded engine started",
		logger.String("policy_dir", e.policyDir),
		logger.String("decision_path", e.decisionPath),
		logger.Bool("hot_reload", e.cfg.HotReload),
	)

	return nil
}

// Stop stops the OPA embedded engine.
func (e *OPAEmbeddedEngine) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.healthy = false

	if e.watcher != nil {
		e.watcher.Close()
	}

	return nil
}

// Healthy returns true if the engine is healthy.
func (e *OPAEmbeddedEngine) Healthy(ctx context.Context) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.healthy
}

// Evaluate evaluates the policy with the given input.
func (e *OPAEmbeddedEngine) Evaluate(ctx context.Context, input *domain.PolicyInput) (*domain.Decision, error) {
	e.mu.RLock()
	query := e.query
	e.mu.RUnlock()

	start := time.Now()

	// Convert input to map for OPA
	inputMap, err := inputToMap(input)
	if err != nil {
		return nil, fmt.Errorf("failed to convert input: %w", err)
	}

	// Evaluate the query
	results, err := query.Eval(ctx, rego.EvalInput(inputMap))
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate policy: %w", err)
	}

	decision := &domain.Decision{
		EvaluatedAt: time.Now(),
		Metadata: map[string]any{
			"engine":          "opa-embedded",
			"evaluation_time": time.Since(start).String(),
		},
	}

	// Parse results
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		// No result means deny
		decision.Allowed = false
		decision.Reasons = []string{"no policy decision returned"}
		return decision, nil
	}

	// Handle different result types
	result := results[0].Expressions[0].Value
	switch v := result.(type) {
	case bool:
		decision.Allowed = v
		if !v {
			decision.Reasons = []string{"policy denied access"}
		}
	case map[string]interface{}:
		// Complex result with allow and reasons
		if allow, ok := v["allow"].(bool); ok {
			decision.Allowed = allow
		}
		if reasons, ok := v["reasons"].([]interface{}); ok {
			for _, r := range reasons {
				if rs, ok := r.(string); ok {
					decision.Reasons = append(decision.Reasons, rs)
				}
			}
		}
		if headers, ok := v["headers_to_add"].(map[string]interface{}); ok {
			decision.HeadersToAdd = make(map[string]string)
			for k, hv := range headers {
				if hs, ok := hv.(string); ok {
					decision.HeadersToAdd[k] = hs
				}
			}
		}
		if remove, ok := v["headers_to_remove"].([]interface{}); ok {
			for _, h := range remove {
				if hs, ok := h.(string); ok {
					decision.HeadersToRemove = append(decision.HeadersToRemove, hs)
				}
			}
		}
	default:
		return nil, fmt.Errorf("unexpected result type: %T", result)
	}

	logger.Debug("OPA embedded evaluation completed",
		logger.Bool("allowed", decision.Allowed),
		logger.Duration("duration", time.Since(start)),
	)

	return decision, nil
}

// prepareQuery compiles and prepares the Rego query.
func (e *OPAEmbeddedEngine) prepareQuery(ctx context.Context) error {
	// Build decision query
	queryStr := "data." + e.decisionPath
	if e.decisionPath == "" {
		queryStr = "data.authz.allow"
	}

	// Find all Rego files
	var policyFiles []string

	// Handle bundle path (tar.gz)
	if e.cfg.BundlePath != "" {
		// For bundle, we'd need to extract it first
		// For simplicity, support directory mode primarily
		logger.Warn("bundle path specified but not fully supported, use policy_dir instead",
			logger.String("bundle_path", e.cfg.BundlePath),
		)
	}

	// Load from policy directory
	if e.policyDir != "" {
		files, err := filepath.Glob(filepath.Join(e.policyDir, "*.rego"))
		if err != nil {
			return fmt.Errorf("failed to glob policy files: %w", err)
		}
		policyFiles = append(policyFiles, files...)

		// Also check subdirectories
		subfiles, err := filepath.Glob(filepath.Join(e.policyDir, "**", "*.rego"))
		if err == nil {
			policyFiles = append(policyFiles, subfiles...)
		}
	}

	if len(policyFiles) == 0 {
		return fmt.Errorf("no policy files found in %s", e.policyDir)
	}

	logger.Info("loading OPA policies",
		logger.Int("file_count", len(policyFiles)),
		logger.Strings("files", policyFiles),
	)

	// Create Rego instance
	r := rego.New(
		rego.Query(queryStr),
		rego.Load(policyFiles, nil),
		rego.Store(e.store),
	)

	// Prepare for evaluation
	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("failed to prepare query: %w", err)
	}

	e.query = query
	return nil
}

// loadData loads external data into the OPA store.
func (e *OPAEmbeddedEngine) loadData(ctx context.Context) error {
	// Check if data directory exists
	info, err := os.Stat(e.dataDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No data directory, that's ok
		}
		return err
	}

	if !info.IsDir() {
		return fmt.Errorf("data path is not a directory: %s", e.dataDir)
	}

	// Find all JSON files in data directory
	files, err := filepath.Glob(filepath.Join(e.dataDir, "*.json"))
	if err != nil {
		return err
	}

	txn, err := e.store.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		return fmt.Errorf("failed to create transaction: %w", err)
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			e.store.Abort(ctx, txn)
			return fmt.Errorf("failed to read %s: %w", file, err)
		}

		var jsonData interface{}
		if err := json.Unmarshal(data, &jsonData); err != nil {
			e.store.Abort(ctx, txn)
			return fmt.Errorf("failed to parse %s: %w", file, err)
		}

		// Use filename (without extension) as path
		name := filepath.Base(file)
		name = name[:len(name)-len(filepath.Ext(name))]
		path := storage.MustParsePath("/" + name)

		if err := e.store.Write(ctx, txn, storage.AddOp, path, jsonData); err != nil {
			e.store.Abort(ctx, txn)
			return fmt.Errorf("failed to write data for %s: %w", name, err)
		}

		logger.Debug("loaded OPA data file",
			logger.String("file", file),
			logger.String("path", name),
		)
	}

	if err := e.store.Commit(ctx, txn); err != nil {
		return fmt.Errorf("failed to commit data: %w", err)
	}

	logger.Info("loaded OPA data files",
		logger.Int("file_count", len(files)),
	)

	return nil
}

// setupWatcher sets up file watching for hot reload.
func (e *OPAEmbeddedEngine) setupWatcher() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	// Watch policy directory
	if e.policyDir != "" {
		if err := watcher.Add(e.policyDir); err != nil {
			watcher.Close()
			return err
		}
	}

	// Watch data directory
	if e.dataDir != "" {
		if err := watcher.Add(e.dataDir); err != nil {
			// Not critical, just log
			logger.Warn("failed to watch data directory",
				logger.String("dir", e.dataDir),
				logger.Err(err),
			)
		}
	}

	e.watcher = watcher

	// Start watching in background
	go e.watchForChanges()

	return nil
}

// watchForChanges watches for file changes and triggers reload.
func (e *OPAEmbeddedEngine) watchForChanges() {
	debounceTimer := time.NewTimer(0)
	<-debounceTimer.C // Drain initial event

	for {
		select {
		case event, ok := <-e.watcher.Events:
			if !ok {
				return
			}

			// Debounce rapid changes
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				debounceTimer.Reset(500 * time.Millisecond)
			}

		case <-debounceTimer.C:
			logger.Info("reloading OPA policies due to file change")
			e.reload()

		case err, ok := <-e.watcher.Errors:
			if !ok {
				return
			}
			logger.Error("watcher error", logger.Err(err))
		}
	}
}

// reload reloads policies.
func (e *OPAEmbeddedEngine) reload() {
	e.mu.Lock()
	defer e.mu.Unlock()

	ctx := context.Background()

	// Reload data
	if e.dataDir != "" {
		if err := e.loadData(ctx); err != nil {
			logger.Error("failed to reload OPA data", logger.Err(err))
		}
	}

	// Reload policies
	if err := e.prepareQuery(ctx); err != nil {
		logger.Error("failed to reload OPA policies", logger.Err(err))
		e.healthy = false
		return
	}

	e.healthy = true
	e.loadedAt = time.Now()
	logger.Info("OPA policies reloaded successfully")
}

// inputToMap converts PolicyInput to a map for OPA evaluation.
func inputToMap(input *domain.PolicyInput) (map[string]interface{}, error) {
	// Use JSON marshaling for clean conversion
	data, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return result, nil
}
