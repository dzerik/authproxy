package config

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// RemoteConfigSource implements ConfigSource for fetching configs from a remote HTTP service.
// Supports both polling and Server-Sent Events (SSE) for real-time updates.
type RemoteConfigSource struct {
	settings RemoteSourceSettings
	log      *zap.Logger
	client   *http.Client

	versions map[ConfigType]string
	mu       sync.RWMutex

	ctx       context.Context
	cancel    context.CancelFunc
	closed    atomic.Bool
	updatesCh chan ConfigUpdate
}

// NewRemoteConfigSource creates a new remote configuration source.
func NewRemoteConfigSource(settings RemoteSourceSettings, log *zap.Logger) (*RemoteConfigSource, error) {
	if settings.Endpoint == "" {
		return nil, fmt.Errorf("remote config endpoint is required")
	}

	client, err := createHTTPClient(settings)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Set default paths
	if settings.Paths.Services == "" {
		settings.Paths.Services = "/api/v1/configs/authz/services"
	}
	if settings.Paths.Rules == "" {
		settings.Paths.Rules = "/api/v1/configs/authz/rules"
	}

	// Set default polling settings
	if settings.Polling.Interval == 0 {
		settings.Polling.Interval = 30 * time.Second
	}
	if settings.Polling.Timeout == 0 {
		settings.Polling.Timeout = 10 * time.Second
	}
	if settings.Polling.Retry.MaxAttempts == 0 {
		settings.Polling.Retry.MaxAttempts = 3
	}
	if settings.Polling.Retry.Backoff == 0 {
		settings.Polling.Retry.Backoff = time.Second
	}
	if settings.Polling.Retry.MaxBackoff == 0 {
		settings.Polling.Retry.MaxBackoff = 30 * time.Second
	}

	return &RemoteConfigSource{
		settings:  settings,
		log:       log.Named("remote-config-source"),
		client:    client,
		versions:  make(map[ConfigType]string),
		updatesCh: make(chan ConfigUpdate, 10),
	}, nil
}

// Load loads the specified configuration type from the remote service.
func (s *RemoteConfigSource) Load(ctx context.Context, configType ConfigType) (interface{}, error) {
	path := s.getPathForType(configType)
	if path == "" {
		return nil, fmt.Errorf("unsupported config type: %s", configType)
	}

	url := strings.TrimSuffix(s.settings.Endpoint, "/") + path

	var lastErr error
	backoff := s.settings.Polling.Retry.Backoff

	for attempt := 0; attempt <= s.settings.Polling.Retry.MaxAttempts; attempt++ {
		if attempt > 0 {
			s.log.Info("retrying config fetch",
				zap.String("type", string(configType)),
				zap.Int("attempt", attempt),
				zap.Duration("backoff", backoff))

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}

			backoff *= 2
			if backoff > s.settings.Polling.Retry.MaxBackoff {
				backoff = s.settings.Polling.Retry.MaxBackoff
			}
		}

		config, version, err := s.fetchConfig(ctx, url, configType)
		if err != nil {
			lastErr = err
			s.log.Warn("failed to fetch config",
				zap.String("type", string(configType)),
				zap.String("url", url),
				zap.Error(err))
			continue
		}

		s.mu.Lock()
		s.versions[configType] = version
		s.mu.Unlock()

		s.log.Info("loaded config from remote",
			zap.String("type", string(configType)),
			zap.String("version", version))

		return config, nil
	}

	return nil, fmt.Errorf("failed to load config after %d attempts: %w",
		s.settings.Polling.Retry.MaxAttempts, lastErr)
}

// Watch starts watching for configuration changes.
func (s *RemoteConfigSource) Watch(ctx context.Context) (<-chan ConfigUpdate, error) {
	s.mu.Lock()
	if s.ctx != nil {
		s.mu.Unlock()
		return s.updatesCh, nil
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.mu.Unlock()

	if s.settings.Push.Enabled && s.settings.Push.Type == "sse" {
		go s.watchSSE()
	} else if s.settings.Polling.Enabled {
		go s.watchPolling()
	} else {
		s.log.Info("config watching is disabled")
		return nil, nil
	}

	return s.updatesCh, nil
}

// watchSSE connects to SSE endpoint and listens for updates.
func (s *RemoteConfigSource) watchSSE() {
	sseURL := strings.TrimSuffix(s.settings.Endpoint, "/") + "/api/v1/configs/authz/events"

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		if err := s.connectSSE(sseURL); err != nil {
			if s.closed.Load() {
				return
			}
			s.log.Error("SSE connection failed, reconnecting",
				zap.Error(err),
				zap.Duration("backoff", s.settings.Polling.Retry.Backoff))

			select {
			case <-s.ctx.Done():
				return
			case <-time.After(s.settings.Polling.Retry.Backoff):
			}
		}
	}
}

// connectSSE establishes SSE connection and processes events.
func (s *RemoteConfigSource) connectSSE(url string) error {
	req, err := http.NewRequestWithContext(s.ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create SSE request: %w", err)
	}

	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	s.addAuthHeaders(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("SSE connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("SSE endpoint returned status %d", resp.StatusCode)
	}

	s.log.Info("SSE connection established", zap.String("url", url))

	reader := bufio.NewReader(resp.Body)
	var event, data strings.Builder

	for {
		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return fmt.Errorf("SSE connection closed")
			}
			return fmt.Errorf("error reading SSE stream: %w", err)
		}

		line = strings.TrimSpace(line)

		if line == "" {
			// Empty line = end of event
			if data.Len() > 0 {
				s.handleSSEEvent(event.String(), data.String())
			}
			event.Reset()
			data.Reset()
			continue
		}

		if strings.HasPrefix(line, "event:") {
			event.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "event:")))
		} else if strings.HasPrefix(line, "data:") {
			if data.Len() > 0 {
				data.WriteString("\n")
			}
			data.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
}

// handleSSEEvent processes an SSE event.
func (s *RemoteConfigSource) handleSSEEvent(eventType, data string) {
	s.log.Debug("received SSE event", zap.String("type", eventType), zap.String("data", data))

	var update struct {
		Type    string          `json:"type"`
		Version string          `json:"version"`
		Config  json.RawMessage `json:"config"`
	}

	if err := json.Unmarshal([]byte(data), &update); err != nil {
		s.log.Error("failed to parse SSE event", zap.Error(err))
		return
	}

	configType := ConfigType(update.Type)
	config, err := s.parseConfig(update.Config, configType)
	if err != nil {
		s.log.Error("failed to parse config from SSE event",
			zap.String("type", update.Type),
			zap.Error(err))
		return
	}

	s.mu.Lock()
	s.versions[configType] = update.Version
	s.mu.Unlock()

	select {
	case s.updatesCh <- ConfigUpdate{
		Type:      configType,
		Version:   update.Version,
		Config:    config,
		Timestamp: time.Now(),
		Source:    "sse",
	}:
	default:
		s.log.Warn("update channel full, dropping SSE event")
	}
}

// watchPolling periodically fetches configs.
func (s *RemoteConfigSource) watchPolling() {
	ticker := time.NewTicker(s.settings.Polling.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.pollForUpdates()
		}
	}
}

// pollForUpdates checks for config updates.
func (s *RemoteConfigSource) pollForUpdates() {
	ctx, cancel := context.WithTimeout(s.ctx, s.settings.Polling.Timeout)
	defer cancel()

	// Check services config
	s.checkConfigUpdate(ctx, ConfigTypeServices)
	// Check rules config
	s.checkConfigUpdate(ctx, ConfigTypeRules)
}

// checkConfigUpdate checks for update of a specific config type.
func (s *RemoteConfigSource) checkConfigUpdate(ctx context.Context, configType ConfigType) {
	path := s.getPathForType(configType)
	if path == "" {
		return
	}

	url := strings.TrimSuffix(s.settings.Endpoint, "/") + path

	config, version, err := s.fetchConfig(ctx, url, configType)
	if err != nil {
		s.log.Warn("failed to poll config",
			zap.String("type", string(configType)),
			zap.Error(err))
		return
	}

	s.mu.RLock()
	currentVersion := s.versions[configType]
	s.mu.RUnlock()

	if version != currentVersion {
		s.mu.Lock()
		s.versions[configType] = version
		s.mu.Unlock()

		select {
		case s.updatesCh <- ConfigUpdate{
			Type:      configType,
			Version:   version,
			Config:    config,
			Timestamp: time.Now(),
			Source:    "polling",
		}:
			s.log.Info("config update detected",
				zap.String("type", string(configType)),
				zap.String("old_version", currentVersion),
				zap.String("new_version", version))
		default:
			s.log.Warn("update channel full, dropping poll update")
		}
	}
}

// fetchConfig fetches config from URL.
func (s *RemoteConfigSource) fetchConfig(ctx context.Context, url string, configType ConfigType) (interface{}, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/yaml, application/json")
	s.addAuthHeaders(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, "", fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read response: %w", err)
	}

	// Get version from header or parse from config
	version := resp.Header.Get("X-Config-Version")
	if version == "" {
		version = resp.Header.Get("ETag")
	}
	if version == "" {
		version = time.Now().Format(time.RFC3339)
	}

	// Parse config based on content type
	contentType := resp.Header.Get("Content-Type")
	var config interface{}

	if strings.Contains(contentType, "json") {
		config, err = s.parseConfig(body, configType)
	} else {
		// Default to YAML
		config, err = s.parseYAMLConfig(body, configType)
	}

	if err != nil {
		return nil, "", fmt.Errorf("failed to parse config: %w", err)
	}

	return config, version, nil
}

// parseConfig parses JSON config.
func (s *RemoteConfigSource) parseConfig(data []byte, configType ConfigType) (interface{}, error) {
	switch configType {
	case ConfigTypeServices:
		var cfg ServicesConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, err
		}
		return &cfg, nil

	case ConfigTypeRules:
		var cfg RulesConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, err
		}
		return &cfg, nil

	default:
		return nil, fmt.Errorf("unsupported config type: %s", configType)
	}
}

// parseYAMLConfig parses YAML config.
func (s *RemoteConfigSource) parseYAMLConfig(data []byte, configType ConfigType) (interface{}, error) {
	switch configType {
	case ConfigTypeServices:
		var cfg ServicesConfig
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, err
		}
		return &cfg, nil

	case ConfigTypeRules:
		var cfg RulesConfig
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, err
		}
		return &cfg, nil

	default:
		return nil, fmt.Errorf("unsupported config type: %s", configType)
	}
}

// addAuthHeaders adds authentication headers to request.
func (s *RemoteConfigSource) addAuthHeaders(req *http.Request) {
	auth := s.settings.Auth

	switch auth.Type {
	case "token":
		token := auth.Token
		if token == "" && auth.TokenFile != "" {
			if data, err := os.ReadFile(auth.TokenFile); err == nil {
				token = strings.TrimSpace(string(data))
			}
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
}

// getPathForType returns the API path for config type.
func (s *RemoteConfigSource) getPathForType(configType ConfigType) string {
	switch configType {
	case ConfigTypeServices:
		return s.settings.Paths.Services
	case ConfigTypeRules:
		return s.settings.Paths.Rules
	default:
		return ""
	}
}

// Close stops watching and releases resources.
func (s *RemoteConfigSource) Close() error {
	if s.closed.Swap(true) {
		return nil
	}

	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()

	close(s.updatesCh)
	s.log.Info("remote config source closed")
	return nil
}

// GetVersion returns the current version of the specified config type.
func (s *RemoteConfigSource) GetVersion(configType ConfigType) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.versions[configType]
}

// createHTTPClient creates an HTTP client with proper TLS configuration.
func createHTTPClient(settings RemoteSourceSettings) (*http.Client, error) {
	transport := &http.Transport{
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	// Configure TLS for mTLS authentication
	if settings.Auth.Type == "mtls" {
		tlsConfig := &tls.Config{}

		// Load client certificate
		if settings.Auth.ClientCert != "" && settings.Auth.ClientKey != "" {
			cert, err := tls.LoadX509KeyPair(settings.Auth.ClientCert, settings.Auth.ClientKey)
			if err != nil {
				return nil, fmt.Errorf("failed to load client certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}

		// Load CA certificate
		if settings.Auth.CACert != "" {
			caCert, err := os.ReadFile(settings.Auth.CACert)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA certificate: %w", err)
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse CA certificate")
			}
			tlsConfig.RootCAs = caCertPool
		}

		transport.TLSClientConfig = tlsConfig
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}, nil
}
