package egress

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/pkg/logger"
)

// CredentialType defines the type of credential.
type CredentialType string

const (
	CredentialTypeOAuth2  CredentialType = "oauth2"
	CredentialTypeAPIKey  CredentialType = "api_key"
	CredentialTypeMTLS    CredentialType = "mtls"
	CredentialTypeBasic   CredentialType = "basic"
	CredentialTypeBearer  CredentialType = "bearer"
	CredentialTypeGCP     CredentialType = "gcp_service_account"
	CredentialTypeAWS     CredentialType = "aws_iam"
	CredentialTypeNone    CredentialType = "none"
)

// Credentials represents obtained credentials for a target.
type Credentials struct {
	Type        CredentialType
	AccessToken string
	ExpiresAt   time.Time
	Headers     map[string]string
	TLSConfig   *tls.Config
}

// IsExpired checks if credentials are expired.
func (c *Credentials) IsExpired() bool {
	if c.ExpiresAt.IsZero() {
		return false // Never expires (e.g., static API key)
	}
	return time.Now().After(c.ExpiresAt)
}

// IsExpiringSoon checks if credentials expire within the given duration.
func (c *Credentials) IsExpiringSoon(within time.Duration) bool {
	if c.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().Add(within).After(c.ExpiresAt)
}

// CredentialProvider obtains credentials for targets.
type CredentialProvider interface {
	// GetCredentials returns current credentials for target.
	GetCredentials(ctx context.Context, targetName string) (*Credentials, error)

	// RefreshCredentials forces refresh of credentials.
	RefreshCredentials(ctx context.Context, targetName string) (*Credentials, error)

	// Health checks if provider is healthy.
	Health(ctx context.Context) error
}

// CredentialManager manages credentials for multiple targets.
type CredentialManager struct {
	targets    map[string]config.EgressTargetConfig
	providers  map[string]credentialFetcher
	tokenStore TokenStore
	httpClient *http.Client
	log        logger.Logger
	mu         sync.RWMutex
}

// credentialFetcher is an internal interface for fetching credentials.
type credentialFetcher interface {
	fetch(ctx context.Context) (*Credentials, error)
}

// NewCredentialManager creates a new credential manager.
func NewCredentialManager(cfg config.EgressConfig, tokenStore TokenStore, log logger.Logger) (*CredentialManager, error) {
	cm := &CredentialManager{
		targets:    cfg.Targets,
		providers:  make(map[string]credentialFetcher),
		tokenStore: tokenStore,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		log: log,
	}

	// Create fetchers for each target
	for name, targetCfg := range cfg.Targets {
		fetcher, err := cm.createFetcher(name, targetCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create credential fetcher for %s: %w", name, err)
		}
		cm.providers[name] = fetcher
	}

	return cm, nil
}

// GetCredentials returns credentials for target, using cache if valid.
func (cm *CredentialManager) GetCredentials(ctx context.Context, targetName string) (*Credentials, error) {
	// Try to get from cache
	cached, err := cm.tokenStore.Get(ctx, targetName)
	if err == nil && cached != nil && !cached.IsExpired() {
		// Check if we should proactively refresh
		targetCfg, ok := cm.targets[targetName]
		refreshBefore := 60 * time.Second
		if ok && targetCfg.Auth.RefreshBeforeExpiry > 0 {
			refreshBefore = targetCfg.Auth.RefreshBeforeExpiry
		}

		if !cached.IsExpiringSoon(refreshBefore) {
			return cached, nil
		}

		// Credentials expiring soon, refresh in background
		go func() {
			_, _ = cm.RefreshCredentials(context.Background(), targetName)
		}()
		return cached, nil
	}

	// Fetch new credentials
	return cm.RefreshCredentials(ctx, targetName)
}

// RefreshCredentials forces refresh of credentials for target.
func (cm *CredentialManager) RefreshCredentials(ctx context.Context, targetName string) (*Credentials, error) {
	cm.mu.Lock()
	fetcher, ok := cm.providers[targetName]
	cm.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("unknown target: %s", targetName)
	}

	creds, err := fetcher.fetch(ctx)
	if err != nil {
		cm.log.Error("Failed to fetch credentials",
			logger.String("target", targetName),
			logger.Err(err),
		)
		return nil, fmt.Errorf("failed to fetch credentials for %s: %w", targetName, err)
	}

	// Store in cache
	if err := cm.tokenStore.Set(ctx, targetName, creds); err != nil {
		cm.log.Warn("Failed to cache credentials",
			logger.String("target", targetName),
			logger.Err(err),
		)
	}

	cm.log.Debug("Credentials refreshed",
		logger.String("target", targetName),
		logger.String("type", string(creds.Type)),
		logger.Time("expires_at", creds.ExpiresAt),
	)

	return creds, nil
}

// Health checks if credential manager is healthy.
func (cm *CredentialManager) Health(ctx context.Context) error {
	return cm.tokenStore.Health(ctx)
}

// createFetcher creates appropriate credential fetcher based on auth type.
func (cm *CredentialManager) createFetcher(name string, cfg config.EgressTargetConfig) (credentialFetcher, error) {
	switch cfg.Auth.Type {
	case "oauth2_client_credentials":
		return &oauth2ClientCredentialsFetcher{
			name:         name,
			tokenURL:     cfg.Auth.TokenURL,
			clientID:     cfg.Auth.ClientID,
			clientSecret: cfg.Auth.ClientSecret,
			scopes:       cfg.Auth.Scopes,
			httpClient:   cm.httpClient,
			log:          cm.log,
		}, nil

	case "api_key":
		return &apiKeyFetcher{
			header:   cfg.Auth.Header,
			queryKey: cfg.Auth.QueryKey,
			key:      cfg.Auth.Key,
		}, nil

	case "basic":
		return &basicAuthFetcher{
			username: cfg.Auth.Username,
			password: cfg.Auth.Password,
		}, nil

	case "bearer":
		return &bearerTokenFetcher{
			token: cfg.Auth.Token,
		}, nil

	case "mtls":
		return &mtlsFetcher{
			certFile: cfg.TLS.ClientCert,
			keyFile:  cfg.TLS.ClientKey,
			caFile:   cfg.TLS.CACert,
		}, nil

	case "", "none":
		return &noAuthFetcher{}, nil

	default:
		return nil, fmt.Errorf("unsupported auth type: %s", cfg.Auth.Type)
	}
}

// =============================================================================
// OAuth2 Client Credentials Fetcher
// =============================================================================

type oauth2ClientCredentialsFetcher struct {
	name         string
	tokenURL     string
	clientID     string
	clientSecret string
	scopes       []string
	httpClient   *http.Client
	log          logger.Logger
}

type oauth2TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

func (f *oauth2ClientCredentialsFetcher) fetch(ctx context.Context) (*Credentials, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", f.clientID)
	data.Set("client_secret", f.clientSecret)
	if len(f.scopes) > 0 {
		data.Set("scope", strings.Join(f.scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp oauth2TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	return &Credentials{
		Type:        CredentialTypeOAuth2,
		AccessToken: tokenResp.AccessToken,
		ExpiresAt:   expiresAt,
		Headers: map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", tokenResp.AccessToken),
		},
	}, nil
}

// =============================================================================
// API Key Fetcher
// =============================================================================

type apiKeyFetcher struct {
	header   string
	queryKey string
	key      string
}

func (f *apiKeyFetcher) fetch(ctx context.Context) (*Credentials, error) {
	headers := make(map[string]string)

	if f.header != "" {
		headers[f.header] = f.key
	}

	return &Credentials{
		Type:    CredentialTypeAPIKey,
		Headers: headers,
		// API keys don't expire (or we don't know when they do)
	}, nil
}

// =============================================================================
// Basic Auth Fetcher
// =============================================================================

type basicAuthFetcher struct {
	username string
	password string
}

func (f *basicAuthFetcher) fetch(ctx context.Context) (*Credentials, error) {
	auth := base64.StdEncoding.EncodeToString([]byte(f.username + ":" + f.password))

	return &Credentials{
		Type: CredentialTypeBasic,
		Headers: map[string]string{
			"Authorization": fmt.Sprintf("Basic %s", auth),
		},
	}, nil
}

// =============================================================================
// Bearer Token Fetcher (static token)
// =============================================================================

type bearerTokenFetcher struct {
	token string
}

func (f *bearerTokenFetcher) fetch(ctx context.Context) (*Credentials, error) {
	return &Credentials{
		Type:        CredentialTypeBearer,
		AccessToken: f.token,
		Headers: map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", f.token),
		},
	}, nil
}

// =============================================================================
// mTLS Fetcher
// =============================================================================

type mtlsFetcher struct {
	certFile string
	keyFile  string
	caFile   string
}

func (f *mtlsFetcher) fetch(ctx context.Context) (*Credentials, error) {
	cert, err := tls.LoadX509KeyPair(f.certFile, f.keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Load CA cert if provided
	if f.caFile != "" {
		// Note: In production, load CA cert properly
		tlsConfig.InsecureSkipVerify = false
	}

	return &Credentials{
		Type:      CredentialTypeMTLS,
		TLSConfig: tlsConfig,
		Headers:   make(map[string]string),
	}, nil
}

// =============================================================================
// No Auth Fetcher
// =============================================================================

type noAuthFetcher struct{}

func (f *noAuthFetcher) fetch(ctx context.Context) (*Credentials, error) {
	return &Credentials{
		Type:    CredentialTypeNone,
		Headers: make(map[string]string),
	}, nil
}
