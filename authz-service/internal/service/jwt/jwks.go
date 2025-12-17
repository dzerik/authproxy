package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/pkg/errors"
	"github.com/your-org/authz-service/pkg/logger"
)

// JWKSProvider manages JWKS fetching and caching for multiple issuers.
type JWKSProvider struct {
	mu       sync.RWMutex
	issuers  map[string]*issuerJWKS
	client   *http.Client
	cfg      config.JWKSCacheConfig
	stopCh   chan struct{}
	stopOnce sync.Once
}

// issuerJWKS holds JWKS data for a single issuer.
type issuerJWKS struct {
	issuerURL   string
	jwksURL     string
	keySet      jwk.Set
	lastRefresh time.Time
	refreshing  bool
	mu          sync.RWMutex
}

// NewJWKSProvider creates a new JWKS provider.
func NewJWKSProvider(issuers []config.IssuerConfig, cacheConfig config.JWKSCacheConfig) *JWKSProvider {
	p := &JWKSProvider{
		issuers: make(map[string]*issuerJWKS),
		client: &http.Client{
			Timeout: cacheConfig.RefreshTimeout,
		},
		cfg:    cacheConfig,
		stopCh: make(chan struct{}),
	}

	for _, issuer := range issuers {
		p.issuers[issuer.IssuerURL] = &issuerJWKS{
			issuerURL: issuer.IssuerURL,
			jwksURL:   issuer.JWKSURL,
		}
	}

	return p
}

// Start begins background JWKS refresh for all issuers.
func (p *JWKSProvider) Start(ctx context.Context) error {
	// Initial fetch for all issuers
	for issuerURL := range p.issuers {
		if err := p.refreshJWKS(ctx, issuerURL); err != nil {
			logger.Warn("failed to fetch initial JWKS",
				logger.String("issuer", issuerURL),
				logger.Err(err),
			)
		}
	}

	// Start background refresh
	go p.backgroundRefresh()

	return nil
}

// Stop stops the background refresh.
func (p *JWKSProvider) Stop() {
	p.stopOnce.Do(func() {
		close(p.stopCh)
	})
}

// GetKey retrieves a key by key ID from the specified issuer's JWKS.
func (p *JWKSProvider) GetKey(ctx context.Context, issuerURL, keyID string) (jwk.Key, error) {
	p.mu.RLock()
	issuer, ok := p.issuers[issuerURL]
	p.mu.RUnlock()

	if !ok {
		return nil, errors.Wrap(errors.ErrIssuerInvalid, fmt.Sprintf("unknown issuer: %s", issuerURL))
	}

	issuer.mu.RLock()
	keySet := issuer.keySet
	lastRefresh := issuer.lastRefresh
	issuer.mu.RUnlock()

	// Try to find the key
	if keySet != nil {
		if key, found := keySet.LookupKeyID(keyID); found {
			return key, nil
		}
	}

	// Key not found, try refreshing if enough time has passed
	if time.Since(lastRefresh) > p.cfg.MinRefreshInterval {
		if err := p.refreshJWKS(ctx, issuerURL); err != nil {
			logger.Warn("failed to refresh JWKS on key miss",
				logger.String("issuer", issuerURL),
				logger.String("kid", keyID),
				logger.Err(err),
			)
		}

		// Try again after refresh
		issuer.mu.RLock()
		keySet = issuer.keySet
		issuer.mu.RUnlock()

		if keySet != nil {
			if key, found := keySet.LookupKeyID(keyID); found {
				return key, nil
			}
		}
	}

	return nil, errors.Wrap(errors.ErrJWKSKeyNotFound, fmt.Sprintf("key %s not found for issuer %s", keyID, issuerURL))
}

// GetKeySet returns the full JWKS for an issuer.
func (p *JWKSProvider) GetKeySet(ctx context.Context, issuerURL string) (jwk.Set, error) {
	p.mu.RLock()
	issuer, ok := p.issuers[issuerURL]
	p.mu.RUnlock()

	if !ok {
		return nil, errors.Wrap(errors.ErrIssuerInvalid, fmt.Sprintf("unknown issuer: %s", issuerURL))
	}

	issuer.mu.RLock()
	keySet := issuer.keySet
	issuer.mu.RUnlock()

	if keySet == nil {
		if err := p.refreshJWKS(ctx, issuerURL); err != nil {
			return nil, err
		}
		issuer.mu.RLock()
		keySet = issuer.keySet
		issuer.mu.RUnlock()
	}

	return keySet, nil
}

// refreshJWKS fetches fresh JWKS for an issuer.
func (p *JWKSProvider) refreshJWKS(ctx context.Context, issuerURL string) error {
	p.mu.RLock()
	issuer, ok := p.issuers[issuerURL]
	p.mu.RUnlock()

	if !ok {
		return fmt.Errorf("unknown issuer: %s", issuerURL)
	}

	// Check if already refreshing
	issuer.mu.Lock()
	if issuer.refreshing {
		issuer.mu.Unlock()
		return nil
	}
	issuer.refreshing = true
	issuer.mu.Unlock()

	defer func() {
		issuer.mu.Lock()
		issuer.refreshing = false
		issuer.mu.Unlock()
	}()

	jwksURL := issuer.jwksURL
	if jwksURL == "" {
		// Try to discover from OIDC well-known endpoint
		var err error
		jwksURL, err = p.discoverJWKSURL(ctx, issuerURL)
		if err != nil {
			return errors.Wrap(errors.ErrJWKSFetchFailed, err.Error())
		}
	}

	// Fetch JWKS
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return errors.Wrap(errors.ErrJWKSFetchFailed, err.Error())
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return errors.Wrap(errors.ErrJWKSFetchFailed, err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.Wrap(errors.ErrJWKSFetchFailed, fmt.Sprintf("HTTP %d", resp.StatusCode))
	}

	keySet, err := jwk.ParseReader(resp.Body)
	if err != nil {
		return errors.Wrap(errors.ErrJWKSParseError, err.Error())
	}

	// Update the key set
	issuer.mu.Lock()
	issuer.keySet = keySet
	issuer.lastRefresh = time.Now()
	issuer.jwksURL = jwksURL
	issuer.mu.Unlock()

	logger.Debug("JWKS refreshed",
		logger.String("issuer", issuerURL),
		logger.Int("keys", keySet.Len()),
	)

	return nil
}

// discoverJWKSURL discovers JWKS URL from OIDC well-known endpoint.
func (p *JWKSProvider) discoverJWKSURL(ctx context.Context, issuerURL string) (string, error) {
	wellKnownURL := issuerURL + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC discovery failed: HTTP %d", resp.StatusCode)
	}

	var config struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return "", err
	}

	if config.JWKSURI == "" {
		return "", fmt.Errorf("jwks_uri not found in OIDC configuration")
	}

	return config.JWKSURI, nil
}

// backgroundRefresh periodically refreshes JWKS for all issuers.
func (p *JWKSProvider) backgroundRefresh() {
	ticker := time.NewTicker(p.cfg.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), p.cfg.RefreshTimeout)
			p.mu.RLock()
			for issuerURL := range p.issuers {
				if err := p.refreshJWKS(ctx, issuerURL); err != nil {
					logger.Warn("background JWKS refresh failed",
						logger.String("issuer", issuerURL),
						logger.Err(err),
					)
				}
			}
			p.mu.RUnlock()
			cancel()
		}
	}
}
