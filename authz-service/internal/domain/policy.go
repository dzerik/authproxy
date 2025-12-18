package domain

// PolicyInput contains all information needed for policy evaluation.
type PolicyInput struct {
	// Request contains HTTP request information
	Request RequestInfo `json:"request"`

	// Token contains parsed JWT token information
	Token *TokenInfo `json:"token,omitempty"`

	// Source contains information about the request source
	Source SourceInfo `json:"source"`

	// Destination contains information about the target service
	Destination DestinationInfo `json:"destination,omitempty"`

	// Resource contains extracted resource information from the request path
	Resource *ResourceInfo `json:"resource,omitempty"`

	// Context contains additional context information
	Context ContextInfo `json:"context,omitempty"`

	// Env contains environment information (production, staging, etc.)
	Env EnvInfo `json:"env,omitempty"`

	// TLS contains mTLS/client certificate information
	TLS *TLSInfo `json:"tls,omitempty"`

	// Body contains parsed request body (if enabled and applicable)
	// Only available for requests with JSON body when request_body.enabled=true
	Body map[string]any `json:"body,omitempty"`

	// Extensions is an extension point for future attributes (agent identity, intent, etc.)
	Extensions map[string]any `json:"extensions,omitempty"`
}

// ResourceInfo contains extracted resource information from a request path.
type ResourceInfo struct {
	// Type is the resource type (e.g., "users", "orders", "products").
	Type string `json:"type,omitempty"`

	// ID is the resource identifier.
	ID string `json:"id,omitempty"`

	// Action is the action being performed on the resource.
	Action string `json:"action,omitempty"`

	// Params contains all extracted path parameters.
	Params map[string]string `json:"params,omitempty"`
}

// SetResource sets the resource information.
func (p *PolicyInput) SetResource(resource *ResourceInfo) {
	p.Resource = resource
}

// DeriveActionFromMethod derives an action name from the HTTP method.
func DeriveActionFromMethod(method string) string {
	switch method {
	case "GET":
		return "read"
	case "POST":
		return "create"
	case "PUT", "PATCH":
		return "update"
	case "DELETE":
		return "delete"
	case "HEAD":
		return "read"
	case "OPTIONS":
		return "options"
	default:
		return "unknown"
	}
}

// RequestInfo contains HTTP request details.
type RequestInfo struct {
	// Method is the HTTP method (GET, POST, etc.)
	Method string `json:"method"`

	// Path is the request path
	Path string `json:"path"`

	// Host is the request host
	Host string `json:"host,omitempty"`

	// Headers contains request headers (sanitized)
	Headers map[string]string `json:"headers,omitempty"`

	// Query contains query parameters
	Query map[string]string `json:"query,omitempty"`

	// Protocol is the request protocol (HTTP/1.1, HTTP/2)
	Protocol string `json:"protocol,omitempty"`
}

// SourceInfo contains information about the request source.
type SourceInfo struct {
	// Principal is the identity of the caller (e.g., SPIFFE ID)
	Principal string `json:"principal,omitempty"`

	// Address is the source IP address
	Address string `json:"address,omitempty"`

	// Port is the source port
	Port int `json:"port,omitempty"`

	// Namespace is the Kubernetes namespace (if applicable)
	Namespace string `json:"namespace,omitempty"`

	// ServiceAccount is the Kubernetes service account (if applicable)
	ServiceAccount string `json:"service_account,omitempty"`
}

// DestinationInfo contains information about the target service.
type DestinationInfo struct {
	// Service is the target service name
	Service string `json:"service,omitempty"`

	// Address is the destination address
	Address string `json:"address,omitempty"`

	// Port is the destination port
	Port int `json:"port,omitempty"`
}

// ContextInfo contains additional context for authorization.
type ContextInfo struct {
	// RequestID is the unique request identifier
	RequestID string `json:"request_id,omitempty"`

	// TraceID is the distributed trace ID
	TraceID string `json:"trace_id,omitempty"`

	// Timestamp is when the request was received
	Timestamp int64 `json:"timestamp,omitempty"`

	// Custom contains custom context attributes
	Custom map[string]any `json:"custom,omitempty"`
}

// EnvInfo contains environment information for context-aware authorization.
// This allows policies to make decisions based on deployment environment.
type EnvInfo struct {
	// Name is the environment name (e.g., "production", "staging", "development")
	Name string `json:"name,omitempty"`

	// Region is the deployment region (e.g., "eu-west-1", "us-east-1")
	Region string `json:"region,omitempty"`

	// Cluster is the cluster identifier (e.g., "k8s-prod-01", "ecs-staging")
	Cluster string `json:"cluster,omitempty"`

	// Version is the service version (e.g., "2.1.0", "v1.2.3-beta")
	Version string `json:"version,omitempty"`

	// Features contains feature flags for gradual rollouts
	Features map[string]bool `json:"features,omitempty"`

	// Custom contains any additional environment-specific attributes
	Custom map[string]any `json:"custom,omitempty"`
}

// TLSInfo contains mTLS/client certificate information for service identity.
// This enables authorization based on client certificates and SPIFFE identities.
type TLSInfo struct {
	// Verified indicates whether the client certificate was successfully verified
	Verified bool `json:"verified"`

	// Subject is the full subject Distinguished Name (DN) from the certificate
	Subject string `json:"subject,omitempty"`

	// Issuer is the full issuer Distinguished Name (DN) from the certificate
	Issuer string `json:"issuer,omitempty"`

	// CommonName is the CN (Common Name) from the certificate subject
	CommonName string `json:"common_name,omitempty"`

	// Serial is the certificate serial number
	Serial string `json:"serial,omitempty"`

	// NotBefore is the certificate validity start time (Unix timestamp)
	NotBefore int64 `json:"not_before,omitempty"`

	// NotAfter is the certificate validity end time (Unix timestamp)
	NotAfter int64 `json:"not_after,omitempty"`

	// DNSNames contains Subject Alternative Name (SAN) DNS entries
	DNSNames []string `json:"dns_names,omitempty"`

	// URIs contains Subject Alternative Name (SAN) URI entries (including SPIFFE IDs)
	URIs []string `json:"uris,omitempty"`

	// Fingerprint is the SHA256 fingerprint of the certificate
	Fingerprint string `json:"fingerprint,omitempty"`

	// SPIFFE contains parsed SPIFFE identity information (if present in URIs)
	SPIFFE *SPIFFEInfo `json:"spiffe,omitempty"`

	// Raw contains raw header values for custom parsing
	Raw map[string]string `json:"raw,omitempty"`
}

// SPIFFEInfo contains parsed SPIFFE identity information.
// SPIFFE URI format: spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>
// Example: spiffe://cluster.local/ns/production/sa/payment-service
type SPIFFEInfo struct {
	// TrustDomain is the SPIFFE trust domain (e.g., "cluster.local", "example.com")
	TrustDomain string `json:"trust_domain,omitempty"`

	// Namespace is the Kubernetes namespace (extracted from /ns/<namespace>)
	Namespace string `json:"namespace,omitempty"`

	// ServiceAccount is the Kubernetes service account (extracted from /sa/<service-account>)
	ServiceAccount string `json:"service_account,omitempty"`

	// Path is the full path after trust domain (e.g., "/ns/production/sa/payment-service")
	Path string `json:"path,omitempty"`

	// URI is the full SPIFFE URI
	URI string `json:"uri,omitempty"`
}

// SetExtension sets an extension value.
func (p *PolicyInput) SetExtension(key string, value any) {
	if p.Extensions == nil {
		p.Extensions = make(map[string]any)
	}
	p.Extensions[key] = value
}

// GetExtension retrieves an extension value.
func (p *PolicyInput) GetExtension(key string) (any, bool) {
	if p.Extensions == nil {
		return nil, false
	}
	v, ok := p.Extensions[key]
	return v, ok
}
