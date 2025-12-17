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

	// Context contains additional context information
	Context ContextInfo `json:"context,omitempty"`

	// Extensions is an extension point for future attributes (agent identity, intent, etc.)
	Extensions map[string]any `json:"extensions,omitempty"`
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
