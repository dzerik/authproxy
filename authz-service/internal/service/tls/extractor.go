// Package tls provides client certificate extraction from HTTP requests.
// It supports multiple extraction methods: XFCC (Envoy/Istio) and individual headers (Nginx/HAProxy).
package tls

import (
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/your-org/authz-service/internal/config"
	"github.com/your-org/authz-service/internal/domain"
	"github.com/your-org/authz-service/pkg/logger"
)

// Extractor extracts client certificate information from HTTP requests.
type Extractor struct {
	cfg              config.TLSClientCertConfig
	trustedProxyCIDRs []*net.IPNet
}

// NewExtractor creates a new TLS certificate extractor.
func NewExtractor(cfg config.TLSClientCertConfig) (*Extractor, error) {
	e := &Extractor{
		cfg: cfg,
	}

	// Parse trusted proxy CIDRs
	for _, cidr := range cfg.TrustedProxyCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			// Try parsing as single IP
			ip := net.ParseIP(cidr)
			if ip == nil {
				logger.Warn("invalid trusted proxy CIDR, skipping",
					logger.String("cidr", cidr))
				continue
			}
			// Convert single IP to /32 or /128 CIDR
			mask := net.CIDRMask(32, 32)
			if ip.To4() == nil {
				mask = net.CIDRMask(128, 128)
			}
			ipNet = &net.IPNet{IP: ip, Mask: mask}
		}
		e.trustedProxyCIDRs = append(e.trustedProxyCIDRs, ipNet)
	}

	return e, nil
}

// Extract extracts TLS client certificate information from the request.
// It uses a cascade approach: XFCC first, then individual headers.
// Both sources can be merged if both are enabled.
func (e *Extractor) Extract(r *http.Request) *domain.TLSInfo {
	if !e.cfg.Enabled {
		return nil
	}

	var tlsInfo *domain.TLSInfo

	// Try XFCC first (primary source for Envoy/Istio)
	if e.cfg.Sources.XFCC.Enabled {
		if e.isTrustedProxy(r.RemoteAddr) || len(e.trustedProxyCIDRs) == 0 {
			tlsInfo = e.extractFromXFCC(r)
		} else {
			logger.Debug("XFCC header ignored: request not from trusted proxy",
				logger.String("remote_addr", r.RemoteAddr))
		}
	}

	// Try individual headers (fallback or additional source)
	if e.cfg.Sources.Headers.Enabled {
		headerInfo := e.extractFromHeaders(r)
		if headerInfo != nil {
			if tlsInfo == nil {
				tlsInfo = headerInfo
			} else {
				// Merge: fill in missing fields from headers
				e.mergeInfo(tlsInfo, headerInfo)
			}
		}
	}

	// If we got TLS info, try to parse SPIFFE ID from URIs
	if tlsInfo != nil && len(tlsInfo.URIs) > 0 {
		for _, uri := range tlsInfo.URIs {
			if strings.HasPrefix(uri, "spiffe://") {
				spiffe := parseSPIFFEURI(uri)
				if spiffe != nil {
					// Check if trust domain is allowed
					if len(e.cfg.TrustedSPIFFEDomains) > 0 {
						trusted := false
						for _, td := range e.cfg.TrustedSPIFFEDomains {
							if spiffe.TrustDomain == td {
								trusted = true
								break
							}
						}
						if !trusted {
							logger.Warn("SPIFFE trust domain not in allowed list",
								logger.String("trust_domain", spiffe.TrustDomain))
							continue
						}
					}
					tlsInfo.SPIFFE = spiffe
					break
				}
			}
		}
	}

	// Store raw headers for custom parsing
	if tlsInfo != nil {
		tlsInfo.Raw = e.collectRawHeaders(r)
	}

	return tlsInfo
}

// isTrustedProxy checks if the remote address is from a trusted proxy.
func (e *Extractor) isTrustedProxy(remoteAddr string) bool {
	if len(e.trustedProxyCIDRs) == 0 {
		return true // No restriction if no CIDRs configured
	}

	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	for _, cidr := range e.trustedProxyCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}

// extractFromXFCC extracts certificate info from X-Forwarded-Client-Cert header.
// XFCC format: Hash=<hash>;Cert="<cert>";Chain="<chain>";Subject="<subject>";URI=<uri>;DNS=<dns>
func (e *Extractor) extractFromXFCC(r *http.Request) *domain.TLSInfo {
	xfcc := r.Header.Get(e.cfg.Sources.XFCC.Header)
	if xfcc == "" {
		return nil
	}

	info := &domain.TLSInfo{
		Verified: true, // XFCC presence implies verification by the proxy
	}

	// Parse XFCC elements
	elements := parseXFCCElements(xfcc)

	for key, value := range elements {
		switch strings.ToLower(key) {
		case "hash":
			info.Fingerprint = value
		case "subject":
			info.Subject = value
			// Extract CN from subject
			info.CommonName = extractCNFromDN(value)
		case "uri":
			// Handle multiple URIs (comma-separated)
			for _, uri := range strings.Split(value, ",") {
				uri = strings.TrimSpace(uri)
				if uri != "" {
					info.URIs = append(info.URIs, uri)
				}
			}
		case "dns":
			// Handle multiple DNS names (comma-separated)
			for _, dns := range strings.Split(value, ",") {
				dns = strings.TrimSpace(dns)
				if dns != "" {
					info.DNSNames = append(info.DNSNames, dns)
				}
			}
		case "by":
			// Proxy URI, could be stored in raw
		case "cert":
			// URL-encoded PEM certificate, skip for now
		case "chain":
			// URL-encoded PEM chain, skip for now
		}
	}

	return info
}

// parseXFCCElements parses the XFCC header into key-value pairs.
// Handles quoted values and multiple occurrences of the same key.
func parseXFCCElements(xfcc string) map[string]string {
	elements := make(map[string]string)

	// XFCC can have multiple elements separated by semicolons
	// Values can be quoted or unquoted
	parts := splitXFCC(xfcc)

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		idx := strings.Index(part, "=")
		if idx == -1 {
			continue
		}

		key := strings.TrimSpace(part[:idx])
		value := strings.TrimSpace(part[idx+1:])

		// Remove quotes if present
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}

		// URL decode if needed
		if decoded, err := url.QueryUnescape(value); err == nil {
			value = decoded
		}

		// Handle multiple URIs/DNS entries by appending
		if existing, ok := elements[key]; ok {
			elements[key] = existing + "," + value
		} else {
			elements[key] = value
		}
	}

	return elements
}

// splitXFCC splits the XFCC header respecting quoted values.
func splitXFCC(xfcc string) []string {
	var parts []string
	var current strings.Builder
	inQuotes := false

	for i := 0; i < len(xfcc); i++ {
		c := xfcc[i]
		switch c {
		case '"':
			inQuotes = !inQuotes
			current.WriteByte(c)
		case ';':
			if inQuotes {
				current.WriteByte(c)
			} else {
				parts = append(parts, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(c)
		}
	}

	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
}

// extractFromHeaders extracts certificate info from individual HTTP headers.
func (e *Extractor) extractFromHeaders(r *http.Request) *domain.TLSInfo {
	cfg := e.cfg.Sources.Headers

	// Check if at least one relevant header is present
	subject := r.Header.Get(cfg.Subject)
	commonName := r.Header.Get(cfg.CommonName)
	verified := r.Header.Get(cfg.Verified)

	if subject == "" && commonName == "" && verified == "" {
		return nil
	}

	info := &domain.TLSInfo{
		Subject:     subject,
		Issuer:      r.Header.Get(cfg.Issuer),
		CommonName:  commonName,
		Serial:      r.Header.Get(cfg.Serial),
		Fingerprint: r.Header.Get(cfg.Fingerprint),
	}

	// If CN not provided directly, try to extract from subject
	if info.CommonName == "" && info.Subject != "" {
		info.CommonName = extractCNFromDN(info.Subject)
	}

	// Parse verified status
	if verified != "" {
		info.Verified = strings.EqualFold(verified, cfg.VerifiedValue)
	}

	// Parse DNS names (comma-separated)
	if dnsHeader := r.Header.Get(cfg.DNSNames); dnsHeader != "" {
		for _, dns := range strings.Split(dnsHeader, ",") {
			dns = strings.TrimSpace(dns)
			if dns != "" {
				info.DNSNames = append(info.DNSNames, dns)
			}
		}
	}

	// Parse URIs (comma-separated)
	if uriHeader := r.Header.Get(cfg.URI); uriHeader != "" {
		for _, uri := range strings.Split(uriHeader, ",") {
			uri = strings.TrimSpace(uri)
			if uri != "" {
				info.URIs = append(info.URIs, uri)
			}
		}
	}

	// Parse timestamps
	if notBeforeStr := r.Header.Get(cfg.NotBefore); notBeforeStr != "" {
		info.NotBefore = parseTimestamp(notBeforeStr)
	}
	if notAfterStr := r.Header.Get(cfg.NotAfter); notAfterStr != "" {
		info.NotAfter = parseTimestamp(notAfterStr)
	}

	return info
}

// mergeInfo merges source info into target, filling in empty fields.
func (e *Extractor) mergeInfo(target, source *domain.TLSInfo) {
	if target.Subject == "" {
		target.Subject = source.Subject
	}
	if target.Issuer == "" {
		target.Issuer = source.Issuer
	}
	if target.CommonName == "" {
		target.CommonName = source.CommonName
	}
	if target.Serial == "" {
		target.Serial = source.Serial
	}
	if target.Fingerprint == "" {
		target.Fingerprint = source.Fingerprint
	}
	if target.NotBefore == 0 {
		target.NotBefore = source.NotBefore
	}
	if target.NotAfter == 0 {
		target.NotAfter = source.NotAfter
	}
	if len(target.DNSNames) == 0 {
		target.DNSNames = source.DNSNames
	}
	if len(target.URIs) == 0 {
		target.URIs = source.URIs
	}
	// Keep verified as true if either source says verified
	if source.Verified {
		target.Verified = true
	}
}

// collectRawHeaders collects all TLS-related headers for custom parsing.
func (e *Extractor) collectRawHeaders(r *http.Request) map[string]string {
	raw := make(map[string]string)

	// Collect XFCC header
	if xfcc := r.Header.Get(e.cfg.Sources.XFCC.Header); xfcc != "" {
		raw["xfcc"] = xfcc
	}

	// Collect individual headers
	cfg := e.cfg.Sources.Headers
	headers := []struct {
		key    string
		header string
	}{
		{"subject", cfg.Subject},
		{"issuer", cfg.Issuer},
		{"common_name", cfg.CommonName},
		{"serial", cfg.Serial},
		{"verified", cfg.Verified},
		{"fingerprint", cfg.Fingerprint},
		{"dns_names", cfg.DNSNames},
		{"uri", cfg.URI},
		{"not_before", cfg.NotBefore},
		{"not_after", cfg.NotAfter},
	}

	for _, h := range headers {
		if value := r.Header.Get(h.header); value != "" {
			raw[h.key] = value
		}
	}

	return raw
}

// parseSPIFFEURI parses a SPIFFE URI into its components.
// Format: spiffe://<trust-domain>/<path>
// Kubernetes format: spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>
func parseSPIFFEURI(uri string) *domain.SPIFFEInfo {
	if !strings.HasPrefix(uri, "spiffe://") {
		return nil
	}

	// Remove scheme
	rest := strings.TrimPrefix(uri, "spiffe://")

	// Split trust domain from path
	idx := strings.Index(rest, "/")
	if idx == -1 {
		return &domain.SPIFFEInfo{
			TrustDomain: rest,
			URI:         uri,
		}
	}

	trustDomain := rest[:idx]
	path := rest[idx:]

	info := &domain.SPIFFEInfo{
		TrustDomain: trustDomain,
		Path:        path,
		URI:         uri,
	}

	// Try to parse Kubernetes-style SPIFFE ID
	// Format: /ns/<namespace>/sa/<service-account>
	parts := strings.Split(path, "/")
	for i := 0; i < len(parts)-1; i++ {
		switch parts[i] {
		case "ns":
			if i+1 < len(parts) {
				info.Namespace = parts[i+1]
			}
		case "sa":
			if i+1 < len(parts) {
				info.ServiceAccount = parts[i+1]
			}
		}
	}

	return info
}

// extractCNFromDN extracts the Common Name (CN) from a Distinguished Name.
func extractCNFromDN(dn string) string {
	// DN format: CN=value,O=org,OU=unit,...
	parts := strings.Split(dn, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "CN=") {
			return strings.TrimPrefix(part[3:], " ")
		}
	}
	return ""
}

// parseTimestamp parses a timestamp string (Unix or RFC3339).
func parseTimestamp(s string) int64 {
	s = strings.TrimSpace(s)

	// Try Unix timestamp first
	if ts, err := strconv.ParseInt(s, 10, 64); err == nil {
		return ts
	}

	// Try RFC3339
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.Unix()
	}

	// Try RFC3339Nano
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.Unix()
	}

	return 0
}

// Enabled returns true if TLS extraction is enabled.
func (e *Extractor) Enabled() bool {
	return e.cfg.Enabled
}

// RequireVerified returns true if verified certificates are required.
func (e *Extractor) RequireVerified() bool {
	return e.cfg.RequireVerified
}
