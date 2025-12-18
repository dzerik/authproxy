package tls

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/your-org/authz-service/internal/config"
)

func TestExtractor_ExtractFromXFCC(t *testing.T) {
	cfg := config.TLSClientCertConfig{
		Enabled: true,
		Sources: config.TLSSourcesConfig{
			XFCC: config.XFCCSourceConfig{
				Enabled: true,
				Header:  "X-Forwarded-Client-Cert",
			},
			Headers: config.HeadersSourceConfig{
				Enabled: false,
			},
		},
	}

	extractor, err := NewExtractor(cfg)
	if err != nil {
		t.Fatalf("failed to create extractor: %v", err)
	}

	tests := []struct {
		name               string
		xfccHeader         string
		wantVerified       bool
		wantSubject        string
		wantCommonName     string
		wantFingerprint    string
		wantURIs           []string
		wantDNSNames       []string
		wantSPIFFETD       string
		wantSPIFFENS       string
		wantSPIFFESA       string
	}{
		{
			name:               "full XFCC header with SPIFFE",
			xfccHeader:         `Hash=abc123;Subject="CN=payment-service,O=MyOrg";URI=spiffe://cluster.local/ns/production/sa/payment-service;DNS=payment.default.svc.cluster.local`,
			wantVerified:       true,
			wantSubject:        "CN=payment-service,O=MyOrg",
			wantCommonName:     "payment-service",
			wantFingerprint:    "abc123",
			wantURIs:           []string{"spiffe://cluster.local/ns/production/sa/payment-service"},
			wantDNSNames:       []string{"payment.default.svc.cluster.local"},
			wantSPIFFETD:       "cluster.local",
			wantSPIFFENS:       "production",
			wantSPIFFESA:       "payment-service",
		},
		{
			name:               "XFCC with quoted values",
			xfccHeader:         `Hash=def456;Subject="CN=order-service, O=MyOrg, OU=Backend";URI=spiffe://prod.example.com/ns/orders/sa/order-svc`,
			wantVerified:       true,
			wantSubject:        "CN=order-service, O=MyOrg, OU=Backend",
			wantCommonName:     "order-service",
			wantFingerprint:    "def456",
			wantURIs:           []string{"spiffe://prod.example.com/ns/orders/sa/order-svc"},
			wantSPIFFETD:       "prod.example.com",
			wantSPIFFENS:       "orders",
			wantSPIFFESA:       "order-svc",
		},
		{
			name:               "XFCC with multiple DNS",
			xfccHeader:         `Hash=ghi789;Subject="CN=api-gateway";DNS=api.example.com;DNS=gateway.example.com`,
			wantVerified:       true,
			wantSubject:        "CN=api-gateway",
			wantCommonName:     "api-gateway",
			wantFingerprint:    "ghi789",
			wantDNSNames:       []string{"api.example.com", "gateway.example.com"},
		},
		{
			name:       "empty XFCC header",
			xfccHeader: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.xfccHeader != "" {
				req.Header.Set("X-Forwarded-Client-Cert", tt.xfccHeader)
			}

			info := extractor.Extract(req)

			if tt.xfccHeader == "" {
				if info != nil {
					t.Errorf("expected nil info for empty header, got %+v", info)
				}
				return
			}

			if info == nil {
				t.Fatal("expected non-nil info")
			}

			if info.Verified != tt.wantVerified {
				t.Errorf("Verified = %v, want %v", info.Verified, tt.wantVerified)
			}
			if info.Subject != tt.wantSubject {
				t.Errorf("Subject = %q, want %q", info.Subject, tt.wantSubject)
			}
			if info.CommonName != tt.wantCommonName {
				t.Errorf("CommonName = %q, want %q", info.CommonName, tt.wantCommonName)
			}
			if info.Fingerprint != tt.wantFingerprint {
				t.Errorf("Fingerprint = %q, want %q", info.Fingerprint, tt.wantFingerprint)
			}

			if len(tt.wantURIs) > 0 {
				if len(info.URIs) != len(tt.wantURIs) {
					t.Errorf("URIs count = %d, want %d", len(info.URIs), len(tt.wantURIs))
				}
				for i, uri := range tt.wantURIs {
					if i < len(info.URIs) && info.URIs[i] != uri {
						t.Errorf("URIs[%d] = %q, want %q", i, info.URIs[i], uri)
					}
				}
			}

			if len(tt.wantDNSNames) > 0 {
				if len(info.DNSNames) != len(tt.wantDNSNames) {
					t.Errorf("DNSNames count = %d, want %d", len(info.DNSNames), len(tt.wantDNSNames))
				}
			}

			if tt.wantSPIFFETD != "" {
				if info.SPIFFE == nil {
					t.Fatal("expected non-nil SPIFFE info")
				}
				if info.SPIFFE.TrustDomain != tt.wantSPIFFETD {
					t.Errorf("SPIFFE.TrustDomain = %q, want %q", info.SPIFFE.TrustDomain, tt.wantSPIFFETD)
				}
				if info.SPIFFE.Namespace != tt.wantSPIFFENS {
					t.Errorf("SPIFFE.Namespace = %q, want %q", info.SPIFFE.Namespace, tt.wantSPIFFENS)
				}
				if info.SPIFFE.ServiceAccount != tt.wantSPIFFESA {
					t.Errorf("SPIFFE.ServiceAccount = %q, want %q", info.SPIFFE.ServiceAccount, tt.wantSPIFFESA)
				}
			}
		})
	}
}

func TestExtractor_ExtractFromHeaders(t *testing.T) {
	cfg := config.TLSClientCertConfig{
		Enabled: true,
		Sources: config.TLSSourcesConfig{
			XFCC: config.XFCCSourceConfig{
				Enabled: false,
			},
			Headers: config.HeadersSourceConfig{
				Enabled:       true,
				Subject:       "X-SSL-Client-S-DN",
				Issuer:        "X-SSL-Client-I-DN",
				CommonName:    "X-SSL-Client-CN",
				Serial:        "X-SSL-Client-Serial",
				Verified:      "X-SSL-Client-Verify",
				VerifiedValue: "SUCCESS",
				Fingerprint:   "X-SSL-Client-Fingerprint",
				DNSNames:      "X-SSL-Client-DNS",
				URI:           "X-SSL-Client-URI",
				NotBefore:     "X-SSL-Client-Not-Before",
				NotAfter:      "X-SSL-Client-Not-After",
			},
		},
	}

	extractor, err := NewExtractor(cfg)
	if err != nil {
		t.Fatalf("failed to create extractor: %v", err)
	}

	tests := []struct {
		name           string
		headers        map[string]string
		wantVerified   bool
		wantSubject    string
		wantCommonName string
		wantSerial     string
	}{
		{
			name: "full headers",
			headers: map[string]string{
				"X-SSL-Client-S-DN":        "CN=backend-service,O=MyOrg",
				"X-SSL-Client-I-DN":        "CN=My CA,O=MyOrg",
				"X-SSL-Client-CN":          "backend-service",
				"X-SSL-Client-Serial":      "1234567890",
				"X-SSL-Client-Verify":      "SUCCESS",
				"X-SSL-Client-Fingerprint": "sha256:abcdef",
			},
			wantVerified:   true,
			wantSubject:    "CN=backend-service,O=MyOrg",
			wantCommonName: "backend-service",
			wantSerial:     "1234567890",
		},
		{
			name: "verification failed",
			headers: map[string]string{
				"X-SSL-Client-S-DN":   "CN=untrusted",
				"X-SSL-Client-Verify": "FAILED",
			},
			wantVerified:   false,
			wantSubject:    "CN=untrusted",
			wantCommonName: "untrusted", // CN is extracted from subject regardless of verification
		},
		{
			name: "CN extracted from subject",
			headers: map[string]string{
				"X-SSL-Client-S-DN":   "CN=extracted-cn,O=Org",
				"X-SSL-Client-Verify": "SUCCESS",
			},
			wantVerified:   true,
			wantSubject:    "CN=extracted-cn,O=Org",
			wantCommonName: "extracted-cn",
		},
		{
			name:    "no headers",
			headers: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			info := extractor.Extract(req)

			if len(tt.headers) == 0 {
				if info != nil {
					t.Errorf("expected nil info for no headers, got %+v", info)
				}
				return
			}

			if info == nil {
				t.Fatal("expected non-nil info")
			}

			if info.Verified != tt.wantVerified {
				t.Errorf("Verified = %v, want %v", info.Verified, tt.wantVerified)
			}
			if info.Subject != tt.wantSubject {
				t.Errorf("Subject = %q, want %q", info.Subject, tt.wantSubject)
			}
			if info.CommonName != tt.wantCommonName {
				t.Errorf("CommonName = %q, want %q", info.CommonName, tt.wantCommonName)
			}
			if tt.wantSerial != "" && info.Serial != tt.wantSerial {
				t.Errorf("Serial = %q, want %q", info.Serial, tt.wantSerial)
			}
		})
	}
}

func TestExtractor_CascadeMode(t *testing.T) {
	cfg := config.TLSClientCertConfig{
		Enabled: true,
		Sources: config.TLSSourcesConfig{
			XFCC: config.XFCCSourceConfig{
				Enabled: true,
				Header:  "X-Forwarded-Client-Cert",
			},
			Headers: config.HeadersSourceConfig{
				Enabled:       true,
				Subject:       "X-SSL-Client-S-DN",
				Serial:        "X-SSL-Client-Serial",
				Verified:      "X-SSL-Client-Verify",
				VerifiedValue: "SUCCESS",
				NotBefore:     "X-SSL-Client-Not-Before",
				NotAfter:      "X-SSL-Client-Not-After",
			},
		},
	}

	extractor, err := NewExtractor(cfg)
	if err != nil {
		t.Fatalf("failed to create extractor: %v", err)
	}

	t.Run("XFCC takes priority, headers fill missing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		// XFCC provides Subject and URI
		req.Header.Set("X-Forwarded-Client-Cert", `Hash=abc;Subject="CN=from-xfcc";URI=spiffe://td/ns/ns1/sa/sa1`)
		// Headers provide Serial, timestamps, and Verified (needed for headers parser to trigger)
		req.Header.Set("X-SSL-Client-Verify", "SUCCESS")
		req.Header.Set("X-SSL-Client-Serial", "12345")
		req.Header.Set("X-SSL-Client-Not-Before", "1700000000")
		req.Header.Set("X-SSL-Client-Not-After", "1800000000")

		info := extractor.Extract(req)
		if info == nil {
			t.Fatal("expected non-nil info")
		}

		// From XFCC
		if info.Subject != "CN=from-xfcc" {
			t.Errorf("Subject = %q, want 'CN=from-xfcc'", info.Subject)
		}
		if info.Fingerprint != "abc" {
			t.Errorf("Fingerprint = %q, want 'abc'", info.Fingerprint)
		}

		// Merged from headers
		if info.Serial != "12345" {
			t.Errorf("Serial = %q, want '12345'", info.Serial)
		}
		if info.NotBefore != 1700000000 {
			t.Errorf("NotBefore = %d, want 1700000000", info.NotBefore)
		}
		if info.NotAfter != 1800000000 {
			t.Errorf("NotAfter = %d, want 1800000000", info.NotAfter)
		}

		// SPIFFE parsed
		if info.SPIFFE == nil {
			t.Fatal("expected non-nil SPIFFE")
		}
		if info.SPIFFE.Namespace != "ns1" {
			t.Errorf("SPIFFE.Namespace = %q, want 'ns1'", info.SPIFFE.Namespace)
		}
	})

	t.Run("only headers when no XFCC", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-SSL-Client-S-DN", "CN=from-headers")
		req.Header.Set("X-SSL-Client-Serial", "99999")
		req.Header.Set("X-SSL-Client-Verify", "SUCCESS")

		info := extractor.Extract(req)
		if info == nil {
			t.Fatal("expected non-nil info")
		}

		if info.Subject != "CN=from-headers" {
			t.Errorf("Subject = %q, want 'CN=from-headers'", info.Subject)
		}
		if info.Serial != "99999" {
			t.Errorf("Serial = %q, want '99999'", info.Serial)
		}
		if !info.Verified {
			t.Error("expected Verified = true")
		}
	})
}

func TestExtractor_TrustedSPIFFEDomains(t *testing.T) {
	cfg := config.TLSClientCertConfig{
		Enabled: true,
		Sources: config.TLSSourcesConfig{
			XFCC: config.XFCCSourceConfig{
				Enabled: true,
				Header:  "X-Forwarded-Client-Cert",
			},
		},
		TrustedSPIFFEDomains: []string{"cluster.local", "prod.example.com"},
	}

	extractor, err := NewExtractor(cfg)
	if err != nil {
		t.Fatalf("failed to create extractor: %v", err)
	}

	t.Run("trusted domain accepted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Forwarded-Client-Cert", `URI=spiffe://cluster.local/ns/default/sa/test`)

		info := extractor.Extract(req)
		if info == nil {
			t.Fatal("expected non-nil info")
		}
		if info.SPIFFE == nil {
			t.Fatal("expected non-nil SPIFFE")
		}
		if info.SPIFFE.TrustDomain != "cluster.local" {
			t.Errorf("TrustDomain = %q, want 'cluster.local'", info.SPIFFE.TrustDomain)
		}
	})

	t.Run("untrusted domain rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Forwarded-Client-Cert", `URI=spiffe://untrusted.com/ns/default/sa/test`)

		info := extractor.Extract(req)
		if info == nil {
			t.Fatal("expected non-nil info")
		}
		// SPIFFE should be nil because trust domain not in allowed list
		if info.SPIFFE != nil {
			t.Errorf("expected nil SPIFFE for untrusted domain, got %+v", info.SPIFFE)
		}
	})
}

func TestExtractor_TrustedProxyCIDRs(t *testing.T) {
	cfg := config.TLSClientCertConfig{
		Enabled: true,
		Sources: config.TLSSourcesConfig{
			XFCC: config.XFCCSourceConfig{
				Enabled: true,
				Header:  "X-Forwarded-Client-Cert",
			},
		},
		TrustedProxyCIDRs: []string{"10.0.0.0/8", "192.168.1.0/24"},
	}

	extractor, err := NewExtractor(cfg)
	if err != nil {
		t.Fatalf("failed to create extractor: %v", err)
	}

	t.Run("trusted proxy accepted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.1.2.3:12345"
		req.Header.Set("X-Forwarded-Client-Cert", `Subject="CN=test"`)

		info := extractor.Extract(req)
		if info == nil {
			t.Fatal("expected non-nil info")
		}
		if info.Subject != "CN=test" {
			t.Errorf("Subject = %q, want 'CN=test'", info.Subject)
		}
	})

	t.Run("untrusted proxy ignored", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "172.16.0.1:12345"
		req.Header.Set("X-Forwarded-Client-Cert", `Subject="CN=test"`)

		info := extractor.Extract(req)
		// Should be nil because XFCC from untrusted proxy is ignored
		if info != nil {
			t.Errorf("expected nil info from untrusted proxy, got %+v", info)
		}
	})
}

func TestParseSPIFFEURI(t *testing.T) {
	tests := []struct {
		name           string
		uri            string
		wantTD         string
		wantNS         string
		wantSA         string
		wantPath       string
	}{
		{
			name:     "kubernetes format",
			uri:      "spiffe://cluster.local/ns/production/sa/payment-service",
			wantTD:   "cluster.local",
			wantNS:   "production",
			wantSA:   "payment-service",
			wantPath: "/ns/production/sa/payment-service",
		},
		{
			name:     "custom path",
			uri:      "spiffe://example.com/workload/web-server",
			wantTD:   "example.com",
			wantPath: "/workload/web-server",
		},
		{
			name:   "trust domain only",
			uri:    "spiffe://simple.local",
			wantTD: "simple.local",
		},
		{
			name: "not spiffe",
			uri:  "https://example.com/path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := parseSPIFFEURI(tt.uri)

			if tt.wantTD == "" {
				if info != nil {
					t.Errorf("expected nil for non-SPIFFE URI")
				}
				return
			}

			if info == nil {
				t.Fatal("expected non-nil info")
			}

			if info.TrustDomain != tt.wantTD {
				t.Errorf("TrustDomain = %q, want %q", info.TrustDomain, tt.wantTD)
			}
			if info.Namespace != tt.wantNS {
				t.Errorf("Namespace = %q, want %q", info.Namespace, tt.wantNS)
			}
			if info.ServiceAccount != tt.wantSA {
				t.Errorf("ServiceAccount = %q, want %q", info.ServiceAccount, tt.wantSA)
			}
			if tt.wantPath != "" && info.Path != tt.wantPath {
				t.Errorf("Path = %q, want %q", info.Path, tt.wantPath)
			}
		})
	}
}

func TestExtractCNFromDN(t *testing.T) {
	tests := []struct {
		dn     string
		wantCN string
	}{
		{"CN=test-service,O=MyOrg", "test-service"},
		{"CN=service, O=Org, OU=Unit", "service"},
		{"O=NoCommonName,OU=Unit", ""},
		{"cn=lowercase,O=Org", "lowercase"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.dn, func(t *testing.T) {
			cn := extractCNFromDN(tt.dn)
			if cn != tt.wantCN {
				t.Errorf("extractCNFromDN(%q) = %q, want %q", tt.dn, cn, tt.wantCN)
			}
		})
	}
}

func TestParseTimestamp(t *testing.T) {
	tests := []struct {
		input string
		want  int64
	}{
		{"1700000000", 1700000000},
		{"2023-11-14T12:00:00Z", 1699963200},
		{"invalid", 0},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseTimestamp(tt.input)
			if got != tt.want {
				t.Errorf("parseTimestamp(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}
