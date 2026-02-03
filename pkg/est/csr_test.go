package est

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestReadCSRPayload(t *testing.T) {
	// Generate a valid CSR for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		DNSNames: []string{"test.example.com", "www.test.example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			name:    "valid base64 encoded DER",
			body:    base64.StdEncoding.EncodeToString(csrDER),
			wantErr: false,
		},
		{
			name:    "valid PEM encoded",
			body:    base64.StdEncoding.EncodeToString(csrPEM),
			wantErr: false,
		},
		{
			name:    "raw DER (no base64)",
			body:    string(csrDER),
			wantErr: false,
		},
		{
			name:    "invalid base64",
			body:    "not-valid-base64!!!",
			wantErr: true,
		},
		{
			name:    "empty body",
			body:    "",
			wantErr: true,
		},
		{
			name:    "garbage data",
			body:    base64.StdEncoding.EncodeToString([]byte("garbage")),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/test", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/pkcs10")

			csr, err := ReadCSRPayload(req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadCSRPayload() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if csr == nil {
					t.Error("ReadCSRPayload() returned nil CSR without error")
					return
				}
				if csr.Subject.CommonName != "test.example.com" {
					t.Errorf("CSR CommonName = %s, want test.example.com", csr.Subject.CommonName)
				}
			}
		})
	}
}

func TestReadCSRPayloadSizeLimit(t *testing.T) {
	// Create a request with body larger than 10MB
	largeBody := strings.Repeat("A", 11*1024*1024)
	req := httptest.NewRequest("POST", "/test", strings.NewReader(largeBody))

	_, err := ReadCSRPayload(req)
	if err == nil {
		t.Error("ReadCSRPayload() should fail with oversized body")
		return
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("Expected oversized body error, got: %v", err)
	}
}

func TestValidateCSRSignature(t *testing.T) {
	// Generate a valid CSR
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	// Test valid signature
	err = ValidateCSRSignature(csr)
	if err != nil {
		t.Errorf("ValidateCSRSignature() failed for valid CSR: %v", err)
	}

	// Test invalid signature by corrupting the CSR
	corruptedDER := make([]byte, len(csrDER))
	copy(corruptedDER, csrDER)
	corruptedDER[len(corruptedDER)-1] ^= 0xFF // Flip last byte

	corruptedCSR, _ := x509.ParseCertificateRequest(corruptedDER)
	if corruptedCSR != nil {
		err = ValidateCSRSignature(corruptedCSR)
		if err == nil {
			t.Error("ValidateCSRSignature() should fail for corrupted CSR")
		}
	}
}

func TestValidateCSRMatchesCertificate(t *testing.T) {
	// Generate key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create CSR with this key
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	// Create certificate with the same key
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Test matching keys
	err = ValidateCSRMatchesCertificate(csr, cert)
	if err != nil {
		t.Errorf("ValidateCSRMatchesCertificate() failed for matching keys: %v", err)
	}

	// Test non-matching keys
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherCSRDER, _ := x509.CreateCertificateRequest(rand.Reader, csrTemplate, otherKey)
	otherCSR, _ := x509.ParseCertificateRequest(otherCSRDER)

	err = ValidateCSRMatchesCertificate(otherCSR, cert)
	if err == nil {
		t.Error("ValidateCSRMatchesCertificate() should fail for non-matching keys")
	}
}

func TestReadCSRPayloadWithDifferentContentTypes(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test.example.com"},
	}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	csrB64 := base64.StdEncoding.EncodeToString(csrDER)

	tests := []struct {
		name        string
		contentType string
		body        string
		wantErr     bool
	}{
		{
			name:        "application/pkcs10",
			contentType: "application/pkcs10",
			body:        csrB64,
			wantErr:     false,
		},
		{
			name:        "application/pkcs10; charset=utf-8",
			contentType: "application/pkcs10; charset=utf-8",
			body:        csrB64,
			wantErr:     false,
		},
		{
			name:        "no content type",
			contentType: "",
			body:        csrB64,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/test", strings.NewReader(tt.body))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}

			csr, err := ReadCSRPayload(req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadCSRPayload() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && csr == nil {
				t.Error("ReadCSRPayload() returned nil CSR without error")
			}
		})
	}
}

func TestCSRWithSANs(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		DNSNames:       []string{"alt1.example.com", "alt2.example.com"},
		EmailAddresses: []string{"test@example.com"},
		IPAddresses:    []net.IP{net.ParseIP("192.168.1.1")},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	csrB64 := base64.StdEncoding.EncodeToString(csrDER)
	req := httptest.NewRequest("POST", "/test", strings.NewReader(csrB64))

	csr, err := ReadCSRPayload(req)
	if err != nil {
		t.Fatalf("ReadCSRPayload() error = %v", err)
	}

	if len(csr.DNSNames) != 2 {
		t.Errorf("CSR DNSNames count = %d, want 2", len(csr.DNSNames))
	}
	if len(csr.EmailAddresses) != 1 {
		t.Errorf("CSR EmailAddresses count = %d, want 1", len(csr.EmailAddresses))
	}
	if len(csr.IPAddresses) != 1 {
		t.Errorf("CSR IPAddresses count = %d, want 1", len(csr.IPAddresses))
	}
}

func TestEmptyCommonName(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "",
		},
		DNSNames: []string{"test.example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	csrB64 := base64.StdEncoding.EncodeToString(csrDER)
	req := httptest.NewRequest("POST", "/test", strings.NewReader(csrB64))

	csr, err := ReadCSRPayload(req)
	if err != nil {
		t.Fatalf("ReadCSRPayload() error = %v", err)
	}

	if csr.Subject.CommonName != "" {
		t.Errorf("CSR CommonName = %s, want empty", csr.Subject.CommonName)
	}
	if len(csr.DNSNames) == 0 {
		t.Error("CSR should have at least one DNS SAN when CN is empty")
	}
}

func TestValidateReenrollmentSubject(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	tests := []struct {
		name            string
		csrSubject      pkix.Name
		certSubject     pkix.Name
		csrDNSNames     []string
		certDNSNames    []string
		csrEmails       []string
		certEmails      []string
		csrIPs          []net.IP
		certIPs         []net.IP
		includeChangeSN bool
		expectError     bool
		errorContains   string
	}{
		{
			name: "identical subject and SANs - should pass",
			csrSubject: pkix.Name{
				CommonName:   "test.example.com",
				Organization: []string{"Test Org"},
			},
			certSubject: pkix.Name{
				CommonName:   "test.example.com",
				Organization: []string{"Test Org"},
			},
			csrDNSNames:  []string{"alt1.example.com", "alt2.example.com"},
			certDNSNames: []string{"alt1.example.com", "alt2.example.com"},
			expectError:  false,
		},
		{
			name: "different subject without ChangeSubjectName - should fail",
			csrSubject: pkix.Name{
				CommonName:   "new.example.com",
				Organization: []string{"New Org"},
			},
			certSubject: pkix.Name{
				CommonName:   "old.example.com",
				Organization: []string{"Old Org"},
			},
			expectError:   true,
			errorContains: "does not match existing certificate Subject",
		},
		{
			name: "different subject with ChangeSubjectName - should pass",
			csrSubject: pkix.Name{
				CommonName:   "new.example.com",
				Organization: []string{"New Org"},
			},
			certSubject: pkix.Name{
				CommonName:   "old.example.com",
				Organization: []string{"Old Org"},
			},
			includeChangeSN: true,
			expectError:     false,
		},
		{
			name: "different DNS names without ChangeSubjectName - should fail",
			csrSubject: pkix.Name{
				CommonName: "test.example.com",
			},
			certSubject: pkix.Name{
				CommonName: "test.example.com",
			},
			csrDNSNames:   []string{"new.example.com"},
			certDNSNames:  []string{"old.example.com"},
			expectError:   true,
			errorContains: "DNS names",
		},
		{
			name: "DNS names in different order - should pass",
			csrSubject: pkix.Name{
				CommonName: "test.example.com",
			},
			certSubject: pkix.Name{
				CommonName: "test.example.com",
			},
			csrDNSNames:  []string{"alt2.example.com", "alt1.example.com"},
			certDNSNames: []string{"alt1.example.com", "alt2.example.com"},
			expectError:  false,
		},
		{
			name: "different email addresses - should fail",
			csrSubject: pkix.Name{
				CommonName: "test.example.com",
			},
			certSubject: pkix.Name{
				CommonName: "test.example.com",
			},
			csrEmails:     []string{"new@example.com"},
			certEmails:    []string{"old@example.com"},
			expectError:   true,
			errorContains: "email addresses",
		},
		{
			name: "email addresses in different order - should pass",
			csrSubject: pkix.Name{
				CommonName: "test.example.com",
			},
			certSubject: pkix.Name{
				CommonName: "test.example.com",
			},
			csrEmails:   []string{"b@example.com", "a@example.com"},
			certEmails:  []string{"a@example.com", "b@example.com"},
			expectError: false,
		},
		{
			name: "different IP addresses - should fail",
			csrSubject: pkix.Name{
				CommonName: "test.example.com",
			},
			certSubject: pkix.Name{
				CommonName: "test.example.com",
			},
			csrIPs:        []net.IP{net.ParseIP("192.168.1.1")},
			certIPs:       []net.IP{net.ParseIP("192.168.1.2")},
			expectError:   true,
			errorContains: "IP addresses",
		},
		{
			name: "IP addresses in different order - should pass",
			csrSubject: pkix.Name{
				CommonName: "test.example.com",
			},
			certSubject: pkix.Name{
				CommonName: "test.example.com",
			},
			csrIPs:      []net.IP{net.ParseIP("192.168.1.2"), net.ParseIP("192.168.1.1")},
			certIPs:     []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.2")},
			expectError: false,
		},
		{
			name: "empty SANs on both - should pass",
			csrSubject: pkix.Name{
				CommonName: "test.example.com",
			},
			certSubject: pkix.Name{
				CommonName: "test.example.com",
			},
			expectError: false,
		},
		{
			name: "complex matching SANs - should pass",
			csrSubject: pkix.Name{
				CommonName: "test.example.com",
			},
			certSubject: pkix.Name{
				CommonName: "test.example.com",
			},
			csrDNSNames:  []string{"alt1.example.com", "alt2.example.com"},
			certDNSNames: []string{"alt1.example.com", "alt2.example.com"},
			csrEmails:    []string{"admin@example.com"},
			certEmails:   []string{"admin@example.com"},
			csrIPs:       []net.IP{net.ParseIP("192.168.1.1")},
			certIPs:      []net.IP{net.ParseIP("192.168.1.1")},
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create CSR template
			csrTemplate := &x509.CertificateRequest{
				Subject:        tt.csrSubject,
				DNSNames:       tt.csrDNSNames,
				EmailAddresses: tt.csrEmails,
				IPAddresses:    tt.csrIPs,
			}

			// Add ChangeSubjectName attribute if requested
			if tt.includeChangeSN {
				csrTemplate.Attributes = []pkix.AttributeTypeAndValueSET{
					{
						Type: oidChangeSubjectName,
					},
				}
			}

			// Create CSR
			csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
			if err != nil {
				t.Fatalf("Failed to create CSR: %v", err)
			}
			csr, err := x509.ParseCertificateRequest(csrDER)
			if err != nil {
				t.Fatalf("Failed to parse CSR: %v", err)
			}

			// Create certificate template
			certTemplate := &x509.Certificate{
				SerialNumber:   big.NewInt(1),
				Subject:        tt.certSubject,
				NotBefore:      time.Now(),
				NotAfter:       time.Now().Add(24 * time.Hour),
				DNSNames:       tt.certDNSNames,
				EmailAddresses: tt.certEmails,
				IPAddresses:    tt.certIPs,
			}

			// Create certificate
			certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
			if err != nil {
				t.Fatalf("Failed to create certificate: %v", err)
			}
			cert, err := x509.ParseCertificate(certDER)
			if err != nil {
				t.Fatalf("Failed to parse certificate: %v", err)
			}

			// Validate
			err = ValidateReenrollmentSubject(csr, cert)

			if tt.expectError {
				if err == nil {
					t.Error("ValidateReenrollmentSubject() should have returned an error")
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Error message should contain %q, got: %v", tt.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateReenrollmentSubject() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestStringSlicesEqual(t *testing.T) {
	tests := []struct {
		name     string
		a        []string
		b        []string
		expected bool
	}{
		{
			name:     "identical slices",
			a:        []string{"a", "b", "c"},
			b:        []string{"a", "b", "c"},
			expected: true,
		},
		{
			name:     "different order",
			a:        []string{"c", "a", "b"},
			b:        []string{"a", "b", "c"},
			expected: true,
		},
		{
			name:     "different elements",
			a:        []string{"a", "b"},
			b:        []string{"a", "c"},
			expected: false,
		},
		{
			name:     "different lengths",
			a:        []string{"a", "b"},
			b:        []string{"a", "b", "c"},
			expected: false,
		},
		{
			name:     "empty slices",
			a:        []string{},
			b:        []string{},
			expected: true,
		},
		{
			name:     "nil vs empty",
			a:        nil,
			b:        []string{},
			expected: true,
		},
		{
			name:     "duplicate elements",
			a:        []string{"a", "a", "b"},
			b:        []string{"a", "b"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stringSlicesEqual(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("stringSlicesEqual(%v, %v) = %v, want %v", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

func TestIPSlicesEqual(t *testing.T) {
	tests := []struct {
		name     string
		a        []net.IP
		b        []net.IP
		expected bool
	}{
		{
			name:     "identical IPs",
			a:        []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("10.0.0.1")},
			b:        []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("10.0.0.1")},
			expected: true,
		},
		{
			name:     "different order",
			a:        []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("192.168.1.1")},
			b:        []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("10.0.0.1")},
			expected: true,
		},
		{
			name:     "different IPs",
			a:        []net.IP{net.ParseIP("192.168.1.1")},
			b:        []net.IP{net.ParseIP("192.168.1.2")},
			expected: false,
		},
		{
			name:     "empty slices",
			a:        []net.IP{},
			b:        []net.IP{},
			expected: true,
		},
		{
			name:     "IPv4 vs IPv6",
			a:        []net.IP{net.ParseIP("192.168.1.1")},
			b:        []net.IP{net.ParseIP("::1")},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ipSlicesEqual(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("ipSlicesEqual(%v, %v) = %v, want %v", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

func TestValidateCSRSignatureAlgorithm_EmptyWhitelist(t *testing.T) {
	// Generate RSA CSR
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	// Empty whitelist should allow all algorithms
	err = ValidateCSRSignatureAlgorithm(csr, []string{})
	if err != nil {
		t.Errorf("Empty whitelist should allow any algorithm, got error: %v", err)
	}

	err = ValidateCSRSignatureAlgorithm(csr, nil)
	if err != nil {
		t.Errorf("Nil whitelist should allow any algorithm, got error: %v", err)
	}
}

func TestValidateCSRSignatureAlgorithm_AllowedRSA(t *testing.T) {
	// Generate RSA CSR with SHA256
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	// CSR should use SHA256WithRSA (default for RSA)
	if csr.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Logf("Note: CSR uses %s instead of SHA256WithRSA", csr.SignatureAlgorithm.String())
	}

	// Whitelist should allow SHA256WithRSA
	allowed := []string{"SHA256WithRSA", "SHA384WithRSA", "SHA512WithRSA"}
	err = ValidateCSRSignatureAlgorithm(csr, allowed)
	if err != nil {
		t.Errorf("SHA256WithRSA should be allowed, got error: %v", err)
	}
}

func TestValidateCSRSignatureAlgorithm_AllowedECDSA(t *testing.T) {
	// Generate ECDSA CSR with P256 (uses SHA256)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	// CSR should use ECDSAWithSHA256
	if csr.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Logf("Note: CSR uses %s instead of ECDSAWithSHA256", csr.SignatureAlgorithm.String())
	}

	// Whitelist should allow ECDSAWithSHA256
	allowed := []string{"ECDSAWithSHA256", "ECDSAWithSHA384", "ECDSAWithSHA512"}
	err = ValidateCSRSignatureAlgorithm(csr, allowed)
	if err != nil {
		t.Errorf("ECDSAWithSHA256 should be allowed, got error: %v", err)
	}
}

func TestValidateCSRSignatureAlgorithm_DisallowedAlgorithm(t *testing.T) {
	// Generate RSA CSR (uses SHA256WithRSA)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	// Whitelist only allows ECDSA algorithms
	allowed := []string{"ECDSAWithSHA256", "ECDSAWithSHA384"}
	err = ValidateCSRSignatureAlgorithm(csr, allowed)
	if err == nil {
		t.Error("RSA CSR should be rejected when only ECDSA is allowed")
	}

	// Verify error message mentions the algorithm
	if err != nil && !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("Error should mention algorithm not allowed, got: %v", err)
	}
}

func TestValidateCSRSignatureAlgorithm_CaseInsensitive(t *testing.T) {
	// Generate RSA CSR
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	tests := []struct {
		name    string
		allowed []string
	}{
		{"lowercase", []string{"sha256withrsa"}},
		{"uppercase", []string{"SHA256WITHRSA"}},
		{"mixed case", []string{"Sha256WithRsa"}},
		{"with spaces", []string{" SHA256WithRSA "}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCSRSignatureAlgorithm(csr, tt.allowed)
			if err != nil {
				t.Errorf("Algorithm matching should be case-insensitive for %s, got error: %v", tt.name, err)
			}
		})
	}
}

func TestValidateCSRSignatureAlgorithm_InvalidConfigurationAllInvalid(t *testing.T) {
	// Generate RSA CSR
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	// Whitelist with all invalid algorithm names
	allowed := []string{"InvalidAlgo1", "NotAnAlgorithm", "BadConfig"}
	err = ValidateCSRSignatureAlgorithm(csr, allowed)
	if err == nil {
		t.Error("Should return error when all configured algorithms are invalid")
	}

	if err != nil && !strings.Contains(err.Error(), "no valid signature algorithms configured") {
		t.Errorf("Error should mention invalid configuration, got: %v", err)
	}
}

func TestValidateCSRSignatureAlgorithm_MixedValidInvalid(t *testing.T) {
	// Generate RSA CSR
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	// Whitelist with mix of valid and invalid names
	// Invalid names should be ignored, valid ones should work
	allowed := []string{"InvalidAlgo", "SHA256WithRSA", "NotAnAlgorithm", "SHA384WithRSA"}
	err = ValidateCSRSignatureAlgorithm(csr, allowed)
	if err != nil {
		t.Errorf("Should accept CSR when valid algorithms are in whitelist, got error: %v", err)
	}
}

func TestParseSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected x509.SignatureAlgorithm
		wantOk   bool
	}{
		// RSA algorithms
		{"MD5WithRSA", "MD5WithRSA", x509.MD5WithRSA, true},
		{"SHA1WithRSA", "SHA1WithRSA", x509.SHA1WithRSA, true},
		{"SHA256WithRSA", "SHA256WithRSA", x509.SHA256WithRSA, true},
		{"SHA384WithRSA", "SHA384WithRSA", x509.SHA384WithRSA, true},
		{"SHA512WithRSA", "SHA512WithRSA", x509.SHA512WithRSA, true},

		// ECDSA algorithms
		{"ECDSAWithSHA1", "ECDSAWithSHA1", x509.ECDSAWithSHA1, true},
		{"ECDSAWithSHA256", "ECDSAWithSHA256", x509.ECDSAWithSHA256, true},
		{"ECDSAWithSHA384", "ECDSAWithSHA384", x509.ECDSAWithSHA384, true},
		{"ECDSAWithSHA512", "ECDSAWithSHA512", x509.ECDSAWithSHA512, true},

		// Case variations
		{"lowercase", "sha256withrsa", x509.SHA256WithRSA, true},
		{"uppercase", "SHA256WITHRSA", x509.SHA256WithRSA, true},
		{"mixed case", "Sha256WithRsa", x509.SHA256WithRSA, true},

		// With whitespace
		{"leading space", " SHA256WithRSA", x509.SHA256WithRSA, true},
		{"trailing space", "SHA256WithRSA ", x509.SHA256WithRSA, true},
		{"both spaces", " SHA256WithRSA ", x509.SHA256WithRSA, true},

		// Invalid inputs
		{"unknown algorithm", "UnknownAlgo", x509.UnknownSignatureAlgorithm, false},
		{"empty string", "", x509.UnknownSignatureAlgorithm, false},
		{"gibberish", "not-a-valid-algorithm", x509.UnknownSignatureAlgorithm, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algo, ok := parseSignatureAlgorithm(tt.input)
			if ok != tt.wantOk {
				t.Errorf("parseSignatureAlgorithm(%q) ok = %v, want %v", tt.input, ok, tt.wantOk)
			}
			if algo != tt.expected {
				t.Errorf("parseSignatureAlgorithm(%q) = %v, want %v", tt.input, algo, tt.expected)
			}
		})
	}
}
