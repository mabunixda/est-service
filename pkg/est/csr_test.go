package est

import (
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
