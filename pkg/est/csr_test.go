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
