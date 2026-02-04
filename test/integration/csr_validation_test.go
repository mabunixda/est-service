//go:build integration
// +build integration

package integration

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/mabunixda/est-service/pkg/handlers"
)

func TestCSRValidation(t *testing.T) {
	env := Setup(t)
	defer env.Cleanup(t)

	config := &handlers.EnrollmentConfig{
		DefaultMount: env.PKIMount,
		DefaultPolicy: handlers.LabelPolicy{
			Type:  "role",
			Value: "est-devices",
			TTL:   "24h",
		},
		Labels:     make(map[string]handlers.LabelPolicy),
		MaxCSRSize: 1024, // Small size for testing
	}

	env.StartServer(t, config)

	username := "est-device"
	password := "device-secret-123"
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	authHeader := "Basic " + auth

	t.Run("valid CSR", func(t *testing.T) {
		csr, _ := GenerateCSR(t, "valid-csr.example.com")

		cert, err := env.EnrollCertificate(t, csr, authHeader)
		if err != nil {
			t.Fatalf("Valid CSR should be accepted: %v", err)
		}

		if cert == nil {
			t.Fatal("No certificate returned for valid CSR")
		}
	})

	t.Run("CSR with SANs", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		template := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "san-test.example.com",
				Organization: []string{"Test Org"},
			},
			DNSNames: []string{"san1.example.com", "san2.example.com"},
		}

		csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
		if err != nil {
			t.Fatalf("Failed to create CSR: %v", err)
		}

		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			t.Fatalf("Failed to parse CSR: %v", err)
		}

		cert, err := env.EnrollCertificate(t, csr, authHeader)
		if err != nil {
			t.Fatalf("CSR with SANs should be accepted: %v", err)
		}

		if cert == nil {
			t.Fatal("No certificate returned for CSR with SANs")
		}

		// Verify SANs were preserved
		if len(cert.DNSNames) == 0 {
			t.Error("SANs were not preserved in certificate")
		}
	})

	t.Run("oversized CSR", func(t *testing.T) {
		// Create a CSR with very long fields to exceed size limit
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		// Create a CSR with an extremely long organization name
		longOrg := strings.Repeat("A", 5000)
		template := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "oversized.example.com",
				Organization: []string{longOrg},
			},
		}

		csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
		if err != nil {
			t.Fatalf("Failed to create CSR: %v", err)
		}

		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			t.Fatalf("Failed to parse CSR: %v", err)
		}

		_, err = env.EnrollCertificate(t, csr, authHeader)
		if err == nil {
			t.Fatal("Oversized CSR should be rejected")
		}
	})

	t.Run("empty common name", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		template := &x509.CertificateRequest{
			Subject: pkix.Name{
				Organization: []string{"Test Org"},
				// No CommonName
			},
		}

		csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
		if err != nil {
			t.Fatalf("Failed to create CSR: %v", err)
		}

		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			t.Fatalf("Failed to parse CSR: %v", err)
		}

		// CSR without CN might still be valid if SANs are present
		// This depends on PKI role configuration
		_, err = env.EnrollCertificate(t, csr, authHeader)
		// We don't assert success/failure as it depends on backend config
		t.Logf("Empty CN result: %v", err)
	})
}
