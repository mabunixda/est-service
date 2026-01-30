package integration

import (
	"encoding/base64"
	"os"
	"testing"
	"time"

	"github.com/mabunixda/est-service/pkg/handlers"
)

func TestSimpleReenroll(t *testing.T) {
	env := Setup(t)
	defer env.Cleanup(t)

	config := &handlers.EnrollmentConfig{
		DefaultMount: env.PKIMount,
		DefaultPolicy: handlers.LabelPolicy{
			Type:  "role",
			Value: "test-role",
			Mount: env.PKIMount,
		},
	}
	env.StartServer(t, config)

	// First, enroll a certificate
	csr, _ := GenerateCSR(t, "reenroll-test.example.com")
	authHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte("testuser:testpass"))

	cert, err := env.EnrollCertificate(t, csr, authHeader)
	if err != nil {
		t.Fatalf("Initial enrollment failed: %v", err)
	}

	t.Run("successful reenrollment with same CN", func(t *testing.T) {
		newCSR, _ := GenerateCSR(t, cert.Subject.CommonName)
		newCert, err := env.ReenrollCertificate(t, newCSR, authHeader, cert)

		if err != nil {
			t.Errorf("Reenrollment failed: %v", err)
			return
		}

		// Verify the new certificate
		if newCert.Subject.CommonName != newCSR.Subject.CommonName {
			t.Errorf("CN = %s, want %s", newCert.Subject.CommonName, newCSR.Subject.CommonName)
		}

		// Verify it's a different certificate
		if newCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			t.Error("Reenrolled cert has same serial number as original")
		}

		// Verify expiry is in the future
		if !newCert.NotAfter.After(time.Now()) {
			t.Error("Reenrolled cert is already expired")
		}
	})

	t.Run("reenrollment with different CN", func(t *testing.T) {
		newCSR, _ := GenerateCSR(t, "different.example.com")
		newCert, err := env.ReenrollCertificate(t, newCSR, authHeader, cert)

		if err != nil {
			t.Errorf("Reenrollment failed: %v", err)
			return
		}

		if newCert.Subject.CommonName != newCSR.Subject.CommonName {
			t.Errorf("CN = %s, want %s", newCert.Subject.CommonName, newCSR.Subject.CommonName)
		}
	})

	t.Run("reenrollment without auth", func(t *testing.T) {
		newCSR, _ := GenerateCSR(t, cert.Subject.CommonName)
		_, err := env.ReenrollCertificate(t, newCSR, "", cert)

		if err == nil {
			t.Error("Expected error but got none")
		}
	})
}

func TestReenrollWithDifferentAuth(t *testing.T) {
	env := Setup(t)
	defer env.Cleanup(t)

	config := &handlers.EnrollmentConfig{
		DefaultMount: env.PKIMount,
		DefaultPolicy: handlers.LabelPolicy{
			Type:  "role",
			Value: "test-role",
			Mount: env.PKIMount,
		},
	}
	env.StartServer(t, config)

	// Enroll with basic auth
	csr, _ := GenerateCSR(t, "multiauth-test.example.com")
	basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("testuser:testpass"))

	cert, err := env.EnrollCertificate(t, csr, basicAuth)
	if err != nil {
		t.Fatalf("Initial enrollment failed: %v", err)
	}

	// Reenroll with bearer token
	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		token = os.Getenv("BAO_TOKEN")
	}
	if token != "" {
		newCSR, _ := GenerateCSR(t, cert.Subject.CommonName)
		bearerAuth := "Bearer " + token

		newCert, err := env.ReenrollCertificate(t, newCSR, bearerAuth, cert)
		if err != nil {
			t.Errorf("Reenrollment with different auth failed: %v", err)
			return
		}

		if newCert.Subject.CommonName != cert.Subject.CommonName {
			t.Errorf("CN changed during reenrollment: %s -> %s", cert.Subject.CommonName, newCert.Subject.CommonName)
		}
	} else {
		t.Skip("No token available for bearer auth test")
	}
}
