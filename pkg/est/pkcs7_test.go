package est

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
)

func TestCreatePKCS7CertsOnly(t *testing.T) {
	// Generate a test certificate
	cert := generateTestCertificate(t)

	t.Run("valid certificate", func(t *testing.T) {
		data, err := CreatePKCS7CertsOnly([]*x509.Certificate{cert})
		if err != nil {
			t.Fatalf("CreatePKCS7CertsOnly failed: %v", err)
		}

		if len(data) == 0 {
			t.Fatal("Expected non-empty PKCS#7 data")
		}

		// Try to parse it back
		certs, err := ParsePKCS7(data)
		if err != nil {
			t.Fatalf("Failed to parse generated PKCS#7: %v", err)
		}

		if len(certs) != 1 {
			t.Fatalf("Expected 1 certificate, got %d", len(certs))
		}

		if !cert.Equal(certs[0]) {
			t.Fatal("Parsed certificate doesn't match original")
		}
	})

	t.Run("multiple certificates", func(t *testing.T) {
		cert2 := generateTestCertificate(t)
		data, err := CreatePKCS7CertsOnly([]*x509.Certificate{cert, cert2})
		if err != nil {
			t.Fatalf("CreatePKCS7CertsOnly failed: %v", err)
		}

		certs, err := ParsePKCS7(data)
		if err != nil {
			t.Fatalf("Failed to parse PKCS#7: %v", err)
		}

		if len(certs) != 2 {
			t.Fatalf("Expected 2 certificates, got %d", len(certs))
		}
	})

	t.Run("empty certificate list", func(t *testing.T) {
		_, err := CreatePKCS7CertsOnly([]*x509.Certificate{})
		if err == nil {
			t.Fatal("Expected error for empty certificate list")
		}
	})
}

func TestBuildCAChain(t *testing.T) {
	cert := generateTestCertificate(t)
	certPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}))

	t.Run("single certificate", func(t *testing.T) {
		certs, err := BuildCAChain(certPEM, nil)
		if err != nil {
			t.Fatalf("BuildCAChain failed: %v", err)
		}

		if len(certs) != 1 {
			t.Fatalf("Expected 1 certificate, got %d", len(certs))
		}

		if !cert.Equal(certs[0]) {
			t.Fatal("Certificate doesn't match")
		}
	})

	t.Run("with chain", func(t *testing.T) {
		cert2 := generateTestCertificate(t)
		cert2PEM := string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert2.Raw,
		}))

		certs, err := BuildCAChain(certPEM, []string{cert2PEM})
		if err != nil {
			t.Fatalf("BuildCAChain failed: %v", err)
		}

		if len(certs) != 2 {
			t.Fatalf("Expected 2 certificates, got %d", len(certs))
		}
	})

	t.Run("empty PEM", func(t *testing.T) {
		_, err := BuildCAChain("", nil)
		if err == nil {
			t.Fatal("Expected error for empty PEM")
		}
	})
}

// Helper function to generate a test certificate
func generateTestCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: randomSerialNumber(t),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// Helper to generate random serial number
func randomSerialNumber(t *testing.T) *big.Int {
	t.Helper()
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(128), nil)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}
	return n
}
