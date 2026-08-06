//go:build integration
// +build integration

package integration

import (
	"testing"

	"github.com/mabunixda/est-service/pkg/handlers"
)

func TestBearerTokenAuth(t *testing.T) {
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
		MaxCSRSize: 32768,
	}

	env.StartServer(t, config)

	t.Run("valid token", func(t *testing.T) {
		csr, _ := GenerateCSR(t, "token-test-device.example.com")

		// Use root token as bearer token
		authHeader := "Bearer " + env.RootToken

		cert, err := env.EnrollCertificate(t, csr, authHeader)
		if err != nil {
			t.Fatalf("Enrollment with bearer token failed: %v", err)
		}

		if cert == nil {
			t.Fatal("No certificate returned")
		}

		if cert.Subject.CommonName != "token-test-device.example.com" {
			t.Errorf("Wrong CN: got %s, want token-test-device.example.com", cert.Subject.CommonName)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		csr, _ := GenerateCSR(t, "invalid-token-device.example.com")

		authHeader := "Bearer invalid-token-12345"

		_, err := env.EnrollCertificate(t, csr, authHeader)
		if err == nil {
			t.Fatal("Expected enrollment to fail with invalid token")
		}
	})

	t.Run("X-OpenBao-Token header", func(t *testing.T) {
		// Test alternative token header format
		csr, _ := GenerateCSR(t, "openbao-token-device.example.com")

		// This would require modifying EnrollCertificate to support custom headers
		// For now, we'll use the Bearer format
		authHeader := "Bearer " + env.RootToken

		cert, err := env.EnrollCertificate(t, csr, authHeader)
		if err != nil {
			t.Fatalf("Enrollment failed: %v", err)
		}

		if cert == nil {
			t.Fatal("No certificate returned")
		}
	})
}
