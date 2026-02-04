//go:build integration
// +build integration

package integration

import (
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mabunixda/est-service/pkg/handlers"
)

func TestBasicAuthEnrollment(t *testing.T) {
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

	t.Run("valid credentials", func(t *testing.T) {
		csr, _ := GenerateCSR(t, "test-device.example.com")

		// Create basic auth header
		username := "est-device"
		password := "device-secret-123"
		auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		authHeader := "Basic " + auth

		cert, err := env.EnrollCertificate(t, csr, authHeader)
		if err != nil {
			t.Fatalf("Enrollment failed: %v", err)
		}

		if cert == nil {
			t.Fatal("No certificate returned")
		}

		if cert.Subject.CommonName != "test-device.example.com" {
			t.Errorf("Wrong CN: got %s, want test-device.example.com", cert.Subject.CommonName)
		}
	})

	t.Run("invalid credentials", func(t *testing.T) {
		csr, _ := GenerateCSR(t, "test-device2.example.com")

		auth := base64.StdEncoding.EncodeToString([]byte("wrong:password"))
		authHeader := "Basic " + auth

		_, err := env.EnrollCertificate(t, csr, authHeader)
		if err == nil {
			t.Fatal("Expected enrollment to fail with invalid credentials")
		}
	})

	t.Run("missing credentials", func(t *testing.T) {
		csr, _ := GenerateCSR(t, "test-device3.example.com")

		_, err := env.EnrollCertificate(t, csr, "")
		if err == nil {
			t.Fatal("Expected enrollment to fail without credentials")
		}
	})
}

func TestCACertsRetrieval(t *testing.T) {
	env := Setup(t)
	defer env.Cleanup(t)

	config := &handlers.EnrollmentConfig{
		DefaultMount:  env.PKIMount,
		DefaultPolicy: handlers.LabelPolicy{Type: "role", Value: "default"},
		Labels:        make(map[string]handlers.LabelPolicy),
		MaxCSRSize:    32768,
	}

	env.StartServer(t, config)

	t.Run("unauthenticated access allowed", func(t *testing.T) {
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get(env.ServerURL + "/.well-known/est/cacerts")
		if err != nil {
			t.Fatalf("Failed to get CA certs: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("Expected 200, got %d: %s", resp.StatusCode, string(body))
		}

		contentType := resp.Header.Get("Content-Type")
		if !strings.HasPrefix(contentType, "application/pkcs7-mime") {
			t.Errorf("Wrong content type: got %s, want application/pkcs7-mime", contentType)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}

		if len(body) == 0 {
			t.Error("Empty CA certs response")
		}
	})
}
