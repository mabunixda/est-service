//go:build integration
// +build integration

package integration

import (
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/mabunixda/est-service/pkg/handlers"
)

func TestCertificateAuthentication(t *testing.T) {
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

	tests := []struct {
		name       string
		wantErr    bool
		wantStatus int
	}{
		{
			name:       "no client certificate - should fail",
			wantErr:    true,
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{}

			// Try to enroll with this client
			csr, _ := GenerateCSR(t, "cert-auth-test.example.com")
			csrPEM := EncodeCSR(csr)
			csrB64 := base64.StdEncoding.EncodeToString(csrPEM)

			req, err := http.NewRequest("POST", env.ServerURL+"/.well-known/est/simpleenroll",
				strings.NewReader(csrB64))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/pkcs10")
			req.Header.Set("Content-Transfer-Encoding", "base64")

			resp, err := client.Do(req)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("Unexpected request error: %v", err)
				}
				return
			}

			defer resp.Body.Close()
			if resp.StatusCode != tt.wantStatus {
				body, _ := io.ReadAll(resp.Body)
				t.Errorf("Status = %d, want %d. Body: %s", resp.StatusCode, tt.wantStatus, string(body))
			}
		})
	}
}

func TestCertAuthWithTLS(t *testing.T) {
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

	// This test requires TLS setup on the test server
	// For now, skip - would need to configure httptest.NewTLSServer
	t.Skip("TLS client cert auth requires TLS test server setup")
}
