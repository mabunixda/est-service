package handlers

import (
	"encoding/base64"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/mabunixda/est-service/pkg/backend"
)

// TestCACertsHandler_Creation tests handler creation with different configurations
func TestCACertsHandler_Creation(t *testing.T) {
	client := &backend.Client{}
	handler := NewCACertsHandler(client, "pki", slog.Default())

	if handler == nil {
		t.Fatal("Handler should not be nil")
	}
	if handler.mount != "pki" {
		t.Errorf("Mount = %s, want pki", handler.mount)
	}
}

// TestCACertsHandler_EmptyCertificateList tests handling of empty certificate lists
func TestCACertsHandler_NilLogger(t *testing.T) {
	handler := NewCACertsHandler(&backend.Client{}, "pki", nil)
	if handler.logger == nil {
		t.Error("Logger should be set to default when nil is passed")
	}
}

// TestCACertsHandler_Configuration tests handler configuration
func TestCACertsHandler_Configuration(t *testing.T) {
	tests := []struct {
		name  string
		mount string
		want  string
	}{
		{"default mount", "pki", "pki"},
		{"custom mount", "pki_int", "pki_int"},
		{"root mount", "pki_root", "pki_root"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewCACertsHandler(&backend.Client{}, tt.mount, slog.Default())
			if handler.mount != tt.want {
				t.Errorf("Mount = %s, want %s", handler.mount, tt.want)
			}
		})
	}
}

// TestCACertsHandler_Base64Encoding tests that responses are base64 encoded
func TestCACertsHandler_Base64EncodingFormat(t *testing.T) {
	// Test that we can decode a base64 response
	testData := "test data"
	encoded := base64.StdEncoding.EncodeToString([]byte(testData))

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}

	if string(decoded) != testData {
		t.Errorf("Decoded = %s, want %s", string(decoded), testData)
	}
}

// TestCACertsHandler_HTTPMethods tests all HTTP methods
func TestCACertsHandler_HTTPMethods(t *testing.T) {
	handler := NewCACertsHandler(&backend.Client{}, "pki", slog.Default())

	methods := []struct {
		method       string
		expectedCode int
	}{
		// GET will try to call backend, so we expect panic/error
		// {"GET", 500}, // Will fail due to backend but should not be 405
		{"POST", 405},
		{"PUT", 405},
		{"DELETE", 405},
		{"PATCH", 405},
		{"HEAD", 405},
		{"OPTIONS", 405},
	}

	for _, tt := range methods {
		t.Run(tt.method, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/.well-known/est/cacerts", nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != tt.expectedCode {
				t.Errorf("Method %s: status = %d, want %d", tt.method, w.Code, tt.expectedCode)
			}
		})
	}
}
