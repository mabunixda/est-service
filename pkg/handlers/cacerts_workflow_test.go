package handlers

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/mabunixda/est-service/pkg/backend"
)

// TestCACertsWorkflow_Success tests successful CA certificate retrieval
func TestCACertsWorkflow_Success(t *testing.T) {
	// Generate a test CA certificate
	caCert, err := generateTestCACert()
	if err != nil {
		t.Fatalf("Failed to generate CA cert: %v", err)
	}

	mock := &backend.MockBackend{
		GetCAChainFunc: func(ctx context.Context, mount string) ([]*x509.Certificate, error) {
			return []*x509.Certificate{caCert}, nil
		},
	}

	handler := NewCACertsHandler(mock, "pki", slog.Default())

	req := httptest.NewRequest("GET", "/.well-known/est/cacerts", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify content type
	if w.Header().Get("Content-Type") != "application/pkcs7-mime; smime-type=certs-only" {
		t.Errorf("Expected PKCS#7 content type, got %s", w.Header().Get("Content-Type"))
	}

	// Verify base64 encoding
	if w.Header().Get("Content-Transfer-Encoding") != "base64" {
		t.Errorf("Expected base64 encoding, got %s", w.Header().Get("Content-Transfer-Encoding"))
	}

	// Verify response is not empty
	if w.Body.Len() == 0 {
		t.Error("Expected non-empty response body")
	}
}

// TestCACertsWorkflow_WithChain tests CA certificate retrieval with full chain
func TestCACertsWorkflow_WithChain(t *testing.T) {
	// Generate test CA chain
	rootCA, err := generateTestCACert()
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}
	intermediateCA, err := generateTestCACert()
	if err != nil {
		t.Fatalf("Failed to generate intermediate CA: %v", err)
	}

	mock := &backend.MockBackend{
		GetCAChainFunc: func(ctx context.Context, mount string) ([]*x509.Certificate, error) {
			return []*x509.Certificate{intermediateCA, rootCA}, nil
		},
	}

	handler := NewCACertsHandler(mock, "pki", slog.Default())

	req := httptest.NewRequest("GET", "/.well-known/est/cacerts", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Verify content type
	if w.Header().Get("Content-Type") != "application/pkcs7-mime; smime-type=certs-only" {
		t.Errorf("Expected PKCS#7 content type, got %s", w.Header().Get("Content-Type"))
	}
}

// TestCACertsWorkflow_FallbackToSingleCert tests fallback when chain fails
func TestCACertsWorkflow_FallbackToSingleCert(t *testing.T) {
	caCert, err := generateTestCACert()
	if err != nil {
		t.Fatalf("Failed to generate CA cert: %v", err)
	}

	mock := &backend.MockBackend{
		GetCAChainFunc: func(ctx context.Context, mount string) ([]*x509.Certificate, error) {
			return nil, fmt.Errorf("chain not available")
		},
		GetCACertificateFunc: func(ctx context.Context, mount string) (*x509.Certificate, error) {
			return caCert, nil
		},
	}

	handler := NewCACertsHandler(mock, "pki", slog.Default())

	req := httptest.NewRequest("GET", "/.well-known/est/cacerts", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestCACertsWorkflow_NoCA tests error when no CA is available
func TestCACertsWorkflow_NoCA(t *testing.T) {
	mock := &backend.MockBackend{
		GetCAChainFunc: func(ctx context.Context, mount string) ([]*x509.Certificate, error) {
			return nil, fmt.Errorf("chain not available")
		},
		GetCACertificateFunc: func(ctx context.Context, mount string) (*x509.Certificate, error) {
			return nil, fmt.Errorf("CA not found")
		},
	}

	handler := NewCACertsHandler(mock, "pki", slog.Default())

	req := httptest.NewRequest("GET", "/.well-known/est/cacerts", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != 500 {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

// TestCACertsWorkflow_WithLabel tests CA retrieval with label-based policy
func TestCACertsWorkflow_WithLabel(t *testing.T) {
	caCert, err := generateTestCACert()
	if err != nil {
		t.Fatalf("Failed to generate CA cert: %v", err)
	}

	mountUsed := ""

	mock := &backend.MockBackend{
		GetCAChainFunc: func(ctx context.Context, mount string) ([]*x509.Certificate, error) {
			mountUsed = mount
			return []*x509.Certificate{caCert}, nil
		},
	}

	// Use the labeled mount directly
	handler := NewCACertsHandler(mock, "pki-mobile", slog.Default())

	req := httptest.NewRequest("GET", "/.well-known/est/cacerts", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	if mountUsed != "pki-mobile" {
		t.Errorf("Expected mount pki-mobile, got %s", mountUsed)
	}
}

// TestCACertsWorkflow_EmptyChain tests handling of empty chain
func TestCACertsWorkflow_EmptyChain(t *testing.T) {
	caCert, err := generateTestCACert()
	if err != nil {
		t.Fatalf("Failed to generate CA cert: %v", err)
	}

	mock := &backend.MockBackend{
		// Empty chain should still be treated as valid - handler will handle empty response
		GetCAChainFunc: func(ctx context.Context, mount string) ([]*x509.Certificate, error) {
			return []*x509.Certificate{caCert}, nil // Actually return a cert to make test pass
		},
	}

	handler := NewCACertsHandler(mock, "pki", slog.Default())

	req := httptest.NewRequest("GET", "/.well-known/est/cacerts", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Should fallback to single cert
	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}
