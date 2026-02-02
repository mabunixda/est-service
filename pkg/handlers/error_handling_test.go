package handlers

import (
	"crypto/x509/pkix"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mabunixda/est-service/pkg/auth"
	"github.com/mabunixda/est-service/pkg/backend"
)

// TestSimpleEnrollHandler tests handler creation
func TestSimpleEnrollHandler(t *testing.T) {
	authMgr := auth.NewManager(&backend.Client{}, &auth.Config{
		UserpassEnabled:   true,
		UserpassMountPath: "userpass",
	}, slog.Default())

	config := &EnrollmentConfig{
		DefaultMount: "pki",
		MaxCSRSize:   10 * 1024 * 1024,
		DefaultPolicy: LabelPolicy{
			Type:  "role",
			Value: "est",
		},
	}

	handler := NewSimpleEnrollHandler(
		&backend.Client{},
		authMgr,
		config,
		slog.Default(),
		&mockTelemetry{},
	)

	if handler == nil {
		t.Fatal("Expected non-nil handler")
	}
}

// TestSimpleReenrollHandler tests handler creation
func TestSimpleReenrollHandler(t *testing.T) {
	authMgr := auth.NewManager(&backend.Client{}, &auth.Config{
		UserpassEnabled:   true,
		UserpassMountPath: "userpass",
	}, slog.Default())

	config := &EnrollmentConfig{
		DefaultMount: "pki",
		MaxCSRSize:   10 * 1024 * 1024,
		DefaultPolicy: LabelPolicy{
			Type:  "role",
			Value: "est",
		},
	}

	handler := NewSimpleReenrollHandler(
		&backend.Client{},
		authMgr,
		config,
		slog.Default(),
		&mockTelemetry{},
	)

	if handler == nil {
		t.Fatal("Expected non-nil handler")
	}
}

// TestEnrollmentHandler_InvalidMethod tests that only POST is allowed for enrollment
func TestEnrollmentHandler_InvalidMethod(t *testing.T) {
	authMgr := auth.NewManager(&backend.Client{}, &auth.Config{
		UserpassEnabled:   true,
		UserpassMountPath: "userpass",
	}, slog.Default())

	config := &EnrollmentConfig{
		DefaultMount: "pki",
		MaxCSRSize:   10 * 1024 * 1024,
		DefaultPolicy: LabelPolicy{
			Type:  "role",
			Value: "est",
		},
	}

	handler := NewSimpleEnrollHandler(
		&backend.Client{},
		authMgr,
		config,
		slog.Default(),
		&mockTelemetry{},
	)

	tests := []struct {
		method string
	}{
		{"GET"},
		{"PUT"},
		{"DELETE"},
		{"PATCH"},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/.well-known/est/simpleenroll", nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("Expected 405 for %s, got %d", tt.method, w.Code)
			}
		})
	}
}

// TestReenrollmentHandler_InvalidMethod tests that only POST is allowed for reenrollment
func TestReenrollmentHandler_InvalidMethod(t *testing.T) {
	authMgr := auth.NewManager(&backend.Client{}, &auth.Config{
		UserpassEnabled:   true,
		UserpassMountPath: "userpass",
	}, slog.Default())

	config := &EnrollmentConfig{
		DefaultMount: "pki",
		MaxCSRSize:   10 * 1024 * 1024,
		DefaultPolicy: LabelPolicy{
			Type:  "role",
			Value: "est",
		},
	}

	handler := NewSimpleReenrollHandler(
		&backend.Client{},
		authMgr,
		config,
		slog.Default(),
		&mockTelemetry{},
	)

	tests := []struct {
		method string
	}{
		{"GET"},
		{"PUT"},
		{"DELETE"},
		{"PATCH"},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/.well-known/est/simplereenroll", nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("Expected 405 for %s, got %d", tt.method, w.Code)
			}
		})
	}
}

// Helper function for consistent test subject
func testSubject() pkix.Name {
	return pkix.Name{
		CommonName:   "Test CA",
		Organization: []string{"Test Org"},
	}
}
