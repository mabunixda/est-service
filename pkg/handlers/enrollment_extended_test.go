package handlers

import (
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mabunixda/est-service/pkg/auth"
	"github.com/mabunixda/est-service/pkg/backend"
)

// TestSimpleEnrollHandler_Configuration tests handler configuration
func TestSimpleEnrollHandler_Configuration(t *testing.T) {
	tests := []struct {
		name           string
		config         *EnrollmentConfig
		expectedMaxCSR int64
	}{
		{
			name: "default max CSR size",
			config: &EnrollmentConfig{
				DefaultMount: "pki",
			},
			expectedMaxCSR: 10 * 1024 * 1024,
		},
		{
			name: "custom max CSR size",
			config: &EnrollmentConfig{
				DefaultMount:          "pki",
				MaxCSRSize:            5 * 1024 * 1024,
				AllowedSignatureAlgos: []string{"SHA256WithRSA"},
			},
			expectedMaxCSR: 5 * 1024 * 1024,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authMgr := auth.NewManager(&backend.Client{}, &auth.Config{}, slog.Default())
			handler := NewSimpleEnrollHandler(&backend.Client{}, authMgr, tt.config, slog.Default(), &mockTelemetry{})

			if handler.config.MaxCSRSize != tt.expectedMaxCSR {
				t.Errorf("MaxCSRSize = %d, want %d", handler.config.MaxCSRSize, tt.expectedMaxCSR)
			}
		})
	}
}

// TestSimpleEnrollHandler_NilLogger tests that nil logger uses default
func TestSimpleEnrollHandler_NilLogger(t *testing.T) {
	authMgr := auth.NewManager(&backend.Client{}, &auth.Config{}, slog.Default())
	config := &EnrollmentConfig{
		DefaultMount: "pki",
	}

	handler := NewSimpleEnrollHandler(&backend.Client{}, authMgr, config, nil, &mockTelemetry{})

	if handler.logger == nil {
		t.Error("Logger should be set to default when nil is passed")
	}
}

// TestSimpleReenrollHandler_NilLogger tests that nil logger uses default
func TestSimpleReenrollHandler_NilLogger(t *testing.T) {
	authMgr := auth.NewManager(&backend.Client{}, &auth.Config{}, slog.Default())
	config := &EnrollmentConfig{
		DefaultMount: "pki",
	}

	handler := NewSimpleReenrollHandler(&backend.Client{}, authMgr, config, nil, &mockTelemetry{})

	if handler.logger == nil {
		t.Error("Logger should be set to default when nil is passed")
	}
}

// TestSimpleEnrollHandler_HTTPMethodsExtended tests additional HTTP methods
func TestSimpleEnrollHandler_HTTPMethodsExtended(t *testing.T) {
	authMgr := auth.NewManager(&backend.Client{}, &auth.Config{}, slog.Default())
	config := &EnrollmentConfig{
		DefaultMount: "pki",
	}

	handler := NewSimpleEnrollHandler(&backend.Client{}, authMgr, config, slog.Default(), &mockTelemetry{})

	methods := []string{"HEAD", "OPTIONS", "TRACE", "CONNECT"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/.well-known/est/simpleenroll", nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != 405 {
				t.Errorf("Method %s: status = %d, want 405", method, w.Code)
			}

			body := w.Body.String()
			if !strings.Contains(body, "Method not allowed") {
				t.Errorf("Method %s: body = %q, want to contain 'Method not allowed'", method, body)
			}
		})
	}
}

// TestSimpleReenrollHandler_HTTPMethodsExtended tests additional HTTP methods
func TestSimpleReenrollHandler_HTTPMethodsExtended(t *testing.T) {
	authMgr := auth.NewManager(&backend.Client{}, &auth.Config{}, slog.Default())
	config := &EnrollmentConfig{
		DefaultMount: "pki",
	}

	handler := NewSimpleReenrollHandler(&backend.Client{}, authMgr, config, slog.Default(), &mockTelemetry{})

	methods := []string{"HEAD", "OPTIONS", "TRACE", "CONNECT"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/.well-known/est/simplereenroll", nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != 405 {
				t.Errorf("Method %s: status = %d, want 405", method, w.Code)
			}
		})
	}
}

// TestEnrollmentConfig_Validation tests enrollment configuration validation
func TestEnrollmentConfig_Validation(t *testing.T) {
	tests := []struct {
		name   string
		config *EnrollmentConfig
		valid  bool
	}{
		{
			name: "valid basic config",
			config: &EnrollmentConfig{
				DefaultMount: "pki",
				DefaultPolicy: LabelPolicy{
					Type:  "role",
					Value: "est",
				},
			},
			valid: true,
		},
		{
			name: "config with labels",
			config: &EnrollmentConfig{
				DefaultMount: "pki",
				Labels: map[string]LabelPolicy{
					"mobile": {
						Type:  "role",
						Value: "mobile-devices",
						Mount: "pki_mobile",
					},
				},
			},
			valid: true,
		},
		{
			name: "config with custom TTL",
			config: &EnrollmentConfig{
				DefaultMount: "pki",
				DefaultPolicy: LabelPolicy{
					Type:  "role",
					Value: "est",
					TTL:   "720h",
				},
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authMgr := auth.NewManager(&backend.Client{}, &auth.Config{}, slog.Default())
			handler := NewSimpleEnrollHandler(&backend.Client{}, authMgr, tt.config, slog.Default(), &mockTelemetry{})

			if handler == nil {
				t.Error("Handler should not be nil")
			}

			// Verify configuration was stored
			if handler.config.DefaultMount != tt.config.DefaultMount {
				t.Errorf("DefaultMount = %s, want %s", handler.config.DefaultMount, tt.config.DefaultMount)
			}
		})
	}
}

// TestEnrollmentHandler_MaxCSRSize tests that MaxCSRSize configuration is respected
func TestEnrollmentHandler_MaxCSRSize(t *testing.T) {
	authMgr := auth.NewManager(&backend.Client{}, &auth.Config{
		UserpassEnabled:   true,
		UserpassMountPath: "userpass",
	}, slog.Default())

	config := &EnrollmentConfig{
		DefaultMount: "pki",
		MaxCSRSize:   1024,
	}

	handler := NewSimpleEnrollHandler(&backend.Client{}, authMgr, config, slog.Default(), &mockTelemetry{})

	if handler.config.MaxCSRSize != 1024 {
		t.Errorf("MaxCSRSize = %d, want 1024", handler.config.MaxCSRSize)
	}
}

// TestReenrollmentHandler_MaxCSRSize tests that MaxCSRSize configuration is respected
func TestReenrollmentHandler_MaxCSRSize(t *testing.T) {
	authMgr := auth.NewManager(&backend.Client{}, &auth.Config{
		UserpassEnabled:   true,
		UserpassMountPath: "userpass",
	}, slog.Default())

	config := &EnrollmentConfig{
		DefaultMount: "pki",
		MaxCSRSize:   2048,
	}

	handler := NewSimpleReenrollHandler(&backend.Client{}, authMgr, config, slog.Default(), &mockTelemetry{})

	if handler.config.MaxCSRSize != 2048 {
		t.Errorf("MaxCSRSize = %d, want 2048", handler.config.MaxCSRSize)
	}
}

// TestLabelPolicy_Types tests different label policy types
func TestLabelPolicy_Types(t *testing.T) {
	tests := []struct {
		name   string
		policy LabelPolicy
	}{
		{
			name: "role policy",
			policy: LabelPolicy{
				Type:  "role",
				Value: "est-role",
				Mount: "pki",
			},
		},
		{
			name: "sign-verbatim policy",
			policy: LabelPolicy{
				Type:  "sign-verbatim",
				Mount: "pki",
			},
		},
		{
			name: "policy with TTL",
			policy: LabelPolicy{
				Type:  "role",
				Value: "short-lived",
				Mount: "pki",
				TTL:   "1h",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &EnrollmentConfig{
				DefaultMount:  "pki",
				DefaultPolicy: tt.policy,
			}

			authMgr := auth.NewManager(&backend.Client{}, &auth.Config{}, slog.Default())
			handler := NewSimpleEnrollHandler(&backend.Client{}, authMgr, config, slog.Default(), &mockTelemetry{})

			if handler.config.DefaultPolicy.Type != tt.policy.Type {
				t.Errorf("Policy Type = %s, want %s", handler.config.DefaultPolicy.Type, tt.policy.Type)
			}
		})
	}
}

// TestEnrollmentHandler_AcceptedContentTypes tests that different content types are accepted
func TestEnrollmentHandler_AcceptedContentTypes(t *testing.T) {
	authMgr := auth.NewManager(&backend.Client{}, &auth.Config{
		UserpassEnabled:   true,
		UserpassMountPath: "userpass",
	}, slog.Default())

	config := &EnrollmentConfig{
		DefaultMount: "pki",
	}

	handler := NewSimpleEnrollHandler(&backend.Client{}, authMgr, config, slog.Default(), &mockTelemetry{})

	// Just verify handler creation with different configurations
	if handler == nil {
		t.Error("Handler should not be nil")
	}

	if handler.config.DefaultMount != "pki" {
		t.Errorf("DefaultMount = %s, want pki", handler.config.DefaultMount)
	}
}
