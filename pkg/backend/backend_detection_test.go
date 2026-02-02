package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openbao/openbao/api/v2"
)

// TestDetectBackendType_Vault tests detection of Vault backend
func TestDetectBackendType_Vault(t *testing.T) {
	// Create mock server that returns Vault version
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			health := api.HealthResponse{
				Initialized:   true,
				Sealed:        false,
				Standby:       false,
				Version:       "Vault v1.15.0",
				ClusterName:   "test-cluster",
				ClusterID:     "test-id",
				ServerTimeUTC: 1234567890,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(health)
		}
	}))
	defer server.Close()

	cfg := &Config{
		Address: server.URL,
		Type:    BackendTypeAuto,
	}

	detectedType, err := detectBackendType(context.Background(), cfg, slog.Default())
	if err != nil {
		t.Fatalf("detectBackendType failed: %v", err)
	}

	if detectedType != BackendTypeVault {
		t.Errorf("Expected BackendTypeVault, got %v", detectedType)
	}
}

// TestDetectBackendType_OpenBao tests detection of OpenBao backend
func TestDetectBackendType_OpenBao(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			health := api.HealthResponse{
				Initialized:   true,
				Sealed:        false,
				Version:       "OpenBao v2.0.0",
				ClusterName:   "openbao-cluster",
				ClusterID:     "openbao-id",
				ServerTimeUTC: 1234567890,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(health)
		}
	}))
	defer server.Close()

	cfg := &Config{
		Address: server.URL,
		Type:    BackendTypeAuto,
	}

	detectedType, err := detectBackendType(context.Background(), cfg, slog.Default())
	if err != nil {
		t.Fatalf("detectBackendType failed: %v", err)
	}

	if detectedType != BackendTypeOpenBao {
		t.Errorf("Expected BackendTypeOpenBao, got %v", detectedType)
	}
}

// TestDetectBackendType_Bao tests detection of Bao (alternative name)
func TestDetectBackendType_Bao(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			health := api.HealthResponse{
				Initialized:   true,
				Sealed:        false,
				Version:       "bao v1.0.0",
				ClusterName:   "bao-cluster",
				ClusterID:     "bao-id",
				ServerTimeUTC: 1234567890,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(health)
		}
	}))
	defer server.Close()

	cfg := &Config{
		Address: server.URL,
		Type:    BackendTypeAuto,
	}

	detectedType, err := detectBackendType(context.Background(), cfg, slog.Default())
	if err != nil {
		t.Fatalf("detectBackendType failed: %v", err)
	}

	if detectedType != BackendTypeOpenBao {
		t.Errorf("Expected BackendTypeOpenBao for 'bao', got %v", detectedType)
	}
}

// TestDetectBackendType_Unknown tests fallback for unknown version strings
func TestDetectBackendType_Unknown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			health := api.HealthResponse{
				Initialized:   true,
				Sealed:        false,
				Version:       "SomeUnknownBackend v1.0.0",
				ClusterName:   "unknown-cluster",
				ClusterID:     "unknown-id",
				ServerTimeUTC: 1234567890,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(health)
		}
	}))
	defer server.Close()

	cfg := &Config{
		Address: server.URL,
		Type:    BackendTypeAuto,
	}

	detectedType, err := detectBackendType(context.Background(), cfg, slog.Default())
	if err != nil {
		t.Fatalf("detectBackendType failed: %v", err)
	}

	// Should default to OpenBao
	if detectedType != BackendTypeOpenBao {
		t.Errorf("Expected default to BackendTypeOpenBao for unknown version, got %v", detectedType)
	}
}

// TestDetectBackendType_HealthError tests fallback when health check fails
func TestDetectBackendType_HealthError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			// Return error
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Server error"))
		}
	}))
	defer server.Close()

	cfg := &Config{
		Address: server.URL,
		Type:    BackendTypeAuto,
	}

	// Should not error, but default to OpenBao
	detectedType, err := detectBackendType(context.Background(), cfg, slog.Default())
	if err != nil {
		t.Fatalf("detectBackendType should not error on health failure, got: %v", err)
	}

	if detectedType != BackendTypeOpenBao {
		t.Errorf("Expected default to BackendTypeOpenBao on health error, got %v", detectedType)
	}
}

// TestDetectBackendType_CaseSensitivity tests case-insensitive detection
func TestDetectBackendType_CaseSensitivity(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected BackendType
	}{
		{"uppercase VAULT", "VAULT v1.15.0", BackendTypeVault},
		{"mixed case Vault", "Vault v1.15.0", BackendTypeVault},
		{"lowercase vault", "vault v1.15.0", BackendTypeVault},
		{"uppercase OPENBAO", "OPENBAO v2.0.0", BackendTypeOpenBao},
		{"mixed case OpenBao", "OpenBao v2.0.0", BackendTypeOpenBao},
		{"lowercase openbao", "openbao v2.0.0", BackendTypeOpenBao},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/sys/health" {
					health := api.HealthResponse{
						Initialized:   true,
						Sealed:        false,
						Version:       tt.version,
						ServerTimeUTC: 1234567890,
					}
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(health)
				}
			}))
			defer server.Close()

			cfg := &Config{
				Address: server.URL,
				Type:    BackendTypeAuto,
			}

			detectedType, err := detectBackendType(context.Background(), cfg, slog.Default())
			if err != nil {
				t.Fatalf("detectBackendType failed: %v", err)
			}

			if detectedType != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, detectedType)
			}
		})
	}
}

// TestBackend_VaultType tests explicit Vault backend creation
func TestBackend_VaultType(t *testing.T) {
	// Create a mock server that responds to health checks (required for initialization)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			health := api.HealthResponse{
				Initialized:   true,
				Sealed:        false,
				Version:       "Vault v1.15.0",
				ServerTimeUTC: 1234567890,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(health)
		}
	}))
	defer server.Close()

	cfg := &Config{
		Address: server.URL,
		Type:    BackendTypeVault,
		Token:   "test-token",
	}

	backend, err := NewBackend(context.Background(), cfg, slog.Default())
	if err != nil {
		t.Fatalf("NewBackend failed: %v", err)
	}

	if backend == nil {
		t.Fatal("Expected backend instance, got nil")
	}

	if backend.Type() != BackendTypeVault {
		t.Errorf("Expected BackendTypeVault, got %v", backend.Type())
	}
}

// TestBackend_OpenBaoType tests explicit OpenBao backend creation
func TestBackend_OpenBaoType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			health := api.HealthResponse{
				Initialized:   true,
				Sealed:        false,
				Version:       "OpenBao v2.0.0",
				ServerTimeUTC: 1234567890,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(health)
		}
	}))
	defer server.Close()

	cfg := &Config{
		Address: server.URL,
		Type:    BackendTypeOpenBao,
		Token:   "test-token",
	}

	backend, err := NewBackend(context.Background(), cfg, slog.Default())
	if err != nil {
		t.Fatalf("NewBackend failed: %v", err)
	}

	if backend == nil {
		t.Fatal("Expected backend instance, got nil")
	}

	if backend.Type() != BackendTypeOpenBao {
		t.Errorf("Expected BackendTypeOpenBao, got %v", backend.Type())
	}
}

// TestBackend_AutoDetection tests automatic backend type detection
func TestBackend_AutoDetection(t *testing.T) {
	healthCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			healthCalled = true
			health := api.HealthResponse{
				Initialized:   true,
				Sealed:        false,
				Version:       "Vault v1.15.0",
				ServerTimeUTC: 1234567890,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(health)
		}
	}))
	defer server.Close()

	cfg := &Config{
		Address: server.URL,
		Type:    BackendTypeAuto,
		Token:   "test-token",
	}

	backend, err := NewBackend(context.Background(), cfg, slog.Default())
	if err != nil {
		t.Fatalf("NewBackend failed: %v", err)
	}

	if backend == nil {
		t.Fatal("Expected backend instance, got nil")
	}

	if !healthCalled {
		t.Error("Expected health endpoint to be called for auto-detection")
	}

	if backend.Type() != BackendTypeVault {
		t.Errorf("Expected BackendTypeVault, got %v", backend.Type())
	}
}

// TestBackend_EmptyType tests that empty type defaults to auto-detection
func TestBackend_EmptyType(t *testing.T) {
	healthCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			healthCalled = true
			health := api.HealthResponse{
				Initialized:   true,
				Sealed:        false,
				Version:       "OpenBao v2.0.0",
				ServerTimeUTC: 1234567890,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(health)
		}
	}))
	defer server.Close()

	cfg := &Config{
		Address: server.URL,
		Type:    "", // Empty type should trigger auto-detection
		Token:   "test-token",
	}

	backend, err := NewBackend(context.Background(), cfg, slog.Default())
	if err != nil {
		t.Fatalf("NewBackend failed: %v", err)
	}

	if backend == nil {
		t.Fatal("Expected backend instance, got nil")
	}

	if !healthCalled {
		t.Error("Expected health endpoint to be called for empty type")
	}

	if backend.Type() != BackendTypeOpenBao {
		t.Errorf("Expected BackendTypeOpenBao, got %v", backend.Type())
	}
}

// TestBackend_InvalidType tests error handling for unsupported backend types
func TestBackend_InvalidType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Should not call any endpoints for invalid type")
	}))
	defer server.Close()

	cfg := &Config{
		Address: server.URL,
		Type:    BackendType("invalid"),
		Token:   "test-token",
	}

	backend, err := NewBackend(context.Background(), cfg, slog.Default())
	if err == nil {
		t.Fatal("Expected error for invalid backend type")
	}

	if backend != nil {
		t.Error("Expected nil backend for invalid type")
	}

	expectedError := "unsupported backend type"
	if err != nil && err.Error()[:len(expectedError)] != expectedError {
		t.Errorf("Expected error message to contain '%s', got: %v", expectedError, err)
	}
}

// TestBackend_NilLogger tests that nil logger doesn't cause panic
func TestBackend_NilLogger(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			health := api.HealthResponse{
				Initialized:   true,
				Sealed:        false,
				Version:       "Vault v1.15.0",
				ServerTimeUTC: 1234567890,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(health)
		}
	}))
	defer server.Close()

	cfg := &Config{
		Address: server.URL,
		Type:    BackendTypeAuto,
		Token:   "test-token",
	}

	// Should not panic with nil logger
	backend, err := NewBackend(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("NewBackend failed: %v", err)
	}

	if backend == nil {
		t.Fatal("Expected backend instance, got nil")
	}
}

// TestDetectBackendType_WithNamespace tests detection with Vault namespace
func TestDetectBackendType_WithNamespace(t *testing.T) {
	namespaceReceived := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			// Capture namespace header
			namespaceReceived = r.Header.Get("X-Vault-Namespace")

			health := api.HealthResponse{
				Initialized:   true,
				Sealed:        false,
				Version:       "Vault v1.15.0",
				ServerTimeUTC: 1234567890,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(health)
		}
	}))
	defer server.Close()

	cfg := &Config{
		Address:   server.URL,
		Type:      BackendTypeAuto,
		Namespace: "test-namespace",
	}

	detectedType, err := detectBackendType(context.Background(), cfg, slog.Default())
	if err != nil {
		t.Fatalf("detectBackendType failed: %v", err)
	}

	if detectedType != BackendTypeVault {
		t.Errorf("Expected BackendTypeVault, got %v", detectedType)
	}

	if namespaceReceived != "test-namespace" {
		t.Errorf("Expected namespace 'test-namespace', got '%s'", namespaceReceived)
	}
}

// TestDetectBackendType_ContextCancellation tests behavior when context is cancelled
func TestDetectBackendType_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Never respond - simulates slow server
		<-r.Context().Done()
	}))
	defer server.Close()

	cfg := &Config{
		Address: server.URL,
		Type:    BackendTypeAuto,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Should fallback to OpenBao on context cancellation
	detectedType, err := detectBackendType(ctx, cfg, slog.Default())
	if err != nil {
		t.Fatalf("detectBackendType should not error on context cancel, got: %v", err)
	}

	if detectedType != BackendTypeOpenBao {
		t.Errorf("Expected default to BackendTypeOpenBao on context cancel, got %v", detectedType)
	}
}

// TestDetectBackendType_InvalidJSON tests handling of malformed JSON response
func TestDetectBackendType_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("invalid json{"))
		}
	}))
	defer server.Close()

	cfg := &Config{
		Address: server.URL,
		Type:    BackendTypeAuto,
	}

	// Should fallback to OpenBao on parse error
	detectedType, err := detectBackendType(context.Background(), cfg, slog.Default())
	if err != nil {
		t.Fatalf("detectBackendType should not error on invalid JSON, got: %v", err)
	}

	if detectedType != BackendTypeOpenBao {
		t.Errorf("Expected default to BackendTypeOpenBao on invalid JSON, got %v", detectedType)
	}
}

// TestBackendTypeString tests BackendType string representation
func TestBackendTypeString(t *testing.T) {
	tests := []struct {
		backendType BackendType
		expected    string
	}{
		{BackendTypeVault, "vault"},
		{BackendTypeOpenBao, "openbao"},
		{BackendTypeAuto, "auto"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("BackendType_%s", tt.expected), func(t *testing.T) {
			if string(tt.backendType) != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, string(tt.backendType))
			}
		})
	}
}
