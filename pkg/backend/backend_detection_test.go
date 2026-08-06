package backend

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openbao/openbao/api/v2"
)

func newBackendTestServer(t *testing.T, version string) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/health" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		health := api.HealthResponse{
			Initialized:   true,
			Sealed:        false,
			Version:       version,
			ServerTimeUTC: 1234567890,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(health); err != nil {
			t.Fatalf("failed to encode health response: %v", err)
		}
	}))
}

func TestBackend_OpenBaoType(t *testing.T) {
	server := newBackendTestServer(t, "OpenBao v2.0.0")
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
		t.Fatal("expected backend instance, got nil")
	}

	if backend.Type() != BackendTypeOpenBao {
		t.Errorf("expected BackendTypeOpenBao, got %v", backend.Type())
	}
}

func TestBackend_EmptyTypeDefaultsToOpenBao(t *testing.T) {
	server := newBackendTestServer(t, "OpenBao v2.0.0")
	defer server.Close()

	cfg := &Config{
		Address: server.URL,
		Token:   "test-token",
	}

	backend, err := NewBackend(context.Background(), cfg, slog.Default())
	if err != nil {
		t.Fatalf("NewBackend failed: %v", err)
	}

	if backend.Type() != BackendTypeOpenBao {
		t.Errorf("expected BackendTypeOpenBao, got %v", backend.Type())
	}
}

func TestBackend_InvalidType(t *testing.T) {
	cfg := &Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
		Type:    BackendType("openbao"),
	}

	backend, err := NewBackend(context.Background(), cfg, slog.Default())
	if err == nil {
		t.Fatal("expected error for invalid backend type")
	}

	if backend != nil {
		t.Error("expected nil backend for invalid type")
	}
}

func TestBackend_NilLogger(t *testing.T) {
	server := newBackendTestServer(t, "OpenBao v2.0.0")
	defer server.Close()

	cfg := &Config{
		Address: server.URL,
		Token:   "test-token",
	}

	backend, err := NewBackend(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("NewBackend failed: %v", err)
	}

	if backend == nil {
		t.Fatal("expected backend instance, got nil")
	}
}

func TestBackendTypeString(t *testing.T) {
	if string(BackendTypeOpenBao) != "openbao" {
		t.Errorf("expected openbao, got %s", string(BackendTypeOpenBao))
	}
}
