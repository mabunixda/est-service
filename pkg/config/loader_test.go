package config

import (
	"os"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	// Save and clear environment variables that could interfere with tests
	savedVaultAddr := os.Getenv("VAULT_ADDR")
	savedVaultToken := os.Getenv("VAULT_TOKEN")
	savedBaoAddr := os.Getenv("BAO_ADDR")
	savedBaoToken := os.Getenv("BAO_TOKEN")
	savedOpenBaoAddr := os.Getenv("OPENBAO_ADDR")
	savedOpenBaoToken := os.Getenv("OPENBAO_TOKEN")

	// Clear environment variables for test isolation
	os.Unsetenv("VAULT_ADDR")
	os.Unsetenv("VAULT_TOKEN")
	os.Unsetenv("BAO_ADDR")
	os.Unsetenv("BAO_TOKEN")
	os.Unsetenv("OPENBAO_ADDR")
	os.Unsetenv("OPENBAO_TOKEN")

	// Restore environment variables after all tests
	t.Cleanup(func() {
		if savedVaultAddr != "" {
			os.Setenv("VAULT_ADDR", savedVaultAddr)
		}
		if savedVaultToken != "" {
			os.Setenv("VAULT_TOKEN", savedVaultToken)
		}
		if savedBaoAddr != "" {
			os.Setenv("BAO_ADDR", savedBaoAddr)
		}
		if savedBaoToken != "" {
			os.Setenv("BAO_TOKEN", savedBaoToken)
		}
		if savedOpenBaoAddr != "" {
			os.Setenv("OPENBAO_ADDR", savedOpenBaoAddr)
		}
		if savedOpenBaoToken != "" {
			os.Setenv("OPENBAO_TOKEN", savedOpenBaoToken)
		}
	})

	t.Run("loads valid config", func(t *testing.T) {
		configYAML := `
server:
  listen_address: "0.0.0.0:8443"
  read_timeout: 30s
  write_timeout: 30s
  rate_limit:
    enabled: true
    requests_per_second: 50
    burst: 100
  tls:
    cert_file: "/etc/est/server.crt"
    key_file: "/etc/est/server.key"

backend:
  address: "https://localhost:8200"
  token: "test-token"

est:
  default_mount: "pki"

observability:
  logging:
    level: "debug"
    format: "json"
    stdout: true
    file: ""
`
		tmpFile, err := os.CreateTemp("", "config-*.yaml")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.WriteString(configYAML); err != nil {
			t.Fatal(err)
		}
		tmpFile.Close()

		cfg, err := Load(tmpFile.Name())
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		if cfg.Server.ListenAddress != "0.0.0.0:8443" {
			t.Errorf("Expected listen address 0.0.0.0:8443, got %s", cfg.Server.ListenAddress)
		}

		if cfg.Server.ReadTimeout != 30*time.Second {
			t.Errorf("Expected read timeout 30s, got %v", cfg.Server.ReadTimeout)
		}

		if !cfg.Server.RateLimit.Enabled {
			t.Error("Expected rate limit to be enabled")
		}

		if cfg.Server.RateLimit.RequestsPerSecond != 50 {
			t.Errorf("Expected 50 req/s, got %d", cfg.Server.RateLimit.RequestsPerSecond)
		}

		if cfg.Backend.Address != "https://localhost:8200" {
			t.Errorf("Expected backend address https://localhost:8200, got %s", cfg.Backend.Address)
		}

		if cfg.Observability.Logging.Level != "debug" {
			t.Errorf("Expected log level debug, got %s", cfg.Observability.Logging.Level)
		}
		if cfg.Observability.Logging.Stdout == nil || !*cfg.Observability.Logging.Stdout {
			t.Error("Expected logging stdout to be true")
		}
	})

	t.Run("applies defaults", func(t *testing.T) {
		configYAML := `
developer_mode: true
backend:
  address: "https://localhost:8200"
  token: "test-token"
`
		tmpFile, err := os.CreateTemp("", "config-*.yaml")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.WriteString(configYAML); err != nil {
			t.Fatal(err)
		}
		tmpFile.Close()

		cfg, err := Load(tmpFile.Name())
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		// Check defaults
		if cfg.Server.ListenAddress != "0.0.0.0:8443" {
			t.Error("Default listen address not applied")
		}

		if cfg.Server.ReadTimeout != 15*time.Second {
			t.Error("Default read timeout not applied")
		}

		if cfg.Server.RateLimit.RequestsPerSecond != 100 {
			t.Error("Default rate limit not applied")
		}

		if cfg.Backend.Timeout != 30*time.Second {
			t.Error("Default backend timeout not applied")
		}

		if cfg.Observability.Logging.Level != "info" {
			t.Error("Default log level not applied")
		}

		if cfg.Observability.Logging.Format != "json" {
			t.Error("Default log format not applied")
		}
		if cfg.Observability.Logging.Stdout == nil || !*cfg.Observability.Logging.Stdout {
			t.Error("Default logging stdout not applied")
		}
		if cfg.Observability.Audit.Stdout == nil || !*cfg.Observability.Audit.Stdout {
			t.Error("Default audit stdout not applied")
		}
	})

	t.Run("validates required fields", func(t *testing.T) {
		configYAML := `
server:
  listen_address: "0.0.0.0:8443"
`
		tmpFile, err := os.CreateTemp("", "config-*.yaml")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.WriteString(configYAML); err != nil {
			t.Fatal(err)
		}
		tmpFile.Close()

		_, err = Load(tmpFile.Name())
		if err == nil {
			t.Error("Should fail without backend.address")
		}
	})

	t.Run("validates TLS requirement in production", func(t *testing.T) {
		configYAML := `
backend:
  address: "https://localhost:8200"
  token: "test-token"
`
		tmpFile, err := os.CreateTemp("", "config-*.yaml")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.WriteString(configYAML); err != nil {
			t.Fatal(err)
		}
		tmpFile.Close()

		_, err = Load(tmpFile.Name())
		if err == nil {
			t.Error("Should fail without TLS in production mode")
		}
	})

	t.Run("allows no TLS in developer mode", func(t *testing.T) {
		configYAML := `
developer_mode: true
backend:
  address: "https://localhost:8200"
  token: "test-token"
`
		tmpFile, err := os.CreateTemp("", "config-*.yaml")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.WriteString(configYAML); err != nil {
			t.Fatal(err)
		}
		tmpFile.Close()

		cfg, err := Load(tmpFile.Name())
		if err != nil {
			t.Errorf("Should allow no TLS in developer mode: %v", err)
		}

		if !cfg.DeveloperMode {
			t.Error("Developer mode should be enabled")
		}
	})

	t.Run("expands environment variables", func(t *testing.T) {
		os.Setenv("TEST_BACKEND_ADDRESS", "https://test-vault.example.com:8200")
		defer os.Unsetenv("TEST_BACKEND_ADDRESS")

		configYAML := `
backend:
  address: "${TEST_BACKEND_ADDRESS}"
  token: "test-token"
server:
  tls:
    cert_file: "/tmp/cert"
    key_file: "/tmp/key"
`
		tmpFile, err := os.CreateTemp("", "config-*.yaml")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.WriteString(configYAML); err != nil {
			t.Fatal(err)
		}
		tmpFile.Close()

		cfg, err := Load(tmpFile.Name())
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		if cfg.Backend.Address != "https://test-vault.example.com:8200" {
			t.Errorf("Expected expanded address, got %s", cfg.Backend.Address)
		}
	})

	t.Run("validates log level", func(t *testing.T) {
		configYAML := `
backend:
  address: "https://localhost:8200"
  token: "test-token"
server:
  tls:
    cert_file: "/tmp/cert"
    key_file: "/tmp/key"
observability:
  logging:
    level: "invalid"
`
		tmpFile, err := os.CreateTemp("", "config-*.yaml")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.WriteString(configYAML); err != nil {
			t.Fatal(err)
		}
		tmpFile.Close()

		_, err = Load(tmpFile.Name())
		if err == nil {
			t.Error("Should fail with invalid log level")
		}
	})

	t.Run("validates log format", func(t *testing.T) {
		configYAML := `
backend:
  address: "https://localhost:8200"
  token: "test-token"
server:
  tls:
    cert_file: "/tmp/cert"
    key_file: "/tmp/key"
observability:
  logging:
    format: "xml"
`
		tmpFile, err := os.CreateTemp("", "config-*.yaml")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.WriteString(configYAML); err != nil {
			t.Fatal(err)
		}
		tmpFile.Close()

		_, err = Load(tmpFile.Name())
		if err == nil {
			t.Error("Should fail with invalid log format")
		}
	})
}
