package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	// Save and clear environment variables that could interfere with tests
	savedBaoAddr := os.Getenv("BAO_ADDR")
	savedBaoToken := os.Getenv("BAO_TOKEN")
	savedOpenBaoAddr := os.Getenv("OPENBAO_ADDR")
	savedOpenBaoToken := os.Getenv("OPENBAO_TOKEN")

	// Clear environment variables for test isolation
	os.Unsetenv("BAO_ADDR")
	os.Unsetenv("BAO_TOKEN")
	os.Unsetenv("OPENBAO_ADDR")
	os.Unsetenv("OPENBAO_TOKEN")

	// Restore environment variables after all tests
	t.Cleanup(func() {
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
		os.Setenv("TEST_BACKEND_ADDRESS", "https://test-openbao.example.com:8200")
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

		if cfg.Backend.Address != "https://test-openbao.example.com:8200" {
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

	t.Run("validates server_key_gen encryption requirement", func(t *testing.T) {
		configYAML := `
backend:
  address: "https://localhost:8200"
  token: "test-token"
server:
  tls:
    cert_file: "/tmp/cert"
    key_file: "/tmp/key"
est:
  server_key_gen:
    enabled: true
    encrypt_private_key: false
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
			t.Error("Should fail when server_key_gen is enabled without encrypt_private_key")
		}
		if err != nil && !contains(err.Error(), "encrypt_private_key") {
			t.Errorf("Expected error about encrypt_private_key, got: %v", err)
		}
	})

	t.Run("allows server_key_gen when encryption is enabled", func(t *testing.T) {
		configYAML := `
backend:
  address: "https://localhost:8200"
  token: "test-token"
server:
  tls:
    cert_file: "/tmp/cert"
    key_file: "/tmp/key"
est:
  server_key_gen:
    enabled: true
    encrypt_private_key: true
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
			t.Errorf("Should allow server_key_gen with encrypt_private_key enabled: %v", err)
		}

		if !cfg.EST.ServerKeyGen.Enabled {
			t.Error("Expected server_key_gen to be enabled")
		}
		if !cfg.EST.ServerKeyGen.EncryptPrivateKey {
			t.Error("Expected encrypt_private_key to be true")
		}
	})

	t.Run("validate various errors", func(t *testing.T) {
		tests := []struct {
			name        string
			yaml        string
			errContains string
		}{
			{
				name: "missing authentication",
				yaml: `
developer_mode: true
backend:
  address: "http://localhost:8200"
`,
				errContains: "backend authentication required",
			},
			{
				name: "cert authentication success",
				yaml: `
developer_mode: true
backend:
  address: "http://localhost:8200"
  client_cert: "cert.pem"
  client_key: "key.pem"
`,
				errContains: "",
			},
			{
				name: "negative max retries",
				yaml: `
developer_mode: true
backend:
  address: "http://localhost:8200"
  token: "t"
  max_retries: -1
`,
				errContains: "backend.max_retries must be >= 0",
			},
			{
				name: "negative min retry wait",
				yaml: `
developer_mode: true
backend:
  address: "http://localhost:8200"
  token: "t"
  min_retry_wait: -1s
`,
				errContains: "backend.min_retry_wait must be >= 0",
			},
			{
				name: "negative max retry wait",
				yaml: `
developer_mode: true
backend:
  address: "http://localhost:8200"
  token: "t"
  max_retry_wait: -1s
`,
				errContains: "backend.max_retry_wait must be >= 0",
			},
			{
				name: "min retry greater than max retry",
				yaml: `
developer_mode: true
backend:
  address: "http://localhost:8200"
  token: "t"
  min_retry_wait: 5s
  max_retry_wait: 1s
`,
				errContains: "cannot be greater than max_retry_wait",
			},
			{
				name: "negative timeout",
				yaml: `
developer_mode: true
backend:
  address: "http://localhost:8200"
  token: "t"
  timeout: -1s
`,
				errContains: "backend.timeout must be >= 0",
			},
			{
				name: "invalid backend type",
				yaml: `
developer_mode: true
backend:
  address: "http://localhost:8200"
  token: "t"
  type: "invalid"
`,
				errContains: "backend.type must be 'openbao'",
			},
			{
				name: "invalid label type",
				yaml: `
developer_mode: true
backend:
  address: "http://localhost:8200"
  token: "t"
est:
  labels:
    test:
      type: "invalid"
`,
				errContains: "type must be 'role' or 'sign-verbatim'",
			},
			{
				name: "missing label value",
				yaml: `
developer_mode: true
backend:
  address: "http://localhost:8200"
  token: "t"
est:
  labels:
    test:
      type: "role"
      value: ""
`,
				errContains: "value is required when type is 'role'",
			},
			{
				name: "max csr size too large",
				yaml: `
developer_mode: true
backend:
  address: "http://localhost:8200"
  token: "t"
est:
  csr_validation:
    max_size_bytes: 9999999
`,
				errContains: "csr_validation.max_size_bytes cannot exceed",
			},
			{
				name: "max csr size too small",
				yaml: `
developer_mode: true
backend:
  address: "http://localhost:8200"
  token: "t"
est:
  csr_validation:
    max_size_bytes: 10
`,
				errContains: "csr_validation.max_size_bytes must be at least",
			},
			{
				name: "weak algorithm",
				yaml: `
developer_mode: true
backend:
  address: "http://localhost:8200"
  token: "t"
est:
  csr_validation:
    allowed_signature_algorithms:
      - "MD5WithRSA"
`,
				errContains: "csr_validation.allowed_signature_algorithms contains weak algorithm",
			},
			{
				name: "logging outputs all false",
				yaml: `
developer_mode: true
backend:
  address: "http://localhost:8200"
  token: "t"
observability:
  logging:
    stdout: false
    file: ""
`,
				errContains: "logging requires at least one output",
			},
			{
				name: "audit outputs all false",
				yaml: `
developer_mode: true
backend:
  address: "http://localhost:8200"
  token: "t"
observability:
  audit:
    enabled: true
    stdout: false
    file: ""
`,
				errContains: "audit logging requires at least one output",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				tmpFile, err := os.CreateTemp("", "config-*.yaml")
				if err != nil {
					t.Fatal(err)
				}
				defer os.Remove(tmpFile.Name())
				tmpFile.WriteString(tc.yaml)
				tmpFile.Close()

				_, err = Load(tmpFile.Name())
				if tc.errContains != "" {
					if err == nil {
						t.Errorf("Expected error containing %q, got nil", tc.errContains)
					} else if !contains(err.Error(), tc.errContains) {
						t.Errorf("Expected error containing %q, got: %v", tc.errContains, err)
					}
				} else {
					if err != nil {
						t.Errorf("Expected no error, got: %v", err)
					}
				}
			})
		}
	})

	t.Run("token file reading", func(t *testing.T) {
		tmpTokenFile, err := os.CreateTemp("", "token-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpTokenFile.Name())
		tmpTokenFile.WriteString("file-token-123\n")
		tmpTokenFile.Close()

		configYAML := `
developer_mode: true
backend:
  address: "https://localhost:8200"
  token_file: "` + tmpTokenFile.Name() + `"
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
		if cfg.Backend.Token != "file-token-123" {
			t.Errorf("Expected token 'file-token-123', got '%s'", cfg.Backend.Token)
		}
	})

	t.Run("token file reading fails", func(t *testing.T) {
		configYAML := `
developer_mode: true
backend:
  address: "https://localhost:8200"
  token_file: "/non/existent/file"
`
		tmpFile, err := os.CreateTemp("", "config-*.yaml")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())
		tmpFile.WriteString(configYAML)
		tmpFile.Close()

		_, err = Load(tmpFile.Name())
		if err == nil {
			t.Error("Expected error when token file does not exist")
		} else if !contains(err.Error(), "failed to read token file") {
			t.Errorf("Expected error about token file, got: %v", err)
		}
	})

	t.Run("env fallback logic", func(t *testing.T) {
		os.Setenv("BAO_TOKEN", "env-token")
		defer os.Unsetenv("BAO_TOKEN")

		tmpTokenFile, err := os.CreateTemp("", "token-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpTokenFile.Name())
		tmpTokenFile.WriteString("file-token-123\n")
		tmpTokenFile.Close()

		configYAML := `
developer_mode: true
backend:
  address: "https://localhost:8200"
  token_file: "` + tmpTokenFile.Name() + `"
`
		tmpFile, err := os.CreateTemp("", "config-*.yaml")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())

		tmpFile.WriteString(configYAML)
		tmpFile.Close()

		cfg, err := Load(tmpFile.Name())
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}
		// Environment token should take precedence over file token
		if cfg.Backend.Token != "env-token" {
			t.Errorf("Expected token 'env-token', got '%s'", cfg.Backend.Token)
		}
	})

	t.Run("invalid YAML", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "config-*.yaml")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())
		tmpFile.WriteString("\tinvalid: yaml: :")
		tmpFile.Close()

		_, err = Load(tmpFile.Name())
		if err == nil {
			t.Error("Expected error with invalid YAML")
		} else if !contains(err.Error(), "failed to parse config") {
			t.Errorf("Expected parse error, got: %v", err)
		}
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := Load("/does/not/exist.yaml")
		if err == nil {
			t.Error("Expected error when config file does not exist")
		} else if !contains(err.Error(), "failed to read config file") {
			t.Errorf("Expected read error, got: %v", err)
		}
	})
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
