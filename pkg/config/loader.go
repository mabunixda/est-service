package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultCSRMaxSizeBytes  = 64 * 1024  // 64 KB default
	absoluteMinCSRSizeBytes = 1024       // 1 KB minimum (realistic for smallest CSR)
	absoluteMaxCSRSizeBytes = 128 * 1024 // 128 KB maximum (prevent DoS)
)

var defaultAllowedSignatureAlgorithms = []string{
	"SHA256WithRSA",
	"SHA384WithRSA",
	"SHA512WithRSA",
	"ECDSAWithSHA256",
	"ECDSAWithSHA384",
	"ECDSAWithSHA512",
}

// getEnvWithFallback returns the first non-empty environment variable value
func getEnvWithFallback(keys ...string) string {
	for _, key := range keys {
		if val := os.Getenv(key); val != "" {
			return val
		}
	}
	return ""
}

// Load reads and parses the configuration file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Expand environment variables
	expanded := os.ExpandEnv(string(data))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Apply defaults
	if err := applyDefaults(&cfg); err != nil {
		return nil, err
	}

	// Validate
	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

func applyDefaults(cfg *Config) error {
	if cfg.Server.ListenAddress == "" {
		cfg.Server.ListenAddress = "0.0.0.0:8443"
	}
	if cfg.Server.ReadTimeout == 0 {
		cfg.Server.ReadTimeout = 15 * time.Second
	}
	if cfg.Server.WriteTimeout == 0 {
		cfg.Server.WriteTimeout = 15 * time.Second
	}
	if cfg.Server.IdleTimeout == 0 {
		cfg.Server.IdleTimeout = 60 * time.Second
	}
	if cfg.Server.InternalEndpointsAuth == nil {
		defaultAuth := !cfg.DeveloperMode
		cfg.Server.InternalEndpointsAuth = &defaultAuth
	}

	// Rate limiting defaults
	if cfg.Server.RateLimit.RequestsPerSecond == 0 {
		cfg.Server.RateLimit.RequestsPerSecond = 100
	}
	if cfg.Server.RateLimit.Burst == 0 {
		cfg.Server.RateLimit.Burst = 200
	}

	// Auth-specific rate limiting defaults (stricter to prevent brute force)
	// Only apply if auth rate limiting is explicitly configured or rate limiting is enabled
	if cfg.Server.RateLimit.Enabled {
		if cfg.Server.RateLimit.AuthRequestsPerSecond == 0 {
			// Default: 10 auth requests per second (stricter than general limit)
			cfg.Server.RateLimit.AuthRequestsPerSecond = 10
		}
		if cfg.Server.RateLimit.AuthBurst == 0 {
			// Default: burst of 5 (stricter than general burst)
			cfg.Server.RateLimit.AuthBurst = 5
		}
	}

	// Backend configuration - environment variables always override config values (12-factor app)
	// Support VAULT_ADDR, BAO_ADDR, or OPENBAO_ADDR (highest priority)
	if envAddr := getEnvWithFallback("BAO_ADDR", "VAULT_ADDR", "OPENBAO_ADDR"); envAddr != "" {
		cfg.Backend.Address = envAddr
	}
	// Support VAULT_TOKEN, BAO_TOKEN, or OPENBAO_TOKEN (highest priority)
	if envToken := getEnvWithFallback("BAO_TOKEN", "VAULT_TOKEN", "OPENBAO_TOKEN"); envToken != "" {
		cfg.Backend.Token = envToken
		cfg.Backend.TokenFile = "" // Clear token_file if env token is set
	}

	// Load token from file if token_file is set and token is not
	if cfg.Backend.TokenFile != "" && cfg.Backend.Token == "" {
		tokenBytes, err := os.ReadFile(cfg.Backend.TokenFile)
		if err != nil {
			return fmt.Errorf("failed to read token file: %w", err)
		}
		cfg.Backend.Token = strings.TrimSpace(string(tokenBytes))
	}

	if cfg.Backend.Timeout == 0 {
		cfg.Backend.Timeout = 30 * time.Second
	}

	// Certificate authentication defaults
	if cfg.EST.Authenticators.Cert.Enabled {
		if cfg.EST.Authenticators.Cert.EntityAliasPrefix == "" {
			cfg.EST.Authenticators.Cert.EntityAliasPrefix = "est-cert-"
		}
		if cfg.EST.Authenticators.Cert.TokenTTL == "" {
			cfg.EST.Authenticators.Cert.TokenTTL = "24h"
		}
	}

	if cfg.EST.CSRValidation.MaxSizeBytes == 0 {
		cfg.EST.CSRValidation.MaxSizeBytes = defaultCSRMaxSizeBytes
	}

	if len(cfg.EST.CSRValidation.AllowedSignatureAlgorithms) == 0 {
		cfg.EST.CSRValidation.AllowedSignatureAlgorithms = append([]string(nil), defaultAllowedSignatureAlgorithms...)
	}

	if cfg.Observability.Metrics.PrometheusPort == 0 && cfg.Observability.Metrics.Enabled {
		cfg.Observability.Metrics.PrometheusPort = 9090
	}
	if cfg.Observability.Logging.Level == "" {
		cfg.Observability.Logging.Level = "info"
	}
	if cfg.Observability.Logging.Format == "" {
		cfg.Observability.Logging.Format = "json"
	}
	if cfg.Observability.Logging.Stdout == nil {
		defaultStdout := true
		cfg.Observability.Logging.Stdout = &defaultStdout
	}
	if cfg.Observability.Audit.Stdout == nil {
		defaultStdout := true
		cfg.Observability.Audit.Stdout = &defaultStdout
	}

	return nil
}

func validate(cfg *Config) error {
	if cfg.Backend.Address == "" {
		return fmt.Errorf("backend.address is required")
	}
	// Allow token, token_file, or client cert auth - at least one must be configured
	hasTokenAuth := cfg.Backend.Token != "" || cfg.Backend.TokenFile != ""
	hasCertAuth := cfg.Backend.ClientCert != "" && cfg.Backend.ClientKey != ""
	if !hasTokenAuth && !hasCertAuth {
		return fmt.Errorf("backend authentication required: set token/token_file OR client_cert/client_key")
	}

	// Validate backend retry configuration
	if cfg.Backend.MaxRetries < 0 {
		return fmt.Errorf("backend.max_retries must be >= 0, got %d", cfg.Backend.MaxRetries)
	}
	if cfg.Backend.MinRetryWait < 0 {
		return fmt.Errorf("backend.min_retry_wait must be >= 0, got %v", cfg.Backend.MinRetryWait)
	}
	if cfg.Backend.MaxRetryWait < 0 {
		return fmt.Errorf("backend.max_retry_wait must be >= 0, got %v", cfg.Backend.MaxRetryWait)
	}
	if cfg.Backend.MinRetryWait > 0 && cfg.Backend.MaxRetryWait > 0 && cfg.Backend.MinRetryWait > cfg.Backend.MaxRetryWait {
		return fmt.Errorf("backend.min_retry_wait (%v) cannot be greater than max_retry_wait (%v)",
			cfg.Backend.MinRetryWait, cfg.Backend.MaxRetryWait)
	}
	if cfg.Backend.Timeout < 0 {
		return fmt.Errorf("backend.timeout must be >= 0, got %v", cfg.Backend.Timeout)
	}

	// Validate certificate authentication configuration
	if cfg.EST.Authenticators.Cert.Enabled {
		// Validate entity alias prefix is not empty
		if cfg.EST.Authenticators.Cert.EntityAliasPrefix == "" {
			return fmt.Errorf("est.authenticators.cert.entity_alias_prefix cannot be empty when cert auth is enabled")
		}
		// Validate token TTL format (should be parseable as Vault duration)
		if cfg.EST.Authenticators.Cert.TokenTTL == "" {
			return fmt.Errorf("est.authenticators.cert.token_ttl cannot be empty when cert auth is enabled")
		}
		// Try to parse as Go duration to ensure it's valid
		if _, err := time.ParseDuration(cfg.EST.Authenticators.Cert.TokenTTL); err != nil {
			// If it fails, check if it's a valid Vault duration format (e.g., "24h", "30d")
			// Vault accepts: s, m, h, d formats
			// For now, just check it's not empty and has reasonable format
			if len(cfg.EST.Authenticators.Cert.TokenTTL) < 2 {
				return fmt.Errorf("est.authenticators.cert.token_ttl must be a valid duration (e.g., '24h', '30d')")
			}
		}
	}

	// Enforce HTTPS by default - only allow HTTP in developer mode
	if !cfg.DeveloperMode {
		if cfg.Server.TLS.CertFile == "" || cfg.Server.TLS.KeyFile == "" {
			return fmt.Errorf("TLS must be enabled in production mode. Set tls.cert_file and tls.key_file, or use developer_mode: true only for local testing (NOT recommended for production)")
		}
	}

	validAuthTypes := map[string]bool{"none": true, "request": true, "require": true}
	if !validAuthTypes[cfg.Server.TLS.ClientAuthType] {
		cfg.Server.TLS.ClientAuthType = "none"
	}

	validLogLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLogLevels[cfg.Observability.Logging.Level] {
		return fmt.Errorf("invalid logging level: %s", cfg.Observability.Logging.Level)
	}

	validLogFormats := map[string]bool{"json": true, "text": true}
	if !validLogFormats[cfg.Observability.Logging.Format] {
		return fmt.Errorf("invalid logging format: %s", cfg.Observability.Logging.Format)
	}

	loggingStdout := true
	if cfg.Observability.Logging.Stdout != nil {
		loggingStdout = *cfg.Observability.Logging.Stdout
	}
	if !loggingStdout && cfg.Observability.Logging.File == "" {
		return fmt.Errorf("logging requires at least one output: set observability.logging.stdout=true or observability.logging.file")
	}

	auditStdout := true
	if cfg.Observability.Audit.Stdout != nil {
		auditStdout = *cfg.Observability.Audit.Stdout
	}
	if cfg.Observability.Audit.Enabled && !auditStdout && cfg.Observability.Audit.File == "" {
		return fmt.Errorf("audit logging requires at least one output: set observability.audit.stdout=true or observability.audit.file")
	}

	// Validate label policies
	for label, policy := range cfg.EST.Labels {
		if policy.Type != "role" && policy.Type != "sign-verbatim" {
			return fmt.Errorf("label %s: type must be 'role' or 'sign-verbatim'", label)
		}
		if policy.Type == "role" && policy.Value == "" {
			return fmt.Errorf("label %s: value is required when type is 'role'", label)
		}
	}

	// Validate CSR size limits - enforce absolute min/max for security
	if cfg.EST.CSRValidation.MaxSizeBytes > absoluteMaxCSRSizeBytes {
		return fmt.Errorf("csr_validation.max_size_bytes cannot exceed %d bytes (128KB), got %d",
			absoluteMaxCSRSizeBytes, cfg.EST.CSRValidation.MaxSizeBytes)
	}
	if cfg.EST.CSRValidation.MaxSizeBytes < absoluteMinCSRSizeBytes {
		return fmt.Errorf("csr_validation.max_size_bytes must be at least %d bytes (1KB), got %d",
			absoluteMinCSRSizeBytes, cfg.EST.CSRValidation.MaxSizeBytes)
	}

	for _, alg := range cfg.EST.CSRValidation.AllowedSignatureAlgorithms {
		if isWeakSignatureAlgorithmName(alg) {
			return fmt.Errorf("csr_validation.allowed_signature_algorithms contains weak algorithm: %s", alg)
		}
	}

	// Validate server-side key generation security
	if cfg.EST.ServerKeyGen.Enabled {
		if !cfg.EST.ServerKeyGen.EncryptPrivateKey {
			return fmt.Errorf("server_key_gen.enabled requires encrypt_private_key: true for security (private keys must be encrypted during transmission)")
		}
	}

	return nil
}

func isWeakSignatureAlgorithmName(name string) bool {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "MD5WITHRSA", "SHA1WITHRSA", "ECDSAWITHSHA1":
		return true
	default:
		return false
	}
}
