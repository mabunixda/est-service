package backend

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/openbao/openbao/api/v2"
)

// BackendType represents the type of backend (Vault or OpenBao)
type BackendType string

const (
	BackendTypeVault   BackendType = "vault"
	BackendTypeOpenBao BackendType = "openbao"
	BackendTypeAuto    BackendType = "auto"
)

// Backend defines the interface for PKI backend operations
// This interface abstracts both Vault and OpenBao implementations
type Backend interface {
	// Health checks the health of the backend server
	Health(ctx context.Context) (*api.HealthResponse, error)

	// PKI Operations
	GetCACertificate(ctx context.Context, mount string) (*x509.Certificate, error)
	GetCAChain(ctx context.Context, mount string) ([]*x509.Certificate, error)
	SignCSR(ctx context.Context, mount, role string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error)
	SignCSRVerbatim(ctx context.Context, mount string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error)
	GetIssuerPEM(ctx context.Context, mount, issuer string) (string, error)

	// Authentication Operations
	AuthenticateUserpass(ctx context.Context, mount, username, password string) (string, error)
	AuthenticateCert(ctx context.Context, mount string, connState *tls.ConnectionState, role string) (string, error)
	ValidateToken(ctx context.Context, token string) (bool, error)
	LookupToken(ctx context.Context, token string) (map[string]interface{}, error)

	// Token Management
	RenewToken(ctx context.Context) error
	StartTokenRenewal(ctx context.Context)

	// Client Access
	GetAPIClient() *api.Client

	// Clone creates a new backend instance with a different token
	// This allows per-request token usage for proper Vault audit trails
	CloneWithToken(ctx context.Context, token string) (Backend, error)

	// Metadata
	Type() BackendType
}

// Config holds the configuration for the backend client
type Config struct {
	Address              string
	Token                string
	Namespace            string
	CACert               string
	CAPath               string
	TLSConfig            *api.TLSConfig
	TokenRenewalInterval time.Duration // Token renewal interval (default: 15m)

	// Type specifies which backend to use (vault, openbao, auto)
	// If "auto", the type will be detected automatically
	Type BackendType
}

// NewBackend creates a new backend implementation with automatic type detection
// It detects whether the backend is Vault or OpenBao and returns the appropriate implementation
func NewBackend(ctx context.Context, cfg *Config, logger *slog.Logger) (Backend, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// Determine backend type
	backendType := cfg.Type
	if backendType == "" || backendType == BackendTypeAuto {
		detected, err := detectBackendType(ctx, cfg, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to detect backend type: %w", err)
		}
		backendType = detected
		logger.Info("Auto-detected backend type", "type", backendType)
	}

	// Create the appropriate implementation
	switch backendType {
	case BackendTypeVault:
		return newVaultBackend(ctx, cfg, logger)
	case BackendTypeOpenBao:
		return newOpenBaoBackend(ctx, cfg, logger)
	default:
		return nil, fmt.Errorf("unsupported backend type: %s (use 'vault', 'openbao', or 'auto')", backendType)
	}
}

// detectBackendType attempts to detect whether the backend is Vault or OpenBao
func detectBackendType(ctx context.Context, cfg *Config, logger *slog.Logger) (BackendType, error) {
	// Create a temporary API client for detection
	apiConfig := api.DefaultConfig()
	apiConfig.Address = cfg.Address

	if cfg.TLSConfig != nil {
		if err := apiConfig.ConfigureTLS(cfg.TLSConfig); err != nil {
			return "", fmt.Errorf("failed to configure TLS: %w", err)
		}
	}

	client, err := api.NewClient(apiConfig)
	if err != nil {
		return "", fmt.Errorf("failed to create API client: %w", err)
	}

	if cfg.Namespace != "" {
		client.SetNamespace(cfg.Namespace)
	}

	// Check health endpoint for version information
	health, err := client.Sys().HealthWithContext(ctx)
	if err != nil {
		logger.Warn("Failed to get health for detection, defaulting to OpenBao", "error", err)
		return BackendTypeOpenBao, nil
	}

	// Detect based on version string
	// Vault versions typically start with "Vault v1.x.x"
	// OpenBao versions typically start with "OpenBao v1.x.x" or similar
	version := strings.ToLower(health.Version)

	logger.Debug("Detected version string", "version", health.Version)

	if strings.Contains(version, "vault") {
		return BackendTypeVault, nil
	} else if strings.Contains(version, "openbao") || strings.Contains(version, "bao") {
		return BackendTypeOpenBao, nil
	}

	// Default to OpenBao if we can't determine
	// (since this project primarily targets OpenBao and it's Vault-compatible)
	logger.Warn("Could not definitively detect backend type from version, defaulting to OpenBao",
		"version", health.Version)
	return BackendTypeOpenBao, nil
}
