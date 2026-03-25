package backend

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"time"

	"github.com/openbao/openbao/api/v2"
)

// BackendType represents the supported backend type.
type BackendType string

const (
	BackendTypeOpenBao BackendType = "openbao"
)

// Backend defines the interface for PKI backend operations
// for the OpenBao PKI backend.
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
	AuthenticateLDAP(ctx context.Context, mount, username, password string) (string, error)
	AuthenticateAppRole(ctx context.Context, mount, roleID, secretID string) (string, error)
	AuthenticateCert(ctx context.Context, mount string, connState *tls.ConnectionState, role, entityAliasPrefix, tokenTTL string) (string, error)
	ValidateToken(ctx context.Context, token string) (bool, error)
	LookupToken(ctx context.Context, token string) (map[string]interface{}, error)

	// Token Management
	RenewToken(ctx context.Context) error
	StartTokenRenewal(ctx context.Context)

	// Identity Management
	// CreateOrUpdateEntity creates or updates an entity with the given name and metadata.
	// Returns the entity ID.
	CreateOrUpdateEntity(ctx context.Context, name string, metadata map[string]string, policies []string) (string, error)

	// CreateOrUpdateEntityAlias creates or updates an entity alias for the given entity.
	// The alias name should be unique and represent the client (e.g., cert fingerprint + CN).
	// mount_accessor identifies the auth method (use "token" for manual token-based entities).
	// Returns the alias ID.
	CreateOrUpdateEntityAlias(ctx context.Context, entityID, aliasName, mountAccessor string) (string, error)

	// CreateTokenForEntity creates a new token bound to the specified entity ID.
	// This ensures the token inherits the entity's identity and policies.
	CreateTokenForEntity(ctx context.Context, entityID string, policies []string, ttl string) (string, error)

	// Transit Operations (for server-side key generation)
	// GenerateExportableKey creates a temporary exportable key in the Transit engine,
	// exports the private key, and then deletes the Transit key.
	// This allows OpenBao to generate keys in a secure environment while
	// still allowing the EST service to deliver them to clients.
	// Supported keyTypes: "rsa", "ecdsa"
	// For RSA: keyBits should be 2048, 3072, or 4096
	// For ECDSA: keyBits should be 256, 384, or 521 (curve size)
	GenerateExportableKey(ctx context.Context, transitMount, keyType string, keyBits int) (privateKey interface{}, publicKey interface{}, err error)

	// Client Access
	GetAPIClient() *api.Client

	// Clone creates a new backend instance with a different token
	// This allows per-request token usage for proper OpenBao audit trails.
	CloneWithToken(ctx context.Context, token string) (Backend, error)

	// Close cleans up resources and scrubs tokens from memory.
	// This should be called when the backend client is no longer needed,
	// especially for cloned instances with per-request tokens.
	Close() error

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
	Timeout              time.Duration // HTTP client timeout (default: 60s)
	MaxRetries           int           // Maximum number of retries for 5xx errors (default: 2)
	MinRetryWait         time.Duration // Minimum wait time before retry (default: 1000ms)
	MaxRetryWait         time.Duration // Maximum wait time before retry (default: 1500ms)

	// Type is an optional legacy field. Only "openbao" is supported.
	Type BackendType
}

// NewBackend creates a new OpenBao backend implementation.
func NewBackend(ctx context.Context, cfg *Config, logger *slog.Logger) (Backend, error) {
	if logger == nil {
		logger = slog.Default()
	}

	if cfg == nil {
		return nil, fmt.Errorf("backend config is required")
	}

	if cfg.Type != "" && cfg.Type != BackendTypeOpenBao {
		return nil, fmt.Errorf("unsupported backend type: %s (only 'openbao' is supported)", cfg.Type)
	}

	return newOpenBaoBackend(ctx, cfg, logger)
}
