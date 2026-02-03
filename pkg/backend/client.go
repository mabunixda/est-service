package backend

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"

	"github.com/openbao/openbao/api/v2"
)

// Client is a facade wrapper around the Backend interface
// It provides backward compatibility while delegating to the underlying backend implementation
// This allows existing code to continue working without changes
type Client struct {
	backend Backend
}

// NewClient creates a new backend client with automatic type detection
// This maintains backward compatibility with existing code that expects *Client
func NewClient(ctx context.Context, cfg *Config, logger *slog.Logger) (*Client, error) {
	backend, err := NewBackend(ctx, cfg, logger)
	if err != nil {
		return nil, err
	}

	return &Client{
		backend: backend,
	}, nil
}

// NewClientWithBackend creates a new Client with a custom Backend implementation
// This is primarily used for testing to allow injecting mock backends
func NewClientWithBackend(backend Backend) *Client {
	return &Client{
		backend: backend,
	}
}

// Health checks the health of the backend server
func (c *Client) Health(ctx context.Context) (*api.HealthResponse, error) {
	return c.backend.Health(ctx)
}

// GetCACertificate retrieves the CA certificate from a PKI mount
func (c *Client) GetCACertificate(ctx context.Context, mount string) (*x509.Certificate, error) {
	return c.backend.GetCACertificate(ctx, mount)
}

// GetCAChain retrieves the full CA chain from a PKI mount
func (c *Client) GetCAChain(ctx context.Context, mount string) ([]*x509.Certificate, error) {
	return c.backend.GetCAChain(ctx, mount)
}

// SignCSR signs a certificate request using a PKI role
// ttl: optional certificate TTL (e.g., "24h", "720h"). If empty, uses role's default TTL.
func (c *Client) SignCSR(ctx context.Context, mount, role string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
	return c.backend.SignCSR(ctx, mount, role, csr, ttl)
}

// SignCSRVerbatim signs a certificate request verbatim (without a role)
// ttl: optional certificate TTL (e.g., "24h", "720h"). If empty, uses default TTL.
func (c *Client) SignCSRVerbatim(ctx context.Context, mount string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
	return c.backend.SignCSRVerbatim(ctx, mount, csr, ttl)
}

// GetIssuerPEM retrieves a specific issuer's certificate in PEM format
func (c *Client) GetIssuerPEM(ctx context.Context, mount, issuer string) (string, error) {
	return c.backend.GetIssuerPEM(ctx, mount, issuer)
}

// AuthenticateUserpass authenticates using the userpass backend
func (c *Client) AuthenticateUserpass(ctx context.Context, mount, username, password string) (string, error) {
	return c.backend.AuthenticateUserpass(ctx, mount, username, password)
}

// AuthenticateLDAP authenticates using the LDAP backend
func (c *Client) AuthenticateLDAP(ctx context.Context, mount, username, password string) (string, error) {
	return c.backend.AuthenticateLDAP(ctx, mount, username, password)
}

// AuthenticateAppRole authenticates using the AppRole backend
func (c *Client) AuthenticateAppRole(ctx context.Context, mount, roleID, secretID string) (string, error) {
	return c.backend.AuthenticateAppRole(ctx, mount, roleID, secretID)
}

// AuthenticateCert authenticates using the certificate backend
func (c *Client) AuthenticateCert(ctx context.Context, mount string, connState *tls.ConnectionState, role string) (string, error) {
	return c.backend.AuthenticateCert(ctx, mount, connState, role)
}

// ValidateToken validates a token by attempting to look it up
func (c *Client) ValidateToken(ctx context.Context, token string) (bool, error) {
	return c.backend.ValidateToken(ctx, token)
}

// LookupToken retrieves information about a token
func (c *Client) LookupToken(ctx context.Context, token string) (map[string]interface{}, error) {
	return c.backend.LookupToken(ctx, token)
}

// RenewToken renews the client's token
func (c *Client) RenewToken(ctx context.Context) error {
	return c.backend.RenewToken(ctx)
}

// StartTokenRenewal starts a background goroutine that renews the token
func (c *Client) StartTokenRenewal(ctx context.Context) {
	c.backend.StartTokenRenewal(ctx)
}

// GetAPIClient returns the underlying API client
func (c *Client) GetAPIClient() *api.Client {
	return c.backend.GetAPIClient()
}

// Type returns the backend type (vault or openbao)
func (c *Client) Type() BackendType {
	return c.backend.Type()
}

// GetBackend returns the underlying Backend implementation
// This allows direct access to the Backend interface if needed
func (c *Client) GetBackend() Backend {
	return c.backend
}

// CloneWithToken creates a new client with a different token
// This allows per-request token usage for proper Vault audit trails and policy enforcement
func (c *Client) CloneWithToken(ctx context.Context, token string) (Backend, error) {
	clonedBackend, err := c.backend.CloneWithToken(ctx, token)
	if err != nil {
		return nil, err
	}
	return &Client{backend: clonedBackend}, nil
}

// Close cleans up resources and scrubs tokens from memory
func (c *Client) Close() error {
	return c.backend.Close()
}
