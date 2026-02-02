package backend

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/openbao/openbao/api/v2"
)

// vaultBackend implements the Backend interface for HashiCorp Vault
// Note: Currently uses the same OpenBao API client library as they are compatible
// In the future, this could be swapped to use hashicorp/vault/api if needed
type vaultBackend struct {
	client               *api.Client
	logger               *slog.Logger
	tokenRenewalInterval time.Duration
}

// newVaultBackend creates a new Vault backend implementation
func newVaultBackend(ctx context.Context, cfg *Config, logger *slog.Logger) (Backend, error) {
	// Create the API client config
	apiConfig := api.DefaultConfig()
	apiConfig.Address = cfg.Address

	if cfg.TLSConfig != nil {
		if err := apiConfig.ConfigureTLS(cfg.TLSConfig); err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", err)
		}
	}

	// Create the API client
	// Note: Using OpenBao client library which is API-compatible with Vault
	client, err := api.NewClient(apiConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Set token if provided
	if cfg.Token != "" {
		client.SetToken(cfg.Token)
	}

	// Set namespace if provided (Vault Enterprise feature)
	if cfg.Namespace != "" {
		client.SetNamespace(cfg.Namespace)
	}

	// Set default token renewal interval if not configured
	renewalInterval := cfg.TokenRenewalInterval
	if renewalInterval == 0 {
		renewalInterval = 15 * time.Minute
	}

	b := &vaultBackend{
		client:               client,
		logger:               logger,
		tokenRenewalInterval: renewalInterval,
	}

	// Verify connectivity
	health, err := b.Health(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to verify Vault connectivity: %w", err)
	}

	logger.Info("Connected to Vault",
		"address", cfg.Address,
		"sealed", health.Sealed,
		"version", health.Version)

	return b, nil
}

// Type returns the backend type
func (b *vaultBackend) Type() BackendType {
	return BackendTypeVault
}

// Health checks the health of the Vault server
func (b *vaultBackend) Health(ctx context.Context) (*api.HealthResponse, error) {
	health, err := b.client.Sys().HealthWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check health: %w", err)
	}
	return health, nil
}

// GetAPIClient returns the underlying Vault API client
func (b *vaultBackend) GetAPIClient() *api.Client {
	return b.client
}

// ========== PKI Operations ==========

// GetCACertificate retrieves the CA certificate from a PKI mount
func (b *vaultBackend) GetCACertificate(ctx context.Context, mount string) (*x509.Certificate, error) {
	path := fmt.Sprintf("%s/ca", mount)

	secret, err := b.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("no CA certificate data returned")
	}

	certPEM, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, fmt.Errorf("CA certificate not found in response")
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	b.logger.Info("Retrieved CA certificate from Vault",
		"mount", mount,
		"subject", cert.Subject.String())

	return cert, nil
}

// GetCAChain retrieves the full CA chain from a PKI mount
func (b *vaultBackend) GetCAChain(ctx context.Context, mount string) ([]*x509.Certificate, error) {
	path := fmt.Sprintf("%s/ca_chain", mount)

	// PKI ca_chain endpoint returns raw PEM, not JSON
	rawResp, err := b.client.Logical().ReadRawWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA chain: %w", err)
	}
	defer func() {
		if closeErr := rawResp.Body.Close(); closeErr != nil {
			b.logger.Warn("Failed to close response body", "error", closeErr)
		}
	}()

	chainPEM, err := io.ReadAll(rawResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if len(chainPEM) == 0 {
		return nil, fmt.Errorf("no CA chain data returned")
	}

	var certs []*x509.Certificate
	rest := chainPEM

	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate in chain: %w", err)
		}

		certs = append(certs, cert)
	}

	b.logger.Info("Retrieved CA chain from Vault",
		"mount", mount,
		"certificates", len(certs))

	return certs, nil
}

// SignCSR signs a certificate request using a PKI role
// ttl: optional certificate TTL (e.g., "24h", "720h"). If empty, uses role's default TTL.
func (b *vaultBackend) SignCSR(ctx context.Context, mount, role string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
	path := fmt.Sprintf("%s/sign/%s", mount, role)

	// Encode CSR to PEM
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	})

	data := map[string]interface{}{
		"csr": string(csrPEM),
	}

	// Add TTL if specified (otherwise backend uses role's default)
	if ttl != "" {
		data["ttl"] = ttl
	}

	secret, err := b.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign CSR: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("no certificate data returned")
	}

	certPEM, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, fmt.Errorf("certificate not found in response")
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	b.logger.Info("Signed CSR with Vault",
		"mount", mount,
		"role", role,
		"subject", cert.Subject.String(),
		"serial", cert.SerialNumber.String())

	return cert, nil
}

// SignCSRVerbatim signs a certificate request verbatim (without a role)
// ttl: optional certificate TTL (e.g., "24h", "720h"). If empty, uses default TTL.
func (b *vaultBackend) SignCSRVerbatim(ctx context.Context, mount string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
	path := fmt.Sprintf("%s/sign-verbatim", mount)

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	})

	data := map[string]interface{}{
		"csr": string(csrPEM),
	}

	// Add TTL if specified (otherwise backend uses default)
	if ttl != "" {
		data["ttl"] = ttl
	}

	secret, err := b.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign CSR verbatim: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("no certificate data returned")
	}

	certPEM, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, fmt.Errorf("certificate not found in response")
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	b.logger.Info("Signed CSR verbatim with Vault",
		"mount", mount,
		"subject", cert.Subject.String(),
		"serial", cert.SerialNumber.String())

	return cert, nil
}

// GetIssuerPEM retrieves a specific issuer's certificate in PEM format
func (b *vaultBackend) GetIssuerPEM(ctx context.Context, mount, issuer string) (string, error) {
	path := fmt.Sprintf("%s/issuer/%s/pem", mount, issuer)

	secret, err := b.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return "", fmt.Errorf("failed to read issuer: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("no issuer data returned")
	}

	certPEM, ok := secret.Data["certificate"].(string)
	if !ok {
		return "", fmt.Errorf("certificate not found in response")
	}

	return certPEM, nil
}

// ========== Authentication Operations ==========

// AuthenticateUserpass authenticates using the userpass backend
func (b *vaultBackend) AuthenticateUserpass(ctx context.Context, mount, username, password string) (string, error) {
	path := fmt.Sprintf("auth/%s/login/%s", mount, username)

	data := map[string]interface{}{
		"password": password,
	}

	secret, err := b.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return "", fmt.Errorf("authentication failed: %w", err)
	}

	if secret == nil || secret.Auth == nil {
		return "", fmt.Errorf("no auth token returned")
	}

	b.logger.Info("Userpass authentication successful on Vault",
		"username", username,
		"mount", mount)

	return secret.Auth.ClientToken, nil
}

// AuthenticateAppRole authenticates using the AppRole backend
func (b *vaultBackend) AuthenticateAppRole(ctx context.Context, mount, roleID, secretID string) (string, error) {
	path := fmt.Sprintf("auth/%s/login", mount)

	data := map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	}

	secret, err := b.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return "", fmt.Errorf("authentication failed: %w", err)
	}

	if secret == nil || secret.Auth == nil {
		return "", fmt.Errorf("no auth token returned")
	}

	b.logger.Info("AppRole authentication successful on Vault",
		"mount", mount)

	return secret.Auth.ClientToken, nil
}

// AuthenticateCert authenticates using the certificate backend
//
// IMPORTANT: Vault cert auth validates certificates during the TLS handshake.
// Since we're proxying authentication (client -> EST service -> Vault), we need to
// create a temporary Vault client configured with the client's certificate and key,
// then use that client to authenticate via cert auth.
//
// This requires the client certificate's private key to be available. For EST workflows,
// the EST service should have access to present the client cert to Vault.
func (b *vaultBackend) AuthenticateCert(ctx context.Context, mount string, connState *tls.ConnectionState, role string) (string, error) {
	if connState == nil || len(connState.PeerCertificates) == 0 {
		return "", fmt.Errorf("no client certificate provided")
	}

	cert := connState.PeerCertificates[0]

	// For cert auth to work with Vault, we need to create a new client that presents
	// the certificate during the TLS handshake to Vault.
	// However, we don't have access to the client's private key here - it stays on the client.
	//
	// Solution: The EST service itself must be configured with its own client certificate
	// that Vault trusts. Then we use the client's certificate CN/Subject for metadata/logging only.
	//
	// If backend.client_cert and backend.client_key are configured in the config,
	// the API client will already be using mTLS. We just need to call the login endpoint.

	path := fmt.Sprintf("auth/%s/login", mount)

	data := map[string]interface{}{}
	if role != "" {
		data["name"] = role
	}

	// Call cert auth login - the TLS handshake with the EST service's client cert
	// is what actually authenticates us
	secret, err := b.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return "", fmt.Errorf("authentication failed: %w", err)
	}

	if secret == nil || secret.Auth == nil {
		return "", fmt.Errorf("no auth token returned")
	}

	b.logger.Info("Certificate authentication successful on Vault",
		"client_subject", cert.Subject.String(),
		"mount", mount,
		"role", role)

	return secret.Auth.ClientToken, nil
}

// ValidateToken validates a token by attempting to look it up
func (b *vaultBackend) ValidateToken(ctx context.Context, token string) (bool, error) {
	// Create a new client with the token to validate
	tempClient, err := b.client.Clone()
	if err != nil {
		return false, fmt.Errorf("failed to clone client: %w", err)
	}

	tempClient.SetToken(token)

	secret, err := tempClient.Logical().ReadWithContext(ctx, "auth/token/lookup-self")
	if err != nil {
		b.logger.Debug("Token validation failed", "error", err)
		return false, nil
	}

	if secret == nil {
		return false, nil
	}

	b.logger.Debug("Token validation successful")
	return true, nil
}

// LookupToken retrieves information about a token
func (b *vaultBackend) LookupToken(ctx context.Context, token string) (map[string]interface{}, error) {
	tempClient, err := b.client.Clone()
	if err != nil {
		return nil, fmt.Errorf("failed to clone client: %w", err)
	}

	tempClient.SetToken(token)

	secret, err := tempClient.Logical().ReadWithContext(ctx, "auth/token/lookup-self")
	if err != nil {
		return nil, fmt.Errorf("failed to lookup token: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("no token data returned")
	}

	return secret.Data, nil
}

// ========== Token Management ==========

// RenewToken renews the client's token
func (b *vaultBackend) RenewToken(ctx context.Context) error {
	secret, err := b.client.Auth().Token().RenewSelfWithContext(ctx, 0)
	if err != nil {
		return fmt.Errorf("failed to renew token: %w", err)
	}

	if secret == nil {
		return fmt.Errorf("no secret returned from token renewal")
	}

	b.logger.Info("Token renewed on Vault",
		"lease_duration", secret.Auth.LeaseDuration,
		"renewable", secret.Auth.Renewable)

	return nil
}

// StartTokenRenewal starts a background goroutine that renews the token
func (b *vaultBackend) StartTokenRenewal(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(b.tokenRenewalInterval)
		defer ticker.Stop()

		b.logger.Info("Token renewal started", "interval", b.tokenRenewalInterval)

		for {
			select {
			case <-ctx.Done():
				b.logger.Info("Stopping token renewal")
				return
			case <-ticker.C:
				if err := b.RenewToken(ctx); err != nil {
					b.logger.Error("Failed to renew token", "error", err)
				}
			}
		}
	}()
}

// CloneWithToken creates a new backend instance with a different token
// This enables per-request token usage for proper Vault audit trails and policy enforcement
func (b *vaultBackend) CloneWithToken(ctx context.Context, token string) (Backend, error) {
	// Clone the API client
	clonedClient, err := b.client.Clone()
	if err != nil {
		return nil, fmt.Errorf("failed to clone Vault client: %w", err)
	}

	// Set the new token
	clonedClient.SetToken(token)

	// Create new backend with cloned client
	clonedBackend := &vaultBackend{
		client: clonedClient,
		logger: b.logger,
	}

	b.logger.Debug("Cloned Vault backend with new token")

	return clonedBackend, nil
}

// Close cleans up resources and scrubs tokens from memory
// This is especially important for cloned clients with per-request tokens
// to minimize the window of token exposure in memory
func (b *vaultBackend) Close() error {
	if b.client != nil {
		// Clear the token from memory
		b.client.SetToken("")
		// Set client to nil to prevent reuse
		b.client = nil
	}
	return nil
}
