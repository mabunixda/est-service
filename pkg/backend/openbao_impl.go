package backend

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/mabunixda/est-service/pkg/observability"
	"github.com/openbao/openbao/api/v2"
)

// openBaoBackend implements the Backend interface for OpenBao
type openBaoBackend struct {
	client               *api.Client
	logger               *slog.Logger
	tokenRenewalInterval time.Duration
}

// newOpenBaoBackend creates a new OpenBao backend implementation
func newOpenBaoBackend(ctx context.Context, cfg *Config, logger *slog.Logger) (Backend, error) {
	// Create the API client config
	apiConfig := api.DefaultConfig()
	apiConfig.Address = cfg.Address

	if cfg.TLSConfig != nil {
		if err := apiConfig.ConfigureTLS(cfg.TLSConfig); err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", err)
		}
	}

	// Create the API client
	client, err := api.NewClient(apiConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenBao client: %w", err)
	}

	// Set token if provided
	if cfg.Token != "" {
		client.SetToken(cfg.Token)
	}

	// Set namespace if provided
	if cfg.Namespace != "" {
		client.SetNamespace(cfg.Namespace)
	}

	// Set default token renewal interval if not configured
	renewalInterval := cfg.TokenRenewalInterval
	if renewalInterval == 0 {
		renewalInterval = 15 * time.Minute
	}

	b := &openBaoBackend{
		client:               client,
		logger:               logger,
		tokenRenewalInterval: renewalInterval,
	}

	// Verify connectivity
	health, err := b.Health(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to verify OpenBao connectivity: %w", err)
	}

	logger.Info("Connected to OpenBao",
		"address", cfg.Address,
		"sealed", health.Sealed,
		"version", health.Version)

	return b, nil
}

// Type returns the backend type
func (b *openBaoBackend) Type() BackendType {
	return BackendTypeOpenBao
}

// Health checks the health of the OpenBao server
func (b *openBaoBackend) Health(ctx context.Context) (*api.HealthResponse, error) {
	health, err := b.client.Sys().HealthWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check health: %w", err)
	}
	return health, nil
}

// GetAPIClient returns the underlying OpenBao API client
func (b *openBaoBackend) GetAPIClient() *api.Client {
	return b.client
}

// ========== PKI Operations ==========

// GetCACertificate retrieves the CA certificate from a PKI mount
func (b *openBaoBackend) GetCACertificate(ctx context.Context, mount string) (*x509.Certificate, error) {
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

	b.logger.Info("Retrieved CA certificate from OpenBao",
		"mount", mount,
		"subject", cert.Subject.String(),
		"request_id", observability.RequestIDFromContext(ctx))

	return cert, nil
}

// GetCAChain retrieves the full CA chain from a PKI mount
func (b *openBaoBackend) GetCAChain(ctx context.Context, mount string) ([]*x509.Certificate, error) {
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

	b.logger.Info("Retrieved CA chain from OpenBao",
		"mount", mount,
		"certificates", len(certs),
		"request_id", observability.RequestIDFromContext(ctx))

	return certs, nil
}

// SignCSR signs a certificate request using a PKI role
// ttl: optional certificate TTL (e.g., "24h", "720h"). If empty, uses role's default TTL.
func (b *openBaoBackend) SignCSR(ctx context.Context, mount, role string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
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

	b.logger.Info("Signed CSR with OpenBao",
		"mount", mount,
		"role", role,
		"subject", cert.Subject.String(),
		"serial", cert.SerialNumber.String(),
		"request_id", observability.RequestIDFromContext(ctx))

	return cert, nil
}

// SignCSRVerbatim signs a certificate request verbatim (without a role)
// ttl: optional certificate TTL (e.g., "24h", "720h"). If empty, uses default TTL.
func (b *openBaoBackend) SignCSRVerbatim(ctx context.Context, mount string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
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

	b.logger.Info("Signed CSR verbatim with OpenBao",
		"mount", mount,
		"subject", cert.Subject.String(),
		"serial", cert.SerialNumber.String(),
		"request_id", observability.RequestIDFromContext(ctx))

	return cert, nil
}

// GetIssuerPEM retrieves a specific issuer's certificate in PEM format
func (b *openBaoBackend) GetIssuerPEM(ctx context.Context, mount, issuer string) (string, error) {
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
func (b *openBaoBackend) AuthenticateUserpass(ctx context.Context, mount, username, password string) (string, error) {
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

	b.logger.Info("Userpass authentication successful on OpenBao",
		"username", username,
		"mount", mount,
		"request_id", observability.RequestIDFromContext(ctx))

	return secret.Auth.ClientToken, nil
}

// AuthenticateLDAP authenticates using the LDAP backend
func (b *openBaoBackend) AuthenticateLDAP(ctx context.Context, mount, username, password string) (string, error) {
	path := fmt.Sprintf("auth/%s/login/%s", mount, username)

	data := map[string]interface{}{
		"password": password,
	}

	secret, err := b.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return "", fmt.Errorf("LDAP authentication failed: %w", err)
	}

	if secret == nil || secret.Auth == nil {
		return "", fmt.Errorf("no auth info returned from LDAP")
	}

	b.logger.Info("LDAP authentication successful on OpenBao",
		"username", username,
		"mount", mount,
		"request_id", observability.RequestIDFromContext(ctx))

	return secret.Auth.ClientToken, nil
}

// AuthenticateAppRole authenticates using the AppRole backend
func (b *openBaoBackend) AuthenticateAppRole(ctx context.Context, mount, roleID, secretID string) (string, error) {
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

	b.logger.Info("AppRole authentication successful on OpenBao",
		"mount", mount,
		"request_id", observability.RequestIDFromContext(ctx))

	return secret.Auth.ClientToken, nil
}

// AuthenticateCert authenticates using the certificate backend
//
// IMPORTANT: OpenBao cert auth validates certificates during the TLS handshake.
// Since we're proxying authentication (client -> EST service -> OpenBao), we need to
// create a temporary OpenBao client configured with the client's certificate and key,
// then use that client to authenticate via cert auth.
//
// This requires the client certificate's private key to be available. For EST workflows,
// the EST service should have access to present the client cert to OpenBao.
func (b *openBaoBackend) AuthenticateCert(ctx context.Context, mount string, connState *tls.ConnectionState, role string) (string, error) {
	if connState == nil || len(connState.PeerCertificates) == 0 {
		return "", fmt.Errorf("no client certificate provided")
	}

	cert := connState.PeerCertificates[0]

	// For cert auth to work with OpenBao, we need to create a new client that presents
	// the certificate during the TLS handshake to OpenBao.
	// However, we don't have access to the client's private key here - it stays on the client.
	//
	// Solution: The EST service itself must be configured with its own client certificate
	// that OpenBao trusts. Then we use the client's certificate CN/Subject for metadata/logging only.
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

	b.logger.Info("Certificate authentication successful on OpenBao",
		"client_subject", cert.Subject.String(),
		"mount", mount,
		"role", role,
		"request_id", observability.RequestIDFromContext(ctx))

	return secret.Auth.ClientToken, nil
}

// createCertAuthClient creates a temporary API client configured with the client certificate
// This is necessary because Vault/OpenBao cert auth validates the certificate during TLS handshake
//
// NOTE: This function is currently unused and kept for future implementation reference.
// The challenge is that we don't have access to the client's private key in the ConnectionState,
// which is required for certificate-based authentication to the backend.
// For now, cert auth relies on the EST service's own client certificate configured in the backend.
//
//nolint:unused // Keeping for future implementation
func (b *openBaoBackend) createCertAuthClient(connState *tls.ConnectionState) (*api.Client, error) {
	if connState == nil || len(connState.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no client certificates available")
	}

	// Clone the existing client configuration
	tempClient, err := b.client.Clone()
	if err != nil {
		return nil, fmt.Errorf("failed to clone client: %w", err)
	}

	// Get the HTTP client and its transport
	httpClient := tempClient.CloneConfig().HttpClient
	transport, ok := httpClient.Transport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("unexpected transport type")
	}

	// Note: Would need to access transport.TLSClientConfig and clone it here for client cert setup,
	// but we don't have the private key available in ConnectionState.
	// The tlsConfig would need to be modified and set back to the transport.
	_ = transport // Silence unused warning

	// IMPORTANT: We need to reconstruct the tls.Certificate with both cert and private key
	// However, the ConnectionState only gives us the certificate, not the private key.
	// The private key was already used during the TLS handshake between client and EST service.
	//
	// For Vault cert auth to work, we need to send the SAME certificate in a NEW TLS
	// connection to Vault. But we don't have access to the private key here.
	//
	// SOLUTION: Vault cert auth actually works differently - it can accept the certificate
	// in PEM format in the request body, OR via TLS client cert. Since we don't have the
	// private key, we'll PEM-encode the cert and send it in the request body.

	// Actually, let me check if Vault supports sending cert in body...
	// After research: Vault cert auth requires TLS client certificate presentation,
	// it cannot be sent in the request body.
	//
	// The real issue: We cannot forward the client certificate to Vault because we don't
	// have the private key. The private key remains on the original client device.
	//
	// WORKAROUND: We need to store/cache the certificate data when it arrives, but this
	// is a fundamental architectural limitation.

	return nil, fmt.Errorf("certificate authentication forwarding not yet implemented: private key not available in ConnectionState")
}

// ValidateToken validates a token by attempting to look it up
func (b *openBaoBackend) ValidateToken(ctx context.Context, token string) (bool, error) {
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
func (b *openBaoBackend) LookupToken(ctx context.Context, token string) (map[string]interface{}, error) {
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
func (b *openBaoBackend) RenewToken(ctx context.Context) error {
	secret, err := b.client.Auth().Token().RenewSelfWithContext(ctx, 0)
	if err != nil {
		return fmt.Errorf("failed to renew token: %w", err)
	}

	if secret == nil {
		return fmt.Errorf("no secret returned from token renewal")
	}

	b.logger.Info("Token renewed on OpenBao",
		"lease_duration", secret.Auth.LeaseDuration,
		"renewable", secret.Auth.Renewable)

	return nil
}

// StartTokenRenewal starts a background goroutine that renews the token
func (b *openBaoBackend) StartTokenRenewal(ctx context.Context) {
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
func (b *openBaoBackend) CloneWithToken(ctx context.Context, token string) (Backend, error) {
	// Clone the API client
	clonedClient, err := b.client.Clone()
	if err != nil {
		return nil, fmt.Errorf("failed to clone OpenBao client: %w", err)
	}

	// Set the new token
	clonedClient.SetToken(token)

	// Create new backend with cloned client
	clonedBackend := &openBaoBackend{
		client: clonedClient,
		logger: b.logger,
	}

	b.logger.Debug("Cloned OpenBao backend with new token")

	return clonedBackend, nil
}

// Close cleans up resources and scrubs tokens from memory
// This is especially important for cloned clients with per-request tokens
// to minimize the window of token exposure in memory
func (b *openBaoBackend) Close() error {
	if b.client != nil {
		// Clear the token from memory
		b.client.SetToken("")
		// Set client to nil to prevent reuse
		b.client = nil
	}
	return nil
}
