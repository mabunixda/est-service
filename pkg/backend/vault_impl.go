package backend

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/mabunixda/est-service/pkg/observability"
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

	// Set timeout if configured
	if cfg.Timeout > 0 {
		apiConfig.Timeout = cfg.Timeout
	}

	// Set retry configuration if provided
	if cfg.MaxRetries >= 0 {
		apiConfig.MaxRetries = cfg.MaxRetries
	}
	if cfg.MinRetryWait > 0 {
		apiConfig.MinRetryWait = cfg.MinRetryWait
	}
	if cfg.MaxRetryWait > 0 {
		apiConfig.MaxRetryWait = cfg.MaxRetryWait
	}

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

	// Authenticate to Vault
	// Priority: 1) Token (if provided), 2) Certificate auth (if TLS client cert configured)
	if cfg.Token != "" {
		// Use provided token
		client.SetToken(cfg.Token)
		logger.Debug("Using token authentication for backend")
	} else if cfg.TLSConfig != nil && cfg.TLSConfig.ClientCert != "" && cfg.TLSConfig.ClientKey != "" {
		// Use certificate authentication to obtain a token
		// The TLS client certificate is already configured in the client, so the cert auth
		// endpoint will validate it during the TLS handshake
		logger.Info("Authenticating to Vault using certificate authentication")

		// Call the cert auth login endpoint
		// Vault will validate our client certificate and return a token
		path := "auth/cert/login"
		secret, err := client.Logical().WriteWithContext(ctx, path, nil)
		if err != nil {
			return nil, fmt.Errorf("certificate authentication to Vault failed: %w", err)
		}

		if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
			return nil, fmt.Errorf("no token returned from certificate authentication")
		}

		client.SetToken(secret.Auth.ClientToken)
		logger.Info("Successfully authenticated to Vault using certificate",
			"token_policies", secret.Auth.Policies,
			"token_ttl", secret.Auth.LeaseDuration)
	} else {
		return nil, fmt.Errorf("no authentication method configured: provide token or client certificate")
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
		"subject", cert.Subject.String(),
		"request_id", observability.RequestIDFromContext(ctx))

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
		"certificates", len(certs),
		"request_id", observability.RequestIDFromContext(ctx))

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
		"serial", cert.SerialNumber.String(),
		"request_id", observability.RequestIDFromContext(ctx))

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
		"serial", cert.SerialNumber.String(),
		"request_id", observability.RequestIDFromContext(ctx))

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
		"mount", mount,
		"request_id", observability.RequestIDFromContext(ctx))

	return secret.Auth.ClientToken, nil
}

// AuthenticateLDAP authenticates using the LDAP backend
func (b *vaultBackend) AuthenticateLDAP(ctx context.Context, mount, username, password string) (string, error) {
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

	b.logger.Info("LDAP authentication successful on Vault",
		"username", username,
		"mount", mount,
		"request_id", observability.RequestIDFromContext(ctx))

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
		"mount", mount,
		"request_id", observability.RequestIDFromContext(ctx))

	return secret.Auth.ClientToken, nil
}

// AuthenticateCert authenticates a client certificate by creating a Vault entity and entity-bound token.
//
// IMPORTANT SECURITY FIX (Issue 1.1 - Certificate Auth Identity Collapse):
// Previous implementation: All clients authenticated with the EST service's certificate, resulting
// in identity collapse where all clients shared the same Vault identity.
//
// Fixed implementation: For each unique client certificate, we:
// 1. Extract a unique identifier (SHA256 fingerprint + CN)
// 2. Create or update a Vault entity representing this specific client
// 3. Create an entity alias to track the cert fingerprint
// 4. Generate a token bound to this entity
//
// This ensures each client has a unique Vault identity with separate audit trails and policies.
//
// Architectural Note: We cannot use Vault's cert auth method directly because we're proxying
// (client -> EST service -> Vault). The client's private key never leaves the client device,
// so we can't perform mTLS authentication to Vault with the client's cert. Instead, we use
// the EST service's privileged token to create entities representing each client.
func (b *vaultBackend) AuthenticateCert(ctx context.Context, mount string, connState *tls.ConnectionState, role, entityAliasPrefix, tokenTTL string) (string, error) {
	if connState == nil || len(connState.PeerCertificates) == 0 {
		return "", fmt.Errorf("no client certificate provided")
	}

	cert := connState.PeerCertificates[0]

	// Step 1: Generate unique identifiers for this client certificate
	// Use SHA256 fingerprint as the primary identifier
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))

	// Extract Common Name for entity naming
	cn := cert.Subject.CommonName
	if cn == "" {
		cn = "unknown"
	}

	// Create entity name and alias using standardized formats
	fingerprintPrefix := fingerprint[:FingerprintPrefixLength]
	entityName := FormatEntityName(entityAliasPrefix, cn, fingerprintPrefix)
	aliasName := FormatEntityAlias(fingerprint, cn)

	// Step 2: Create or update the entity with metadata about the certificate
	metadata := map[string]string{
		"cert_fingerprint": fingerprint,
		"cert_subject":     cert.Subject.String(),
		"cert_cn":          cn,
		"cert_serial":      cert.SerialNumber.String(),
		"cert_not_before":  cert.NotBefore.Format(time.RFC3339),
		"cert_not_after":   cert.NotAfter.Format(time.RFC3339),
		"source":           "est-service",
	}

	// Default policies for cert-authenticated entities
	// These can be overridden by Vault's entity policies or group memberships
	policies := []string{}
	if role != "" {
		// If a role is specified, add it as a policy hint
		policies = append(policies, role)
	}

	entityID, err := b.CreateOrUpdateEntity(ctx, entityName, metadata, policies)
	if err != nil {
		return "", fmt.Errorf("failed to create entity for client certificate: %w", err)
	}

	// Step 3: Create entity alias
	// We need the mount accessor for the token auth method to create the alias
	// For manually-created entities, we'll use the token auth mount accessor
	// First, get the token auth mount accessor
	authMounts, err := b.client.Sys().ListAuthWithContext(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to list auth mounts: %w", err)
	}

	var tokenMountAccessor string
	for path, mount := range authMounts {
		if mount.Type == "token" && path == "token/" {
			tokenMountAccessor = mount.Accessor
			break
		}
	}

	if tokenMountAccessor == "" {
		return "", fmt.Errorf("token auth mount accessor not found")
	}

	// Create or update the entity alias
	// Note: If the alias already exists, this will update it
	_, err = b.CreateOrUpdateEntityAlias(ctx, entityID, aliasName, tokenMountAccessor)
	if err != nil {
		// If alias creation fails (e.g., due to conflict), log but continue
		// The entity still exists and we can create a token for it
		b.logger.Warn("Failed to create entity alias, continuing with entity token creation",
			"error", err,
			"entity_id", entityID,
			"alias_name", aliasName)
	}

	// Step 4: Create a token bound to this entity
	// The token will inherit the entity's identity and policies
	// Use configurable TTL (default: 24h) which provides enough time for
	// certificate operations while limiting exposure
	token, err := b.CreateTokenForEntity(ctx, entityID, policies, tokenTTL)
	if err != nil {
		return "", fmt.Errorf("failed to create token for entity: %w", err)
	}

	b.logger.Info("Certificate authentication successful on Vault",
		"entity_id", entityID,
		"entity_name", entityName,
		"client_subject", cert.Subject.String(),
		"cert_fingerprint", fingerprint,
		"mount", mount,
		"role", role,
		"request_id", observability.RequestIDFromContext(ctx))

	return token, nil
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

// ========== Identity Management ==========

// CreateOrUpdateEntity creates or updates a Vault entity with the given name and metadata.
// This is used to create unique identities for certificate-authenticated clients.
// Returns the entity ID.
func (b *vaultBackend) CreateOrUpdateEntity(ctx context.Context, name string, metadata map[string]string, policies []string) (string, error) {
	// Try to create new entity first
	path := "identity/entity/name/" + name

	data := map[string]interface{}{
		"name":     name,
		"metadata": metadata,
	}

	if len(policies) > 0 {
		data["policies"] = policies
	}

	secret, err := b.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return "", fmt.Errorf("failed to create/update entity: %w", err)
	}

	// When updating an existing entity, Vault doesn't return data in the response
	// In this case, we need to read the entity back to get its ID
	var entityID string
	if secret != nil && secret.Data != nil {
		// Entity was created - ID is in the response
		id, ok := secret.Data["id"].(string)
		if !ok {
			return "", fmt.Errorf("entity ID not found in response")
		}
		entityID = id
	} else {
		// Entity was updated - need to read it back
		readSecret, err := b.client.Logical().ReadWithContext(ctx, path)
		if err != nil {
			return "", fmt.Errorf("failed to read entity after update: %w", err)
		}
		if readSecret == nil || readSecret.Data == nil {
			return "", fmt.Errorf("no entity data returned after update")
		}
		id, ok := readSecret.Data["id"].(string)
		if !ok {
			return "", fmt.Errorf("entity ID not found in read response")
		}
		entityID = id
	}

	b.logger.Info("Created/updated Vault entity",
		"entity_id", entityID,
		"entity_name", name,
		"request_id", observability.RequestIDFromContext(ctx))

	return entityID, nil
}

// CreateOrUpdateEntityAlias creates or updates an entity alias.
// The alias name should uniquely identify the client (e.g., cert:SHA256:<fingerprint>:CN=<cn>).
// For manually-created entities without an auth method, use the token auth mount accessor.
// Returns the alias ID.
func (b *vaultBackend) CreateOrUpdateEntityAlias(ctx context.Context, entityID, aliasName, mountAccessor string) (string, error) {
	path := "identity/entity-alias"

	data := map[string]interface{}{
		"name":           aliasName,
		"canonical_id":   entityID,
		"mount_accessor": mountAccessor,
	}

	secret, err := b.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return "", fmt.Errorf("failed to create/update entity alias: %w", err)
	}

	// When updating an existing alias, Vault may not return data in the response
	// We can still return successfully since the alias was created/updated
	var aliasID string
	if secret != nil && secret.Data != nil {
		// Alias was created - ID is in the response
		id, ok := secret.Data["id"].(string)
		if ok {
			aliasID = id
		} else {
			// If we can't get the ID but the write succeeded, that's okay
			// The alias was created/updated successfully
			aliasID = "<updated>"
		}
	} else {
		// Alias was updated successfully but no data returned
		// This is normal behavior for Vault when updating existing aliases
		aliasID = "<updated>"
	}

	b.logger.Info("Created/updated Vault entity alias",
		"alias_id", aliasID,
		"alias_name", aliasName,
		"entity_id", entityID,
		"request_id", observability.RequestIDFromContext(ctx))

	return aliasID, nil
}

// CreateTokenForEntity creates a new token bound to the specified entity.
// This ensures the token inherits the entity's identity and appears as that entity in audit logs.
// The entity_id is set in the token metadata to bind it to the entity.
func (b *vaultBackend) CreateTokenForEntity(ctx context.Context, entityID string, policies []string, ttl string) (string, error) {
	path := "auth/token/create"

	data := map[string]interface{}{
		"entity_id": entityID,
		"policies":  policies,
	}

	if ttl != "" {
		data["ttl"] = ttl
	}

	secret, err := b.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return "", fmt.Errorf("failed to create token for entity: %w", err)
	}

	if secret == nil || secret.Auth == nil {
		return "", fmt.Errorf("no auth token returned")
	}

	token := secret.Auth.ClientToken

	b.logger.Info("Created token for Vault entity",
		"entity_id", entityID,
		"policies", policies,
		"ttl", ttl,
		"request_id", observability.RequestIDFromContext(ctx))

	return token, nil
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
