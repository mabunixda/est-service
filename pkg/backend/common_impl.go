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

const backendName = "OpenBao"

// commonBackend contains the shared OpenBao backend implementation.
type commonBackend struct {
	client               *api.Client
	logger               *slog.Logger
	tokenRenewalInterval time.Duration
}

// newCommonBackend creates a new OpenBao backend implementation.
func newCommonBackend(ctx context.Context, cfg *Config, logger *slog.Logger) (*commonBackend, error) {
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
	client, err := api.NewClient(apiConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s client: %w", backendName, err)
	}

	// Authenticate to backend
	// Priority: 1) Token (if provided), 2) Certificate auth (if TLS client cert configured)
	if cfg.Token != "" {
		// Use provided token
		client.SetToken(cfg.Token)
		logger.Debug("Using token authentication for backend")
	} else if cfg.TLSConfig != nil && cfg.TLSConfig.ClientCert != "" && cfg.TLSConfig.ClientKey != "" {
		// Use certificate authentication to obtain a token
		// The TLS client certificate is already configured in the client, so the cert auth
		// endpoint will validate it during the TLS handshake
		logger.Info(fmt.Sprintf("Authenticating to %s using certificate authentication", backendName))

		// Call the cert auth login endpoint
		path := "auth/cert/login"
		secret, err := client.Logical().WriteWithContext(ctx, path, nil)
		if err != nil {
			return nil, fmt.Errorf("certificate authentication to %s failed: %w", backendName, err)
		}

		if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
			return nil, fmt.Errorf("no token returned from certificate authentication")
		}

		client.SetToken(secret.Auth.ClientToken)
		logger.Info(fmt.Sprintf("Successfully authenticated to %s using certificate", backendName),
			"token_policies", secret.Auth.Policies,
			"token_ttl", secret.Auth.LeaseDuration)
	} else {
		return nil, fmt.Errorf("no authentication method configured: provide token or client certificate")
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

	b := &commonBackend{
		client:               client,
		logger:               logger,
		tokenRenewalInterval: renewalInterval,
	}

	// Verify connectivity
	health, err := b.Health(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to verify %s connectivity: %w", backendName, err)
	}

	logger.Info(fmt.Sprintf("Connected to %s", backendName),
		"address", cfg.Address,
		"sealed", health.Sealed,
		"version", health.Version)

	return b, nil
}

// Health checks the health of the backend server
func (b *commonBackend) Health(ctx context.Context) (*api.HealthResponse, error) {
	health, err := b.client.Sys().HealthWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check health: %w", err)
	}
	return health, nil
}

// GetAPIClient returns the underlying API client
func (b *commonBackend) GetAPIClient() *api.Client {
	return b.client
}

// ========== PKI Operations ==========

// GetCACertificate retrieves the CA certificate from a PKI mount
func (b *commonBackend) GetCACertificate(ctx context.Context, mount string) (*x509.Certificate, error) {
	path := fmt.Sprintf("%s/cert/ca", mount)

	// PKI cert/ca endpoint returns JSON with certificate in PEM format
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

	b.logger.Info(fmt.Sprintf("Retrieved CA certificate from %s", backendName),
		"mount", mount,
		"subject", cert.Subject.String(),
		"request_id", observability.RequestIDFromContext(ctx))

	return cert, nil
}

// GetCAChain retrieves the full CA chain from a PKI mount
func (b *commonBackend) GetCAChain(ctx context.Context, mount string) ([]*x509.Certificate, error) {
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

	b.logger.Info(fmt.Sprintf("Retrieved CA chain from %s", backendName),
		"mount", mount,
		"certificates", len(certs),
		"request_id", observability.RequestIDFromContext(ctx))

	return certs, nil
}

// SignCSR signs a certificate request using a PKI role
// ttl: optional certificate TTL (e.g., "24h", "720h"). If empty, uses role's default TTL.
func (b *commonBackend) SignCSR(ctx context.Context, mount, role string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
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

	b.logger.Info(fmt.Sprintf("Signed CSR with %s", backendName),
		"mount", mount,
		"role", role,
		"subject", cert.Subject.String(),
		"serial", cert.SerialNumber.String(),
		"request_id", observability.RequestIDFromContext(ctx))

	return cert, nil
}

// SignCSRVerbatim signs a certificate request verbatim (without a role)
// ttl: optional certificate TTL (e.g., "24h", "720h"). If empty, uses default TTL.
func (b *commonBackend) SignCSRVerbatim(ctx context.Context, mount string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
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

	b.logger.Info(fmt.Sprintf("Signed CSR verbatim with %s", backendName),
		"mount", mount,
		"subject", cert.Subject.String(),
		"serial", cert.SerialNumber.String(),
		"request_id", observability.RequestIDFromContext(ctx))

	return cert, nil
}

// GetIssuerPEM retrieves a specific issuer's certificate in PEM format
func (b *commonBackend) GetIssuerPEM(ctx context.Context, mount, issuer string) (string, error) {
	path := fmt.Sprintf("%s/issuer/%s/pem", mount, issuer)

	// PKI issuer PEM endpoint returns raw PEM, not JSON
	rawResp, err := b.client.Logical().ReadRawWithContext(ctx, path)
	if err != nil {
		return "", fmt.Errorf("failed to read issuer: %w", err)
	}
	defer func() {
		if closeErr := rawResp.Body.Close(); closeErr != nil {
			b.logger.Warn("Failed to close response body", "error", closeErr)
		}
	}()

	if rawResp == nil {
		return "", fmt.Errorf("no issuer data returned")
	}

	certPEM, err := io.ReadAll(rawResp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read issuer PEM body: %w", err)
	}

	return string(certPEM), nil
}

// ========== Authentication Operations ==========

// AuthenticateUserpass authenticates using the userpass backend
func (b *commonBackend) AuthenticateUserpass(ctx context.Context, mount, username, password string) (string, error) {
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

	b.logger.Info(fmt.Sprintf("Userpass authentication successful on %s", backendName),
		"username", username,
		"mount", mount,
		"request_id", observability.RequestIDFromContext(ctx))

	return secret.Auth.ClientToken, nil
}

// AuthenticateLDAP authenticates using the LDAP backend
func (b *commonBackend) AuthenticateLDAP(ctx context.Context, mount, username, password string) (string, error) {
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

	b.logger.Info(fmt.Sprintf("LDAP authentication successful on %s", backendName),
		"username", username,
		"mount", mount,
		"request_id", observability.RequestIDFromContext(ctx))

	return secret.Auth.ClientToken, nil
}

// AuthenticateAppRole authenticates using the AppRole backend
func (b *commonBackend) AuthenticateAppRole(ctx context.Context, mount, roleID, secretID string) (string, error) {
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

	b.logger.Info(fmt.Sprintf("AppRole authentication successful on %s", backendName),
		"mount", mount,
		"request_id", observability.RequestIDFromContext(ctx))

	return secret.Auth.ClientToken, nil
}

// AuthenticateCert authenticates a client certificate by creating an entity and entity-bound token.
//
// IMPORTANT SECURITY FIX (Issue 1.1 - Certificate Auth Identity Collapse):
// Previous implementation: All clients authenticated with the EST service's certificate, resulting
// in identity collapse where all clients shared the same identity.
//
// Fixed implementation: For each unique client certificate, we:
// 1. Extract a unique identifier (SHA256 fingerprint + CN)
// 2. Create or update an entity representing this specific client
// 3. Create an entity alias to track the cert fingerprint
// 4. Generate a token bound to this entity
//
// This ensures each client has a unique identity with separate audit trails and policies.
//
// Architectural Note: We cannot use the cert auth method directly because we're proxying
// (client -> EST service -> backend). The client's private key never leaves the client device,
// so we can't perform mTLS authentication to the backend with the client's cert. Instead, we use
// the EST service's privileged token to create entities representing each client.
func (b *commonBackend) AuthenticateCert(ctx context.Context, mount string, connState *tls.ConnectionState, role, entityAliasPrefix, tokenTTL string) (string, error) {
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
	// These can be overridden by entity policies or group memberships
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

	b.logger.Info(fmt.Sprintf("Certificate authentication successful on %s", backendName),
		"entity_id", entityID,
		"entity_name", entityName,
		"client_subject", cert.Subject.String(),
		"cert_fingerprint", fingerprint,
		"mount", mount,
		"role", role,
		"request_id", observability.RequestIDFromContext(ctx))

	return token, nil
}

// ValidateToken validates a token by attempting to look it up.
//
// Deprecated: This method is redundant. Use LookupToken directly instead,
// which performs the same validation and also returns token metadata.
// ValidateToken will be removed in a future version.
func (b *commonBackend) ValidateToken(ctx context.Context, token string) (bool, error) {
	// Simply delegate to LookupToken - if it succeeds, the token is valid
	_, err := b.LookupToken(ctx, token)
	if err != nil {
		b.logger.Debug("Token validation failed", "error", err)
		return false, nil
	}

	b.logger.Debug("Token validation successful")
	return true, nil
}

// LookupToken retrieves information about a token
func (b *commonBackend) LookupToken(ctx context.Context, token string) (map[string]interface{}, error) {
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

// CreateOrUpdateEntity creates or updates an entity with the given name and metadata.
// This is used to create unique identities for certificate-authenticated clients.
// Returns the entity ID.
func (b *commonBackend) CreateOrUpdateEntity(ctx context.Context, name string, metadata map[string]string, policies []string) (string, error) {
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

	// When updating an existing entity, the backend doesn't return data in the response
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

	b.logger.Info(fmt.Sprintf("Created/updated %s entity", backendName),
		"entity_id", entityID,
		"entity_name", name,
		"request_id", observability.RequestIDFromContext(ctx))

	return entityID, nil
}

// CreateOrUpdateEntityAlias creates or updates an entity alias.
// The alias name should uniquely identify the client (e.g., cert:SHA256:<fingerprint>:CN=<cn>).
// For manually-created entities without an auth method, use the token auth mount accessor.
// Returns the alias ID.
func (b *commonBackend) CreateOrUpdateEntityAlias(ctx context.Context, entityID, aliasName, mountAccessor string) (string, error) {
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

	// When updating an existing alias, the backend may not return data in the response
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
		// This is normal behavior when updating existing aliases
		aliasID = "<updated>"
	}

	b.logger.Info(fmt.Sprintf("Created/updated %s entity alias", backendName),
		"alias_id", aliasID,
		"alias_name", aliasName,
		"entity_id", entityID,
		"request_id", observability.RequestIDFromContext(ctx))

	return aliasID, nil
}

// CreateTokenForEntity creates a new token bound to the specified entity.
// This ensures the token inherits the entity's identity and appears as that entity in audit logs.
// The entity_id is set in the token metadata to bind it to the entity.
func (b *commonBackend) CreateTokenForEntity(ctx context.Context, entityID string, policies []string, ttl string) (string, error) {
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

	b.logger.Info(fmt.Sprintf("Created token for %s entity", backendName),
		"entity_id", entityID,
		"policies", policies,
		"ttl", ttl,
		"request_id", observability.RequestIDFromContext(ctx))

	return token, nil
}

// ========== Token Management ==========

// RenewToken renews the client's token
func (b *commonBackend) RenewToken(ctx context.Context) error {
	secret, err := b.client.Auth().Token().RenewSelfWithContext(ctx, 0)
	if err != nil {
		return fmt.Errorf("failed to renew token: %w", err)
	}

	if secret == nil {
		return fmt.Errorf("no secret returned from token renewal")
	}

	b.logger.Info(fmt.Sprintf("Token renewed on %s", backendName),
		"lease_duration", secret.Auth.LeaseDuration,
		"renewable", secret.Auth.Renewable)

	return nil
}

// StartTokenRenewal starts a background goroutine that renews the token
func (b *commonBackend) StartTokenRenewal(ctx context.Context) {
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

// cloneWithToken creates a new commonBackend instance with a different token
// This is used by the wrapper implementations to create cloned backends
func (b *commonBackend) cloneWithToken(ctx context.Context, token string) (*commonBackend, error) {
	// Clone the API client
	clonedClient, err := b.client.Clone()
	if err != nil {
		return nil, fmt.Errorf("failed to clone client: %w", err)
	}

	// Set the new token
	clonedClient.SetToken(token)

	// Create new backend with cloned client
	clonedBackend := &commonBackend{
		client:               clonedClient,
		logger:               b.logger,
		tokenRenewalInterval: b.tokenRenewalInterval,
	}

	b.logger.Debug(fmt.Sprintf("Cloned %s backend with new token", backendName))

	return clonedBackend, nil
}

// Close cleans up resources and scrubs tokens from memory
// This is especially important for cloned clients with per-request tokens
// to minimize the window of token exposure in memory
func (b *commonBackend) Close() error {
	if b.client != nil {
		// Clear the token from memory
		b.client.SetToken("")
		// Set client to nil to prevent reuse
		b.client = nil
	}
	return nil
}

// GenerateExportableKey creates a temporary exportable key in the Transit engine,
// exports the private key, and then deletes the Transit key.
// This allows OpenBao to generate keys in a secure environment while still
// allowing the EST service to deliver them to clients.
func (b *commonBackend) GenerateExportableKey(ctx context.Context, transitMount, keyType string, keyBits int) (interface{}, interface{}, error) {
	requestID := observability.RequestIDFromContext(ctx)

	// Generate a unique temporary key name
	keyName := fmt.Sprintf("temp-keygen-%d", time.Now().UnixNano())

	b.logger.Debug("Generating exportable key in Transit engine",
		"request_id", requestID,
		"transit_mount", transitMount,
		"key_name", keyName,
		"key_type", keyType,
		"key_bits", keyBits)

	// Map keyType and keyBits to Transit engine type
	transitType, err := mapToTransitKeyType(keyType, keyBits)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid key type/size: %w", err)
	}

	// 1. Create temporary Transit key (exportable)
	keyPath := fmt.Sprintf("%s/keys/%s", transitMount, keyName)
	_, err = b.client.Logical().WriteWithContext(ctx, keyPath, map[string]interface{}{
		"type":       transitType,
		"exportable": true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create Transit key: %w", err)
	}

	// Ensure cleanup - delete the Transit key when done
	defer func() {
		deletePath := fmt.Sprintf("%s/keys/%s", transitMount, keyName)
		// First, configure the key to allow deletion
		configPath := fmt.Sprintf("%s/keys/%s/config", transitMount, keyName)
		_, _ = b.client.Logical().WriteWithContext(context.Background(), configPath, map[string]interface{}{
			"deletion_allowed": true,
		})
		// Then delete it
		_, delErr := b.client.Logical().DeleteWithContext(context.Background(), deletePath)
		if delErr != nil {
			b.logger.Warn("Failed to delete temporary Transit key",
				"request_id", requestID,
				"key_name", keyName,
				"error", delErr)
		} else {
			b.logger.Debug("Deleted temporary Transit key",
				"request_id", requestID,
				"key_name", keyName)
		}
	}()

	// 2. Export the private key
	// Use appropriate export endpoint based on key type:
	// - RSA keys: use encryption-key endpoint
	// - ECDSA keys: use signing-key endpoint (ECDSA is for signatures, not encryption)
	var exportPath string
	if keyType == "rsa" {
		exportPath = fmt.Sprintf("%s/export/encryption-key/%s/latest", transitMount, keyName)
	} else {
		// ECDSA/EC keys use signing-key endpoint
		exportPath = fmt.Sprintf("%s/export/signing-key/%s/latest", transitMount, keyName)
	}

	exportResp, err := b.client.Logical().ReadWithContext(ctx, exportPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to export Transit key: %w", err)
	}

	if exportResp == nil || exportResp.Data == nil {
		return nil, nil, fmt.Errorf("empty response from Transit export")
	}

	// Extract the exported key
	keysData, ok := exportResp.Data["keys"].(map[string]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("invalid keys data in Transit export response")
	}

	keyPEM, ok := keysData["1"].(string)
	if !ok {
		return nil, nil, fmt.Errorf("missing key version 1 in Transit export response")
	}

	b.logger.Debug("Successfully exported key from Transit",
		"request_id", requestID,
		"key_name", keyName)

	// 3. Parse the exported PEM key
	privateKey, publicKey, err := parseExportedKey(keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse exported key: %w", err)
	}

	b.logger.Info("Successfully generated exportable key via Transit",
		"request_id", requestID,
		"key_type", keyType,
		"key_bits", keyBits)

	return privateKey, publicKey, nil
}
