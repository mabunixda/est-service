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
		return nil, fmt.Errorf("failed to create OpenBao client: %w", err)
	}

	// Authenticate to OpenBao
	// Priority: 1) Token (if provided), 2) Certificate auth (if TLS client cert configured)
	if cfg.Token != "" {
		// Use provided token
		client.SetToken(cfg.Token)
		logger.Debug("Using token authentication for backend")
	} else if cfg.TLSConfig != nil && cfg.TLSConfig.ClientCert != "" && cfg.TLSConfig.ClientKey != "" {
		// Use certificate authentication to obtain a token
		// The TLS client certificate is already configured in the client, so the cert auth
		// endpoint will validate it during the TLS handshake
		logger.Info("Authenticating to OpenBao using certificate authentication")

		// Call the cert auth login endpoint
		// OpenBao will validate our client certificate and return a token
		path := "auth/cert/login"
		secret, err := client.Logical().WriteWithContext(ctx, path, nil)
		if err != nil {
			return nil, fmt.Errorf("certificate authentication to OpenBao failed: %w", err)
		}

		if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
			return nil, fmt.Errorf("no token returned from certificate authentication")
		}

		client.SetToken(secret.Auth.ClientToken)
		logger.Info("Successfully authenticated to OpenBao using certificate",
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

// AuthenticateCert authenticates a client certificate by creating an OpenBao entity and entity-bound token.
//
// IMPORTANT SECURITY FIX (Issue 1.1 - Certificate Auth Identity Collapse):
// Previous implementation: All clients authenticated with the EST service's certificate, resulting
// in identity collapse where all clients shared the same OpenBao identity.
//
// Fixed implementation: For each unique client certificate, we:
// 1. Extract a unique identifier (SHA256 fingerprint + CN)
// 2. Create or update an OpenBao entity representing this specific client
// 3. Create an entity alias to track the cert fingerprint
// 4. Generate a token bound to this entity
//
// This ensures each client has a unique OpenBao identity with separate audit trails and policies.
//
// Architectural Note: We cannot use OpenBao's cert auth method directly because we're proxying
// (client -> EST service -> OpenBao). The client's private key never leaves the client device,
// so we can't perform mTLS authentication to OpenBao with the client's cert. Instead, we use
// the EST service's privileged token to create entities representing each client.
func (b *openBaoBackend) AuthenticateCert(ctx context.Context, mount string, connState *tls.ConnectionState, role, entityAliasPrefix, tokenTTL string) (string, error) {
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
	// These can be overridden by OpenBao's entity policies or group memberships
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

	b.logger.Info("Certificate authentication successful on OpenBao",
		"entity_id", entityID,
		"entity_name", entityName,
		"client_subject", cert.Subject.String(),
		"cert_fingerprint", fingerprint,
		"mount", mount,
		"role", role,
		"request_id", observability.RequestIDFromContext(ctx))

	return token, nil
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

// ========== Identity Management ==========

// CreateOrUpdateEntity creates or updates an OpenBao entity with the given name and metadata.
// This is used to create unique identities for certificate-authenticated clients.
// Returns the entity ID.
func (b *openBaoBackend) CreateOrUpdateEntity(ctx context.Context, name string, metadata map[string]string, policies []string) (string, error) {
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

	// When updating an existing entity, OpenBao doesn't return data in the response
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

	b.logger.Info("Created/updated OpenBao entity",
		"entity_id", entityID,
		"entity_name", name,
		"request_id", observability.RequestIDFromContext(ctx))

	return entityID, nil
}

// CreateOrUpdateEntityAlias creates or updates an entity alias.
// The alias name should uniquely identify the client (e.g., cert:SHA256:<fingerprint>:CN=<cn>).
// For manually-created entities without an auth method, use the token auth mount accessor.
// Returns the alias ID.
func (b *openBaoBackend) CreateOrUpdateEntityAlias(ctx context.Context, entityID, aliasName, mountAccessor string) (string, error) {
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

	// When updating an existing alias, OpenBao may not return data in the response
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
		// This is normal behavior for OpenBao when updating existing aliases
		aliasID = "<updated>"
	}

	b.logger.Info("Created/updated OpenBao entity alias",
		"alias_id", aliasID,
		"alias_name", aliasName,
		"entity_id", entityID,
		"request_id", observability.RequestIDFromContext(ctx))

	return aliasID, nil
}

// CreateTokenForEntity creates a new token bound to the specified entity.
// This ensures the token inherits the entity's identity and appears as that entity in audit logs.
// The entity_id is set in the token metadata to bind it to the entity.
func (b *openBaoBackend) CreateTokenForEntity(ctx context.Context, entityID string, policies []string, ttl string) (string, error) {
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

	b.logger.Info("Created token for OpenBao entity",
		"entity_id", entityID,
		"policies", policies,
		"ttl", ttl,
		"request_id", observability.RequestIDFromContext(ctx))

	return token, nil
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

// GenerateExportableKey creates a temporary exportable key in the Transit engine,
// exports the private key, and then deletes the Transit key.
// This allows OpenBao to generate keys in a secure environment while still
// allowing the EST service to deliver them to clients.
func (b *openBaoBackend) GenerateExportableKey(ctx context.Context, transitMount, keyType string, keyBits int) (interface{}, interface{}, error) {
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
	exportPath := fmt.Sprintf("%s/export/encryption-key/%s/latest", transitMount, keyName)
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
