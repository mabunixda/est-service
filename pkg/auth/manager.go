package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/mabunixda/est-service/pkg/backend"
)

// Manager handles multiple authentication methods for EST
type Manager struct {
	backend backend.Backend
	config  *Config
	logger  *slog.Logger
}

// Config holds authentication configuration
type Config struct {
	// Userpass authentication
	UserpassEnabled   bool
	UserpassMountPath string

	// LDAP authentication
	LDAPEnabled   bool
	LDAPMountPath string

	// AppRole authentication
	AppRoleEnabled   bool
	AppRoleMountPath string

	// Certificate authentication
	CertEnabled   bool
	CertMountPath string
	CertRole      string

	// Token authentication (Bearer)
	TokenEnabled bool
}

// Result holds authentication result information
type Result struct {
	Authenticated bool
	Token         string
	Method        string
	Identity      string
	Error         error
}

// NewManager creates a new authentication manager
func NewManager(backend backend.Backend, config *Config, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}

	if config.UserpassMountPath == "" {
		config.UserpassMountPath = "userpass"
	}
	if config.LDAPMountPath == "" {
		config.LDAPMountPath = "ldap"
	}
	if config.CertMountPath == "" {
		config.CertMountPath = "cert"
	}
	if config.AppRoleMountPath == "" {
		config.AppRoleMountPath = "approle"
	}

	return &Manager{
		backend: backend,
		config:  config,
		logger:  logger,
	}
}

// Authenticate tries multiple authentication methods in order:
// 1. Bearer Token (if present)
// 2. TLS Client Certificate (if present)
// 3. HTTP Basic Auth (if present)
func (m *Manager) Authenticate(ctx context.Context, r *http.Request) *Result {
	// Try Bearer Token first
	if m.config.TokenEnabled {
		if result := m.authenticateToken(ctx, r); result.Authenticated {
			return result
		}
	}

	// Try TLS Client Certificate
	if m.config.CertEnabled {
		if result := m.authenticateCert(ctx, r); result.Authenticated {
			return result
		}
	}

	// Try HTTP Basic Auth
	if m.config.UserpassEnabled || m.config.LDAPEnabled || m.config.AppRoleEnabled {
		if result := m.authenticateBasic(ctx, r); result.Authenticated {
			return result
		}
	}

	return &Result{
		Authenticated: false,
		Error:         fmt.Errorf("no valid authentication method found"),
	}
}

// authenticateToken validates a Bearer token
func (m *Manager) authenticateToken(ctx context.Context, r *http.Request) *Result {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return &Result{Authenticated: false}
	}

	// Check for Bearer token
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return &Result{Authenticated: false}
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return &Result{Authenticated: false}
	}

	// Validate token with backend
	valid, err := m.backend.ValidateToken(ctx, token)
	if err != nil {
		m.logger.Debug("Token validation failed", "error", err)
		return &Result{
			Authenticated: false,
			Error:         err,
		}
	}

	if !valid {
		return &Result{
			Authenticated: false,
			Error:         fmt.Errorf("invalid token"),
		}
	}

	// Get token information for identity
	tokenInfo, err := m.backend.LookupToken(ctx, token)
	if err != nil {
		m.logger.Debug("Token lookup failed", "error", err)
	}

	identity := "unknown"
	if tokenInfo != nil {
		if displayName, ok := tokenInfo["display_name"].(string); ok {
			identity = displayName
		}
	}

	m.logger.Info("Token authentication successful")

	return &Result{
		Authenticated: true,
		Token:         token,
		Method:        "token",
		Identity:      identity,
	}
}

// authenticateCert validates a TLS client certificate
func (m *Manager) authenticateCert(ctx context.Context, r *http.Request) *Result {
	if r.TLS == nil {
		m.logger.Debug("No TLS connection state available for certificate authentication")
		return &Result{Authenticated: false}
	}

	if len(r.TLS.PeerCertificates) == 0 {
		m.logger.Debug("No client certificates presented in TLS connection")
		return &Result{Authenticated: false}
	}

	clientCert := r.TLS.PeerCertificates[0]
	m.logger.Debug("Client certificate found in TLS connection")

	// Authenticate with backend
	token, err := m.backend.AuthenticateCert(ctx, m.config.CertMountPath, r.TLS, m.config.CertRole)
	if err != nil {
		m.logger.Debug("Certificate authentication failed",
			"error", err)
		return &Result{
			Authenticated: false,
			Error:         err,
		}
	}

	identity := clientCert.Subject.CommonName
	m.logger.Info("Certificate authentication successful")

	return &Result{
		Authenticated: true,
		Token:         token,
		Method:        "cert",
		Identity:      identity,
	}
}

// authenticateBasic validates HTTP Basic Auth credentials
func (m *Manager) authenticateBasic(ctx context.Context, r *http.Request) *Result {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return &Result{Authenticated: false}
	}

	// Check for Basic auth
	if !strings.HasPrefix(authHeader, "Basic ") {
		return &Result{Authenticated: false}
	}

	// Decode credentials
	encoded := strings.TrimPrefix(authHeader, "Basic ")
	decoded, decodeErr := base64.StdEncoding.DecodeString(encoded)
	if decodeErr != nil {
		m.logger.Debug("Failed to decode basic auth", "error", decodeErr)
		return &Result{
			Authenticated: false,
			Error:         decodeErr,
		}
	}

	// Split username:password
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return &Result{
			Authenticated: false,
			Error:         fmt.Errorf("invalid basic auth format"),
		}
	}

	username, password := parts[0], parts[1]

	var (
		token         string
		err           error
		userpassError error
		ldapError     error
		appRoleError  error
		triedUserpass bool
		triedLDAP     bool
		triedAppRole  bool
	)

	// Authenticate with backend IMMEDIATELY
	// We want to minimize the time the password stays in memory
	if m.config.UserpassEnabled {
		triedUserpass = true
		token, err = m.backend.AuthenticateUserpass(ctx, m.config.UserpassMountPath, username, password)
		if err == nil {
			m.logger.Info("Userpass authentication successful")
			return &Result{
				Authenticated: true,
				Token:         token,
				Method:        "userpass",
				Identity:      username,
			}
		}
		userpassError = err
	}

	// Try LDAP if userpass failed
	if m.config.LDAPEnabled {
		triedLDAP = true
		token, err = m.backend.AuthenticateLDAP(ctx, m.config.LDAPMountPath, username, password)
		if err == nil {
			m.logger.Info("LDAP authentication successful")
			return &Result{
				Authenticated: true,
				Token:         token,
				Method:        "ldap",
				Identity:      username,
			}
		}
		ldapError = err
	}

	if m.config.AppRoleEnabled {
		triedAppRole = true
		token, err = m.backend.AuthenticateAppRole(ctx, m.config.AppRoleMountPath, username, password)
		if err == nil {
			m.logger.Info("AppRole authentication successful")
			return &Result{
				Authenticated: true,
				Token:         token,
				Method:        "approle",
				Identity:      "approle",
			}
		}
		appRoleError = err
	}

	// SECURITY: Scrub password from memory immediately after use
	// This reduces the window of exposure, though Go's GC may have already created copies.
	// We overwrite both the string data and the parts slice to be thorough.
	if len(password) > 0 {
		// Convert password string to byte slice for overwriting
		// Note: In Go, strings are immutable, so we can't directly overwrite them.
		// However, we can overwrite the underlying byte slice if we have access to it.
		// The best we can do is overwrite the parts slice and clear references.

		// Overwrite the decoded byte slice (contains "username:password")
		for i := range decoded {
			decoded[i] = 0
		}

		// Clear the parts slice
		for i := range parts {
			parts[i] = ""
		}

		// Clear password variable reference (best effort - strings are immutable in Go)
		_ = password // Mark as intentionally unused after this point
	}

	if triedUserpass && userpassError != nil {
		m.logger.Debug("Userpass authentication failed",
			"error", userpassError)
	}
	if triedLDAP && ldapError != nil {
		m.logger.Debug("LDAP authentication failed",
			"error", ldapError)
	}
	if triedAppRole && appRoleError != nil {
		m.logger.Debug("AppRole authentication failed",
			"error", appRoleError)
	}
	if err != nil {
		return &Result{
			Authenticated: false,
			Error:         err,
		}
	}

	return &Result{
		Authenticated: false,
		Error:         fmt.Errorf("no basic authentication methods enabled"),
	}
}

// GetWWWAuthenticateHeaders returns the WWW-Authenticate headers for unauthenticated requests
func (m *Manager) GetWWWAuthenticateHeaders() []string {
	var headers []string

	if m.config.UserpassEnabled || m.config.LDAPEnabled {
		headers = append(headers, `Basic realm="EST Service"`)
	}

	if m.config.AppRoleEnabled && !m.config.UserpassEnabled && !m.config.LDAPEnabled {
		headers = append(headers, `Basic realm="EST Service"`)
	}

	if m.config.TokenEnabled {
		headers = append(headers, `Bearer realm="EST Service"`)
	}

	return headers
}
