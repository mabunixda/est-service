package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/big"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mabunixda/est-service/pkg/backend"
)

// ============================================================================
// Basic Auth Edge Cases
// ============================================================================

func TestAuthenticateBasic_EmptyUsername(t *testing.T) {
	mock := &backend.MockBackend{
		AuthenticateUserpassFunc: func(ctx context.Context, mount, username, password string) (string, error) {
			if username == "" {
				return "", fmt.Errorf("empty username not allowed")
			}
			return "token", nil
		},
	}

	mgr := NewManager(mock, &Config{UserpassEnabled: true}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	// Empty username with password
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(":password")))

	result := mgr.authenticateBasic(context.Background(), req)

	if result.Authenticated {
		t.Error("Expected authentication to fail with empty username")
	}
}

func TestAuthenticateBasic_EmptyPassword(t *testing.T) {
	mock := &backend.MockBackend{
		AuthenticateUserpassFunc: func(ctx context.Context, mount, username, password string) (string, error) {
			if password == "" {
				return "", fmt.Errorf("empty password not allowed")
			}
			return "token", nil
		},
	}

	mgr := NewManager(mock, &Config{UserpassEnabled: true}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	// Username with empty password
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("username:")))

	result := mgr.authenticateBasic(context.Background(), req)

	if result.Authenticated {
		t.Error("Expected authentication to fail with empty password")
	}
}

func TestAuthenticateBasic_SpecialCharactersInCredentials(t *testing.T) {
	mock := &backend.MockBackend{
		AuthenticateUserpassFunc: func(ctx context.Context, mount, username, password string) (string, error) {
			if username == "user@example.com" && password == "p@ss:w0rd!" {
				return "test-token", nil
			}
			return "", fmt.Errorf("invalid credentials")
		},
	}

	mgr := NewManager(mock, &Config{UserpassEnabled: true}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	// Username and password with special characters
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user@example.com:p@ss:w0rd!")))

	result := mgr.authenticateBasic(context.Background(), req)

	if !result.Authenticated {
		t.Error("Expected authentication to succeed with special characters in credentials")
	}
	if result.Token != "test-token" {
		t.Errorf("Expected token 'test-token', got '%s'", result.Token)
	}
	if result.Identity != "user@example.com" {
		t.Errorf("Expected identity 'user@example.com', got '%s'", result.Identity)
	}
}

func TestAuthenticateBasic_MultipleColonsInPassword(t *testing.T) {
	mock := &backend.MockBackend{
		AuthenticateUserpassFunc: func(ctx context.Context, mount, username, password string) (string, error) {
			if username == "user" && password == "pass:with:colons" {
				return "test-token", nil
			}
			return "", fmt.Errorf("invalid credentials")
		},
	}

	mgr := NewManager(mock, &Config{UserpassEnabled: true}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	// Password containing colons (should be handled by SplitN with limit 2)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:pass:with:colons")))

	result := mgr.authenticateBasic(context.Background(), req)

	if !result.Authenticated {
		t.Error("Expected authentication to succeed with colons in password")
	}
	if result.Identity != "user" {
		t.Errorf("Expected identity 'user', got '%s'", result.Identity)
	}
}

func TestAuthenticateBasic_BackendError(t *testing.T) {
	mock := &backend.MockBackend{
		AuthenticateUserpassFunc: func(ctx context.Context, mount, username, password string) (string, error) {
			return "", fmt.Errorf("backend connection failed")
		},
	}

	mgr := NewManager(mock, &Config{UserpassEnabled: true}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:pass")))

	result := mgr.authenticateBasic(context.Background(), req)

	if result.Authenticated {
		t.Error("Expected authentication to fail when backend returns error")
	}
	if result.Error == nil {
		t.Error("Expected error to be populated")
	}
}

func TestAuthenticateBasic_CustomMountPath(t *testing.T) {
	mountUsed := ""
	mock := &backend.MockBackend{
		AuthenticateUserpassFunc: func(ctx context.Context, mount, username, password string) (string, error) {
			mountUsed = mount
			return "test-token", nil
		},
	}

	mgr := NewManager(mock, &Config{
		UserpassEnabled:   true,
		UserpassMountPath: "custom-userpass",
	}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:pass")))

	result := mgr.authenticateBasic(context.Background(), req)

	if !result.Authenticated {
		t.Error("Expected authentication to succeed")
	}
	if mountUsed != "custom-userpass" {
		t.Errorf("Expected mount path 'custom-userpass', got '%s'", mountUsed)
	}
}

// ============================================================================
// Token Auth Edge Cases
// ============================================================================

func TestAuthenticateToken_ValidToken(t *testing.T) {
	mock := &backend.MockBackend{
		LookupTokenFunc: func(ctx context.Context, token string) (map[string]interface{}, error) {
			if token == "valid-token" {
				return map[string]interface{}{
					"display_name": "test-user",
				}, nil
			}
			return nil, fmt.Errorf("invalid token")
		},
	}

	mgr := NewManager(mock, &Config{TokenEnabled: true}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	result := mgr.authenticateToken(context.Background(), req)

	if !result.Authenticated {
		t.Error("Expected authentication to succeed with valid token")
	}
	if result.Token != "valid-token" {
		t.Errorf("Expected token 'valid-token', got '%s'", result.Token)
	}
	if result.Method != "token" {
		t.Errorf("Expected method 'token', got '%s'", result.Method)
	}
	if result.Identity != "test-user" {
		t.Errorf("Expected identity 'test-user', got '%s'", result.Identity)
	}
}

func TestAuthenticateToken_InvalidToken(t *testing.T) {
	mock := &backend.MockBackend{
		LookupTokenFunc: func(ctx context.Context, token string) (map[string]interface{}, error) {
			return nil, fmt.Errorf("invalid token")
		},
	}

	mgr := NewManager(mock, &Config{TokenEnabled: true}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	result := mgr.authenticateToken(context.Background(), req)

	if result.Authenticated {
		t.Error("Expected authentication to fail with invalid token")
	}
	if result.Error == nil {
		t.Error("Expected error for invalid token")
	}
}

func TestAuthenticateToken_BackendValidationError(t *testing.T) {
	mock := &backend.MockBackend{
		LookupTokenFunc: func(ctx context.Context, token string) (map[string]interface{}, error) {
			return nil, fmt.Errorf("backend unavailable")
		},
	}

	mgr := NewManager(mock, &Config{TokenEnabled: true}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer some-token")

	result := mgr.authenticateToken(context.Background(), req)

	if result.Authenticated {
		t.Error("Expected authentication to fail when validation fails")
	}
	if result.Error == nil {
		t.Error("Expected error to be populated")
	}
}

func TestAuthenticateToken_LookupFailure(t *testing.T) {
	// This test is no longer relevant since LookupToken failure means authentication fails
	// Previously, ValidateToken could succeed while LookupToken failed
	// Now, LookupToken does both validation and metadata retrieval
	t.Skip("Test no longer applicable: LookupToken now handles validation, so lookup failure means auth failure")
}

func TestAuthenticateToken_NoDisplayName(t *testing.T) {
	mock := &backend.MockBackend{
		LookupTokenFunc: func(ctx context.Context, token string) (map[string]interface{}, error) {
			return map[string]interface{}{
				"other_field": "value",
			}, nil
		},
	}

	mgr := NewManager(mock, &Config{TokenEnabled: true}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	result := mgr.authenticateToken(context.Background(), req)

	if !result.Authenticated {
		t.Error("Expected authentication to succeed")
	}
	if result.Identity != "unknown" {
		t.Errorf("Expected identity 'unknown' when display_name missing, got '%s'", result.Identity)
	}
}

func TestAuthenticateToken_WhitespaceInToken(t *testing.T) {
	mock := &backend.MockBackend{
		LookupTokenFunc: func(ctx context.Context, token string) (map[string]interface{}, error) {
			// Token with whitespace should fail
			if token != "no-whitespace" {
				return nil, fmt.Errorf("invalid token")
			}
			return map[string]interface{}{"display_name": "test"}, nil
		},
	}

	mgr := NewManager(mock, &Config{TokenEnabled: true}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	// Token with trailing whitespace (should not be trimmed by our code)
	req.Header.Set("Authorization", "Bearer no-whitespace ")

	result := mgr.authenticateToken(context.Background(), req)

	// This will fail because we don't trim - which is correct behavior
	if result.Authenticated {
		t.Error("Expected authentication to fail with whitespace in token")
	}
}

// ============================================================================
// Certificate Auth Edge Cases
// ============================================================================

func TestAuthenticateCert_NoCertificates(t *testing.T) {
	mgr := NewManager(nil, &Config{CertEnabled: true}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{},
	}

	result := mgr.authenticateCert(context.Background(), req)

	if result.Authenticated {
		t.Error("Expected authentication to fail with no certificates")
	}
}

func TestAuthenticateCert_ValidCertificate(t *testing.T) {
	cert := generateTestCert(t, "client.example.com")

	mock := &backend.MockBackend{
		AuthenticateCertFunc: func(ctx context.Context, mount string, connState *tls.ConnectionState, role, entityAliasPrefix, tokenTTL string) (string, error) {
			return "cert-token", nil
		},
	}

	mgr := NewManager(mock, &Config{
		CertEnabled:   true,
		CertMountPath: "cert",
		CertRole:      "client",
	}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	result := mgr.authenticateCert(context.Background(), req)

	if !result.Authenticated {
		t.Error("Expected authentication to succeed with valid certificate")
	}
	if result.Token != "cert-token" {
		t.Errorf("Expected token 'cert-token', got '%s'", result.Token)
	}
	if result.Method != "cert" {
		t.Errorf("Expected method 'cert', got '%s'", result.Method)
	}
	if result.Identity != "client.example.com" {
		t.Errorf("Expected identity 'client.example.com', got '%s'", result.Identity)
	}
}

func TestAuthenticateCert_BackendRejection(t *testing.T) {
	cert := generateTestCert(t, "untrusted.example.com")

	mock := &backend.MockBackend{
		AuthenticateCertFunc: func(ctx context.Context, mount string, connState *tls.ConnectionState, role, entityAliasPrefix, tokenTTL string) (string, error) {
			return "", fmt.Errorf("certificate not trusted")
		},
	}

	mgr := NewManager(mock, &Config{CertEnabled: true}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	result := mgr.authenticateCert(context.Background(), req)

	if result.Authenticated {
		t.Error("Expected authentication to fail when backend rejects certificate")
	}
	if result.Error == nil {
		t.Error("Expected error to be populated")
	}
}

func TestAuthenticateCert_CustomRole(t *testing.T) {
	cert := generateTestCert(t, "client.example.com")

	roleUsed := ""
	mock := &backend.MockBackend{
		AuthenticateCertFunc: func(ctx context.Context, mount string, connState *tls.ConnectionState, role, entityAliasPrefix, tokenTTL string) (string, error) {
			roleUsed = role
			return "cert-token", nil
		},
	}

	mgr := NewManager(mock, &Config{
		CertEnabled: true,
		CertRole:    "custom-role",
	}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	result := mgr.authenticateCert(context.Background(), req)

	if !result.Authenticated {
		t.Error("Expected authentication to succeed")
	}
	if roleUsed != "custom-role" {
		t.Errorf("Expected role 'custom-role', got '%s'", roleUsed)
	}
}

// ============================================================================
// Multi-Method Authentication Priority Tests
// ============================================================================

func TestAuthenticate_BearerTokenTakesPriority(t *testing.T) {
	authMethodUsed := ""

	mock := &backend.MockBackend{
		LookupTokenFunc: func(ctx context.Context, token string) (map[string]interface{}, error) {
			authMethodUsed = "token"
			return map[string]interface{}{"display_name": "token-user"}, nil
		},
		AuthenticateUserpassFunc: func(ctx context.Context, mount, username, password string) (string, error) {
			authMethodUsed = "userpass"
			return "userpass-token", nil
		},
	}

	mgr := NewManager(mock, &Config{
		TokenEnabled:    true,
		UserpassEnabled: true,
	}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	// Provide both Bearer token and Basic auth
	req.Header.Set("Authorization", "Bearer valid-token")

	result := mgr.Authenticate(context.Background(), req)

	if !result.Authenticated {
		t.Error("Expected authentication to succeed")
	}
	if authMethodUsed != "token" {
		t.Errorf("Expected Bearer token to take priority, but %s was used", authMethodUsed)
	}
	if result.Method != "token" {
		t.Errorf("Expected method 'token', got '%s'", result.Method)
	}
}

func TestAuthenticate_CertTakesPriorityOverBasic(t *testing.T) {
	cert := generateTestCert(t, "client.example.com")
	authMethodUsed := ""

	mock := &backend.MockBackend{
		AuthenticateCertFunc: func(ctx context.Context, mount string, connState *tls.ConnectionState, role, entityAliasPrefix, tokenTTL string) (string, error) {
			authMethodUsed = "cert"
			return "cert-token", nil
		},
		AuthenticateUserpassFunc: func(ctx context.Context, mount, username, password string) (string, error) {
			authMethodUsed = "userpass"
			return "userpass-token", nil
		},
	}

	mgr := NewManager(mock, &Config{
		CertEnabled:     true,
		UserpassEnabled: true,
	}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:pass")))

	result := mgr.Authenticate(context.Background(), req)

	if !result.Authenticated {
		t.Error("Expected authentication to succeed")
	}
	if authMethodUsed != "cert" {
		t.Errorf("Expected cert to take priority, but %s was used", authMethodUsed)
	}
	if result.Method != "cert" {
		t.Errorf("Expected method 'cert', got '%s'", result.Method)
	}
}

func TestAuthenticate_FallbackToBasicWhenTokenInvalid(t *testing.T) {
	mock := &backend.MockBackend{
		ValidateTokenFunc: func(ctx context.Context, token string) (bool, error) {
			return false, nil // Token is invalid
		},
		AuthenticateUserpassFunc: func(ctx context.Context, mount, username, password string) (string, error) {
			return "userpass-token", nil
		},
	}

	mgr := NewManager(mock, &Config{
		TokenEnabled:    true,
		UserpassEnabled: true,
	}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:pass")))

	result := mgr.Authenticate(context.Background(), req)

	if !result.Authenticated {
		t.Error("Expected authentication to succeed with fallback to Basic")
	}
	if result.Method != "userpass" {
		t.Errorf("Expected method 'userpass', got '%s'", result.Method)
	}
}

func TestAuthenticate_AllMethodsFailure(t *testing.T) {
	mock := &backend.MockBackend{
		ValidateTokenFunc: func(ctx context.Context, token string) (bool, error) {
			return false, fmt.Errorf("invalid token")
		},
		AuthenticateUserpassFunc: func(ctx context.Context, mount, username, password string) (string, error) {
			return "", fmt.Errorf("invalid credentials")
		},
	}

	mgr := NewManager(mock, &Config{
		TokenEnabled:    true,
		UserpassEnabled: true,
		CertEnabled:     true,
	}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:pass")))

	result := mgr.Authenticate(context.Background(), req)

	if result.Authenticated {
		t.Error("Expected authentication to fail when all methods fail")
	}
	if result.Error == nil {
		t.Error("Expected error to be populated")
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

func generateTestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}
