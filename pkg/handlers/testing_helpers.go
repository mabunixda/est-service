package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/mabunixda/est-service/pkg/backend"
	"github.com/openbao/openbao/api/v2"
)

// mockBackendHandlers implements backend.Backend for handler tests
type mockBackendHandlers struct {
	signCSRFunc       func(context.Context, string, string, *x509.CertificateRequest, string) (*x509.Certificate, error)
	getCACertFunc     func(context.Context, string) (*x509.Certificate, error)
	getCAChainFunc    func(context.Context, string) ([]*x509.Certificate, error)
	validateTokenFunc func(context.Context, string) (bool, error)
}

func (m *mockBackendHandlers) Health(ctx context.Context) (*api.HealthResponse, error) {
	return &api.HealthResponse{Initialized: true, Sealed: false}, nil
}

func (m *mockBackendHandlers) GetCACertificate(ctx context.Context, mount string) (*x509.Certificate, error) {
	if m.getCACertFunc != nil {
		return m.getCACertFunc(ctx, mount)
	}
	return generateTestCACert()
}

func (m *mockBackendHandlers) GetCAChain(ctx context.Context, mount string) ([]*x509.Certificate, error) {
	if m.getCAChainFunc != nil {
		return m.getCAChainFunc(ctx, mount)
	}
	certs := []*x509.Certificate{}
	cert, _ := generateTestCACert()
	if cert != nil {
		certs = append(certs, cert)
	}
	return certs, nil
}

func (m *mockBackendHandlers) SignCSR(ctx context.Context, mount, role string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
	if m.signCSRFunc != nil {
		return m.signCSRFunc(ctx, mount, role, csr, ttl)
	}
	return generateTestCertFromCSR(csr)
}

func (m *mockBackendHandlers) SignCSRVerbatim(ctx context.Context, mount string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
	return generateTestCertFromCSR(csr)
}

func (m *mockBackendHandlers) GetIssuerPEM(ctx context.Context, mount, issuer string) (string, error) {
	return "", nil
}

func (m *mockBackendHandlers) AuthenticateUserpass(ctx context.Context, mount, username, password string) (string, error) {
	// Use constant-time comparison to prevent timing attacks even in tests
	// This serves as a good example for production code patterns
	usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte("testuser")) == 1
	passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte("testpass")) == 1

	if usernameMatch && passwordMatch {
		return "test-token", nil
	}
	return "", fmt.Errorf("invalid credentials")
}

func (m *mockBackendHandlers) AuthenticateLDAP(ctx context.Context, mount, username, password string) (string, error) {
	// Use constant-time comparison to prevent timing attacks even in tests
	usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte("ldapuser")) == 1
	passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte("ldappass")) == 1

	if usernameMatch && passwordMatch {
		return "ldap-token", nil
	}
	return "", fmt.Errorf("invalid LDAP credentials")
}

func (m *mockBackendHandlers) AuthenticateAppRole(ctx context.Context, mount, roleID, secretID string) (string, error) {
	if roleID == "test-role" && secretID == "test-secret" {
		return "approle-token", nil
	}
	return "", fmt.Errorf("invalid approle credentials")
}

func (m *mockBackendHandlers) AuthenticateCert(ctx context.Context, mount string, connState *tls.ConnectionState, role, entityAliasPrefix, tokenTTL string) (string, error) {
	if connState != nil && len(connState.PeerCertificates) > 0 {
		return "cert-token", nil
	}
	return "", fmt.Errorf("no client certificate")
}

func (m *mockBackendHandlers) ValidateToken(ctx context.Context, token string) (bool, error) {
	if m.validateTokenFunc != nil {
		return m.validateTokenFunc(ctx, token)
	}
	// Use constant-time comparison to prevent timing attacks even in tests
	return subtle.ConstantTimeCompare([]byte(token), []byte("valid-token")) == 1, nil
}

func (m *mockBackendHandlers) LookupToken(ctx context.Context, token string) (map[string]interface{}, error) {
	return nil, nil
}

func (m *mockBackendHandlers) RenewToken(ctx context.Context) error {
	return nil
}

func (m *mockBackendHandlers) StartTokenRenewal(ctx context.Context) {}

func (m *mockBackendHandlers) CreateOrUpdateEntity(ctx context.Context, name string, metadata map[string]string, policies []string) (string, error) {
	return "test-entity-id", nil
}

func (m *mockBackendHandlers) CreateOrUpdateEntityAlias(ctx context.Context, entityID, aliasName, mountAccessor string) (string, error) {
	return "test-alias-id", nil
}

func (m *mockBackendHandlers) CreateTokenForEntity(ctx context.Context, entityID string, policies []string, ttl string) (string, error) {
	return "test-entity-token", nil
}

func (m *mockBackendHandlers) GetAPIClient() *api.Client {
	return nil
}

func (m *mockBackendHandlers) CloneWithToken(ctx context.Context, token string) (backend.Backend, error) {
	return m, nil
}

func (m *mockBackendHandlers) Type() backend.BackendType {
	return backend.BackendTypeOpenBao
}

func (m *mockBackendHandlers) Close() error {
	return nil
}

// Helper functions for generating test certificates
func generateTestCACert() (*x509.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}

func generateTestCertFromCSR(csr *x509.CertificateRequest) (*x509.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, csr.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}

func generateTestCSR() ([]byte, *x509.CertificateRequest, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		DNSNames: []string{"test.example.com", "www.test.example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, nil, err
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, err
	}

	return csrDER, csr, nil
}

// mockTelemetry is a no-op telemetry implementation for tests
type mockTelemetry struct{}

func (m *mockTelemetry) RecordAuthSuccess(ctx context.Context, method, identity string) {}
func (m *mockTelemetry) RecordAuthFailure(ctx context.Context, method, reason string)   {}
func (m *mockTelemetry) RecordCertificateIssued(ctx context.Context, operation, subject, serialNumber string, ttl string) {
}
func (m *mockTelemetry) RecordCertificateRejected(ctx context.Context, operation, reason string) {}
