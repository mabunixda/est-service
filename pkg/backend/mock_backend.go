package backend

import (
	"context"
	"crypto/tls"
	"crypto/x509"

	"github.com/openbao/openbao/api/v2"
)

// MockBackend is a comprehensive mock implementation of the Backend interface for testing
type MockBackend struct {
	// Health
	HealthFunc func(ctx context.Context) (*api.HealthResponse, error)

	// PKI Operations
	GetCACertificateFunc func(ctx context.Context, mount string) (*x509.Certificate, error)
	GetCAChainFunc       func(ctx context.Context, mount string) ([]*x509.Certificate, error)
	SignCSRFunc          func(ctx context.Context, mount, role string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error)
	SignCSRVerbatimFunc  func(ctx context.Context, mount string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error)
	GetIssuerPEMFunc     func(ctx context.Context, mount, issuer string) (string, error)

	// Authentication Operations
	AuthenticateUserpassFunc func(ctx context.Context, mount, username, password string) (string, error)
	AuthenticateLDAPFunc     func(ctx context.Context, mount, username, password string) (string, error)
	AuthenticateAppRoleFunc  func(ctx context.Context, mount, roleID, secretID string) (string, error)
	AuthenticateCertFunc     func(ctx context.Context, mount string, connState *tls.ConnectionState, role string) (string, error)
	ValidateTokenFunc        func(ctx context.Context, token string) (bool, error)
	LookupTokenFunc          func(ctx context.Context, token string) (map[string]interface{}, error)

	// Token Management
	RenewTokenFunc        func(ctx context.Context) error
	StartTokenRenewalFunc func(ctx context.Context)

	// Client Access
	GetAPIClientFunc func() *api.Client

	// Clone
	CloneWithTokenFunc func(ctx context.Context, token string) (Backend, error)

	// Close
	CloseFunc func() error

	// Metadata
	TypeFunc func() BackendType
}

// Health implements Backend.Health
func (m *MockBackend) Health(ctx context.Context) (*api.HealthResponse, error) {
	if m.HealthFunc != nil {
		return m.HealthFunc(ctx)
	}
	return &api.HealthResponse{Initialized: true, Sealed: false}, nil
}

// GetCACertificate implements Backend.GetCACertificate
func (m *MockBackend) GetCACertificate(ctx context.Context, mount string) (*x509.Certificate, error) {
	if m.GetCACertificateFunc != nil {
		return m.GetCACertificateFunc(ctx, mount)
	}
	return nil, nil
}

// GetCAChain implements Backend.GetCAChain
func (m *MockBackend) GetCAChain(ctx context.Context, mount string) ([]*x509.Certificate, error) {
	if m.GetCAChainFunc != nil {
		return m.GetCAChainFunc(ctx, mount)
	}
	return nil, nil
}

// SignCSR implements Backend.SignCSR
func (m *MockBackend) SignCSR(ctx context.Context, mount, role string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
	if m.SignCSRFunc != nil {
		return m.SignCSRFunc(ctx, mount, role, csr, ttl)
	}
	return nil, nil
}

// SignCSRVerbatim implements Backend.SignCSRVerbatim
func (m *MockBackend) SignCSRVerbatim(ctx context.Context, mount string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
	if m.SignCSRVerbatimFunc != nil {
		return m.SignCSRVerbatimFunc(ctx, mount, csr, ttl)
	}
	return nil, nil
}

// GetIssuerPEM implements Backend.GetIssuerPEM
func (m *MockBackend) GetIssuerPEM(ctx context.Context, mount, issuer string) (string, error) {
	if m.GetIssuerPEMFunc != nil {
		return m.GetIssuerPEMFunc(ctx, mount, issuer)
	}
	return "", nil
}

// AuthenticateUserpass implements Backend.AuthenticateUserpass
func (m *MockBackend) AuthenticateUserpass(ctx context.Context, mount, username, password string) (string, error) {
	if m.AuthenticateUserpassFunc != nil {
		return m.AuthenticateUserpassFunc(ctx, mount, username, password)
	}
	return "", nil
}

// AuthenticateLDAP implements Backend.AuthenticateLDAP
func (m *MockBackend) AuthenticateLDAP(ctx context.Context, mount, username, password string) (string, error) {
	if m.AuthenticateLDAPFunc != nil {
		return m.AuthenticateLDAPFunc(ctx, mount, username, password)
	}
	return "", nil
}

// AuthenticateAppRole implements Backend.AuthenticateAppRole
func (m *MockBackend) AuthenticateAppRole(ctx context.Context, mount, roleID, secretID string) (string, error) {
	if m.AuthenticateAppRoleFunc != nil {
		return m.AuthenticateAppRoleFunc(ctx, mount, roleID, secretID)
	}
	return "", nil
}

// AuthenticateCert implements Backend.AuthenticateCert
func (m *MockBackend) AuthenticateCert(ctx context.Context, mount string, connState *tls.ConnectionState, role string) (string, error) {
	if m.AuthenticateCertFunc != nil {
		return m.AuthenticateCertFunc(ctx, mount, connState, role)
	}
	return "", nil
}

// ValidateToken implements Backend.ValidateToken
func (m *MockBackend) ValidateToken(ctx context.Context, token string) (bool, error) {
	if m.ValidateTokenFunc != nil {
		return m.ValidateTokenFunc(ctx, token)
	}
	return true, nil
}

// LookupToken implements Backend.LookupToken
func (m *MockBackend) LookupToken(ctx context.Context, token string) (map[string]interface{}, error) {
	if m.LookupTokenFunc != nil {
		return m.LookupTokenFunc(ctx, token)
	}
	return map[string]interface{}{}, nil
}

// RenewToken implements Backend.RenewToken
func (m *MockBackend) RenewToken(ctx context.Context) error {
	if m.RenewTokenFunc != nil {
		return m.RenewTokenFunc(ctx)
	}
	return nil
}

// StartTokenRenewal implements Backend.StartTokenRenewal
func (m *MockBackend) StartTokenRenewal(ctx context.Context) {
	if m.StartTokenRenewalFunc != nil {
		m.StartTokenRenewalFunc(ctx)
	}
}

// GetAPIClient implements Backend.GetAPIClient
func (m *MockBackend) GetAPIClient() *api.Client {
	if m.GetAPIClientFunc != nil {
		return m.GetAPIClientFunc()
	}
	return nil
}

// CloneWithToken implements Backend.CloneWithToken
func (m *MockBackend) CloneWithToken(ctx context.Context, token string) (Backend, error) {
	if m.CloneWithTokenFunc != nil {
		return m.CloneWithTokenFunc(ctx, token)
	}
	// Return a new mock with the same functions
	return &MockBackend{
		HealthFunc:               m.HealthFunc,
		GetCACertificateFunc:     m.GetCACertificateFunc,
		GetCAChainFunc:           m.GetCAChainFunc,
		SignCSRFunc:              m.SignCSRFunc,
		SignCSRVerbatimFunc:      m.SignCSRVerbatimFunc,
		GetIssuerPEMFunc:         m.GetIssuerPEMFunc,
		AuthenticateUserpassFunc: m.AuthenticateUserpassFunc,
		AuthenticateLDAPFunc:     m.AuthenticateLDAPFunc,
		AuthenticateAppRoleFunc:  m.AuthenticateAppRoleFunc,
		AuthenticateCertFunc:     m.AuthenticateCertFunc,
		ValidateTokenFunc:        m.ValidateTokenFunc,
		LookupTokenFunc:          m.LookupTokenFunc,
		RenewTokenFunc:           m.RenewTokenFunc,
		StartTokenRenewalFunc:    m.StartTokenRenewalFunc,
		GetAPIClientFunc:         m.GetAPIClientFunc,
		CloneWithTokenFunc:       m.CloneWithTokenFunc,
		CloseFunc:                m.CloseFunc,
		TypeFunc:                 m.TypeFunc,
	}, nil
}

// Type implements Backend.Type
func (m *MockBackend) Type() BackendType {
	if m.TypeFunc != nil {
		return m.TypeFunc()
	}
	return BackendTypeVault
}

// Close implements Backend.Close
func (m *MockBackend) Close() error {
	if m.CloseFunc != nil {
		return m.CloseFunc()
	}
	return nil
}
