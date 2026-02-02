package backend

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"testing"

	"github.com/openbao/openbao/api/v2"
)

// Mock backend for testing
type mockBackendTest struct {
	healthFunc        func(context.Context) (*api.HealthResponse, error)
	getCACertFunc     func(context.Context, string) (*x509.Certificate, error)
	validateTokenFunc func(context.Context, string) (bool, error)
}

func (m *mockBackendTest) Health(ctx context.Context) (*api.HealthResponse, error) {
	if m.healthFunc != nil {
		return m.healthFunc(ctx)
	}
	return &api.HealthResponse{Initialized: true, Sealed: false}, nil
}

func (m *mockBackendTest) GetCACertificate(ctx context.Context, mount string) (*x509.Certificate, error) {
	if m.getCACertFunc != nil {
		return m.getCACertFunc(ctx, mount)
	}
	return nil, nil
}

func (m *mockBackendTest) GetCAChain(ctx context.Context, mount string) ([]*x509.Certificate, error) {
	return nil, nil
}

func (m *mockBackendTest) SignCSR(ctx context.Context, mount, role string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
	return nil, nil
}

func (m *mockBackendTest) SignCSRVerbatim(ctx context.Context, mount string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
	return nil, nil
}

func (m *mockBackendTest) GetIssuerPEM(ctx context.Context, mount, issuer string) (string, error) {
	return "", nil
}

func (m *mockBackendTest) AuthenticateUserpass(ctx context.Context, mount, username, password string) (string, error) {
	return "", nil
}

func (m *mockBackendTest) AuthenticateLDAP(ctx context.Context, mount, username, password string) (string, error) {
	return "", nil
}

func (m *mockBackendTest) AuthenticateAppRole(ctx context.Context, mount, roleID, secretID string) (string, error) {
	return "", nil
}

func (m *mockBackendTest) AuthenticateCert(ctx context.Context, mount string, connState *tls.ConnectionState, role string) (string, error) {
	return "", nil
}

func (m *mockBackendTest) ValidateToken(ctx context.Context, token string) (bool, error) {
	if m.validateTokenFunc != nil {
		return m.validateTokenFunc(ctx, token)
	}
	return true, nil
}

func (m *mockBackendTest) LookupToken(ctx context.Context, token string) (map[string]interface{}, error) {
	return nil, nil
}

func (m *mockBackendTest) RenewToken(ctx context.Context) error {
	return nil
}

func (m *mockBackendTest) StartTokenRenewal(ctx context.Context) {}

func (m *mockBackendTest) GetAPIClient() *api.Client {
	return nil
}

func (m *mockBackendTest) CloneWithToken(ctx context.Context, token string) (Backend, error) {
	return m, nil
}

func (m *mockBackendTest) Type() BackendType {
	return BackendTypeOpenBao
}

func (m *mockBackendTest) Close() error {
	return nil
}

func TestClientWrapperDelegation(t *testing.T) {
	mock := &mockBackendTest{}
	client := &Client{backend: mock}

	ctx := context.Background()

	// Test Health delegation
	health, err := client.Health(ctx)
	if err != nil {
		t.Errorf("Health() error = %v", err)
	}
	if health == nil {
		t.Error("Health() returned nil")
	}

	// Test ValidateToken delegation
	valid, err := client.ValidateToken(ctx, "test-token")
	if err != nil {
		t.Errorf("ValidateToken() error = %v", err)
	}
	if !valid {
		t.Error("ValidateToken() should return true for mock")
	}
}

// TestClient_AllMethodDelegation comprehensively tests all Client method delegations
func TestClient_AllMethodDelegation(t *testing.T) {
	tests := []struct {
		name string
		test func(*testing.T, *Client, *mockBackendTest)
	}{
		{
			name: "Health",
			test: func(t *testing.T, c *Client, m *mockBackendTest) {
				healthCalled := false
				m.healthFunc = func(ctx context.Context) (*api.HealthResponse, error) {
					healthCalled = true
					return &api.HealthResponse{Initialized: true, Sealed: false}, nil
				}

				health, err := c.Health(context.Background())
				if err != nil {
					t.Errorf("Health() error = %v", err)
				}
				if !healthCalled {
					t.Error("Health() did not call backend")
				}
				if health == nil || !health.Initialized {
					t.Error("Health() returned unexpected value")
				}
			},
		},
		{
			name: "GetCACertificate",
			test: func(t *testing.T, c *Client, m *mockBackendTest) {
				getCACalled := false
				testCert := &x509.Certificate{SerialNumber: big.NewInt(12345)}

				m.getCACertFunc = func(ctx context.Context, mount string) (*x509.Certificate, error) {
					getCACalled = true
					if mount != "test-mount" {
						t.Errorf("Expected mount 'test-mount', got '%s'", mount)
					}
					return testCert, nil
				}

				cert, err := c.GetCACertificate(context.Background(), "test-mount")
				if err != nil {
					t.Errorf("GetCACertificate() error = %v", err)
				}
				if !getCACalled {
					t.Error("GetCACertificate() did not call backend")
				}
				if cert != testCert {
					t.Error("GetCACertificate() returned wrong certificate")
				}
			},
		},
		{
			name: "ValidateToken",
			test: func(t *testing.T, c *Client, m *mockBackendTest) {
				validateCalled := false

				m.validateTokenFunc = func(ctx context.Context, token string) (bool, error) {
					validateCalled = true
					if token != "test-token" {
						t.Errorf("Expected token 'test-token', got '%s'", token)
					}
					return true, nil
				}

				valid, err := c.ValidateToken(context.Background(), "test-token")
				if err != nil {
					t.Errorf("ValidateToken() error = %v", err)
				}
				if !validateCalled {
					t.Error("ValidateToken() did not call backend")
				}
				if !valid {
					t.Error("ValidateToken() returned false")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockBackendTest{}
			client := &Client{backend: mock}
			tt.test(t, client, mock)
		})
	}
}

// TestClient_GetBackend tests that GetBackend returns the underlying backend
func TestClient_GetBackend(t *testing.T) {
	mock := &mockBackendTest{}
	client := &Client{backend: mock}

	backend := client.GetBackend()
	if backend != mock {
		t.Error("GetBackend() did not return the underlying backend")
	}
}

// TestClient_Type tests that Type returns the backend type
func TestClient_Type(t *testing.T) {
	tests := []struct {
		name         string
		backendType  BackendType
		expectedType BackendType
	}{
		{
			name:         "Vault backend",
			backendType:  BackendTypeVault,
			expectedType: BackendTypeVault,
		},
		{
			name:         "OpenBao backend",
			backendType:  BackendTypeOpenBao,
			expectedType: BackendTypeOpenBao,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockBackendType{backendType: tt.backendType}
			client := &Client{backend: mock}

			if client.Type() != tt.expectedType {
				t.Errorf("Type() = %v, want %v", client.Type(), tt.expectedType)
			}
		})
	}
}

// mockBackendType is a minimal mock that only implements Type()
type mockBackendType struct {
	mockBackendTest
	backendType BackendType
}

func (m *mockBackendType) Type() BackendType {
	return m.backendType
}

func (m *mockBackendType) Close() error {
	return nil
}

// TestClient_CloneWithToken_Delegation tests that CloneWithToken returns a Client wrapping the cloned Backend
func TestClient_CloneWithToken_Delegation(t *testing.T) {
	cloneCalled := false
	clonedBackend := &mockBackendTest{}

	mock := &mockBackendClone{
		cloneFunc: func(ctx context.Context, token string) (Backend, error) {
			cloneCalled = true
			if token != "new-token" {
				t.Errorf("Expected token 'new-token', got '%s'", token)
			}
			return clonedBackend, nil
		},
	}

	client := &Client{backend: mock}

	cloned, err := client.CloneWithToken(context.Background(), "new-token")
	if err != nil {
		t.Fatalf("CloneWithToken() error = %v", err)
	}

	if !cloneCalled {
		t.Error("CloneWithToken() did not call backend")
	}

	// Verify the returned value is a Client wrapping the cloned backend
	clonedClient, ok := cloned.(*Client)
	if !ok {
		t.Fatal("CloneWithToken() did not return a *Client")
	}

	if clonedClient.GetBackend() != clonedBackend {
		t.Error("CloneWithToken() returned Client with wrong backend")
	}
}

// mockBackendClone is a minimal mock for testing CloneWithToken
type mockBackendClone struct {
	mockBackendTest
	cloneFunc func(context.Context, string) (Backend, error)
}

func (m *mockBackendClone) CloneWithToken(ctx context.Context, token string) (Backend, error) {
	if m.cloneFunc != nil {
		return m.cloneFunc(ctx, token)
	}
	return &mockBackendTest{}, nil
}

// TestClient_GetCAChain tests GetCAChain delegation
func TestClient_GetCAChain(t *testing.T) {
	getCalled := false
	testChain := []*x509.Certificate{
		{SerialNumber: big.NewInt(1)},
		{SerialNumber: big.NewInt(2)},
	}

	mock := &mockBackendGetChain{
		getChainFunc: func(ctx context.Context, mount string) ([]*x509.Certificate, error) {
			getCalled = true
			if mount != "test-mount" {
				t.Errorf("Expected mount 'test-mount', got '%s'", mount)
			}
			return testChain, nil
		},
	}

	client := &Client{backend: mock}

	chain, err := client.GetCAChain(context.Background(), "test-mount")
	if err != nil {
		t.Fatalf("GetCAChain() error = %v", err)
	}

	if !getCalled {
		t.Error("GetCAChain() did not call backend")
	}

	if len(chain) != 2 {
		t.Errorf("Expected chain length 2, got %d", len(chain))
	}
}

// mockBackendGetChain for testing GetCAChain
type mockBackendGetChain struct {
	mockBackendTest
	getChainFunc func(context.Context, string) ([]*x509.Certificate, error)
}

func (m *mockBackendGetChain) GetCAChain(ctx context.Context, mount string) ([]*x509.Certificate, error) {
	if m.getChainFunc != nil {
		return m.getChainFunc(ctx, mount)
	}
	return nil, nil
}

// TestClient_SignCSR tests SignCSR delegation
func TestClient_SignCSR(t *testing.T) {
	signCalled := false
	testCSR := &x509.CertificateRequest{}
	testCert := &x509.Certificate{SerialNumber: big.NewInt(999)}

	mock := &mockBackendSignCSR{
		signFunc: func(ctx context.Context, mount, role string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
			signCalled = true
			if mount != "pki" {
				t.Errorf("Expected mount 'pki', got '%s'", mount)
			}
			if role != "server-role" {
				t.Errorf("Expected role 'server-role', got '%s'", role)
			}
			if csr != testCSR {
				t.Error("CSR mismatch")
			}
			if ttl != "24h" {
				t.Errorf("Expected ttl '24h', got '%s'", ttl)
			}
			return testCert, nil
		},
	}

	client := &Client{backend: mock}

	cert, err := client.SignCSR(context.Background(), "pki", "server-role", testCSR, "24h")
	if err != nil {
		t.Fatalf("SignCSR() error = %v", err)
	}

	if !signCalled {
		t.Error("SignCSR() did not call backend")
	}

	if cert != testCert {
		t.Error("SignCSR() returned wrong certificate")
	}
}

// mockBackendSignCSR for testing SignCSR
type mockBackendSignCSR struct {
	mockBackendTest
	signFunc func(context.Context, string, string, *x509.CertificateRequest, string) (*x509.Certificate, error)
}

func (m *mockBackendSignCSR) SignCSR(ctx context.Context, mount, role string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
	if m.signFunc != nil {
		return m.signFunc(ctx, mount, role, csr, ttl)
	}
	return nil, nil
}

// TestClient_SignCSRVerbatim tests SignCSRVerbatim delegation
func TestClient_SignCSRVerbatim(t *testing.T) {
	signCalled := false
	testCSR := &x509.CertificateRequest{}
	testCert := &x509.Certificate{SerialNumber: big.NewInt(888)}

	mock := &mockBackendSignCSRVerbatim{
		signVerbatimFunc: func(ctx context.Context, mount string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
			signCalled = true
			if mount != "pki" {
				t.Errorf("Expected mount 'pki', got '%s'", mount)
			}
			if csr != testCSR {
				t.Error("CSR mismatch")
			}
			if ttl != "48h" {
				t.Errorf("Expected ttl '48h', got '%s'", ttl)
			}
			return testCert, nil
		},
	}

	client := &Client{backend: mock}

	cert, err := client.SignCSRVerbatim(context.Background(), "pki", testCSR, "48h")
	if err != nil {
		t.Fatalf("SignCSRVerbatim() error = %v", err)
	}

	if !signCalled {
		t.Error("SignCSRVerbatim() did not call backend")
	}

	if cert != testCert {
		t.Error("SignCSRVerbatim() returned wrong certificate")
	}
}

// mockBackendSignCSRVerbatim for testing SignCSRVerbatim
type mockBackendSignCSRVerbatim struct {
	mockBackendTest
	signVerbatimFunc func(context.Context, string, *x509.CertificateRequest, string) (*x509.Certificate, error)
}

func (m *mockBackendSignCSRVerbatim) SignCSRVerbatim(ctx context.Context, mount string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
	if m.signVerbatimFunc != nil {
		return m.signVerbatimFunc(ctx, mount, csr, ttl)
	}
	return nil, nil
}

// TestClient_GetIssuerPEM tests GetIssuerPEM delegation
func TestClient_GetIssuerPEM(t *testing.T) {
	getCalled := false
	expectedPEM := "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"

	mock := &mockBackendGetIssuer{
		getIssuerFunc: func(ctx context.Context, mount, issuer string) (string, error) {
			getCalled = true
			if mount != "pki" {
				t.Errorf("Expected mount 'pki', got '%s'", mount)
			}
			if issuer != "test-issuer" {
				t.Errorf("Expected issuer 'test-issuer', got '%s'", issuer)
			}
			return expectedPEM, nil
		},
	}

	client := &Client{backend: mock}

	pem, err := client.GetIssuerPEM(context.Background(), "pki", "test-issuer")
	if err != nil {
		t.Fatalf("GetIssuerPEM() error = %v", err)
	}

	if !getCalled {
		t.Error("GetIssuerPEM() did not call backend")
	}

	if pem != expectedPEM {
		t.Errorf("Expected PEM '%s', got '%s'", expectedPEM, pem)
	}
}

// mockBackendGetIssuer for testing GetIssuerPEM
type mockBackendGetIssuer struct {
	mockBackendTest
	getIssuerFunc func(context.Context, string, string) (string, error)
}

func (m *mockBackendGetIssuer) GetIssuerPEM(ctx context.Context, mount, issuer string) (string, error) {
	if m.getIssuerFunc != nil {
		return m.getIssuerFunc(ctx, mount, issuer)
	}
	return "", nil
}

// TestClient_AuthenticateUserpass tests AuthenticateUserpass delegation
func TestClient_AuthenticateUserpass(t *testing.T) {
	authCalled := false
	expectedToken := "test-token-123"

	mock := &mockBackendAuthUserpass{
		authFunc: func(ctx context.Context, mount, username, password string) (string, error) {
			authCalled = true
			if mount != "userpass" {
				t.Errorf("Expected mount 'userpass', got '%s'", mount)
			}
			if username != "testuser" {
				t.Errorf("Expected username 'testuser', got '%s'", username)
			}
			if password != "testpass" {
				t.Errorf("Expected password 'testpass', got '%s'", password)
			}
			return expectedToken, nil
		},
	}

	client := &Client{backend: mock}

	token, err := client.AuthenticateUserpass(context.Background(), "userpass", "testuser", "testpass")
	if err != nil {
		t.Fatalf("AuthenticateUserpass() error = %v", err)
	}

	if !authCalled {
		t.Error("AuthenticateUserpass() did not call backend")
	}

	if token != expectedToken {
		t.Errorf("Expected token '%s', got '%s'", expectedToken, token)
	}
}

// mockBackendAuthUserpass for testing AuthenticateUserpass
type mockBackendAuthUserpass struct {
	mockBackendTest
	authFunc func(context.Context, string, string, string) (string, error)
}

func (m *mockBackendAuthUserpass) AuthenticateUserpass(ctx context.Context, mount, username, password string) (string, error) {
	if m.authFunc != nil {
		return m.authFunc(ctx, mount, username, password)
	}
	return "", nil
}

// TestClient_AuthenticateCert tests AuthenticateCert delegation
func TestClient_AuthenticateCert(t *testing.T) {
	authCalled := false
	expectedToken := "cert-token-456"
	testConnState := &tls.ConnectionState{}

	mock := &mockBackendAuthCert{
		authFunc: func(ctx context.Context, mount string, connState *tls.ConnectionState, role string) (string, error) {
			authCalled = true
			if mount != "cert" {
				t.Errorf("Expected mount 'cert', got '%s'", mount)
			}
			if connState != testConnState {
				t.Error("Connection state mismatch")
			}
			if role != "client-role" {
				t.Errorf("Expected role 'client-role', got '%s'", role)
			}
			return expectedToken, nil
		},
	}

	client := &Client{backend: mock}

	token, err := client.AuthenticateCert(context.Background(), "cert", testConnState, "client-role")
	if err != nil {
		t.Fatalf("AuthenticateCert() error = %v", err)
	}

	if !authCalled {
		t.Error("AuthenticateCert() did not call backend")
	}

	if token != expectedToken {
		t.Errorf("Expected token '%s', got '%s'", expectedToken, token)
	}
}

// mockBackendAuthCert for testing AuthenticateCert
type mockBackendAuthCert struct {
	mockBackendTest
	authFunc func(context.Context, string, *tls.ConnectionState, string) (string, error)
}

func (m *mockBackendAuthCert) AuthenticateCert(ctx context.Context, mount string, connState *tls.ConnectionState, role string) (string, error) {
	if m.authFunc != nil {
		return m.authFunc(ctx, mount, connState, role)
	}
	return "", nil
}

// TestClient_LookupToken tests LookupToken delegation
func TestClient_LookupToken(t *testing.T) {
	lookupCalled := false
	expectedData := map[string]interface{}{
		"id":   "test-token",
		"ttl":  3600,
		"role": "test-role",
	}

	mock := &mockBackendLookupToken{
		lookupFunc: func(ctx context.Context, token string) (map[string]interface{}, error) {
			lookupCalled = true
			if token != "test-token" {
				t.Errorf("Expected token 'test-token', got '%s'", token)
			}
			return expectedData, nil
		},
	}

	client := &Client{backend: mock}

	data, err := client.LookupToken(context.Background(), "test-token")
	if err != nil {
		t.Fatalf("LookupToken() error = %v", err)
	}

	if !lookupCalled {
		t.Error("LookupToken() did not call backend")
	}

	if data["id"] != "test-token" {
		t.Error("LookupToken() returned wrong data")
	}
}

// mockBackendLookupToken for testing LookupToken
type mockBackendLookupToken struct {
	mockBackendTest
	lookupFunc func(context.Context, string) (map[string]interface{}, error)
}

func (m *mockBackendLookupToken) LookupToken(ctx context.Context, token string) (map[string]interface{}, error) {
	if m.lookupFunc != nil {
		return m.lookupFunc(ctx, token)
	}
	return nil, nil
}

// TestClient_RenewToken tests RenewToken delegation
func TestClient_RenewToken(t *testing.T) {
	renewCalled := false

	mock := &mockBackendRenewToken{
		renewFunc: func(ctx context.Context) error {
			renewCalled = true
			return nil
		},
	}

	client := &Client{backend: mock}

	err := client.RenewToken(context.Background())
	if err != nil {
		t.Fatalf("RenewToken() error = %v", err)
	}

	if !renewCalled {
		t.Error("RenewToken() did not call backend")
	}
}

// mockBackendRenewToken for testing RenewToken
type mockBackendRenewToken struct {
	mockBackendTest
	renewFunc func(context.Context) error
}

func (m *mockBackendRenewToken) RenewToken(ctx context.Context) error {
	if m.renewFunc != nil {
		return m.renewFunc(ctx)
	}
	return nil
}

// TestClient_StartTokenRenewal tests StartTokenRenewal delegation
func TestClient_StartTokenRenewal(t *testing.T) {
	startCalled := false

	mock := &mockBackendStartRenewal{
		startFunc: func(ctx context.Context) {
			startCalled = true
		},
	}

	client := &Client{backend: mock}

	client.StartTokenRenewal(context.Background())

	if !startCalled {
		t.Error("StartTokenRenewal() did not call backend")
	}
}

// mockBackendStartRenewal for testing StartTokenRenewal
type mockBackendStartRenewal struct {
	mockBackendTest
	startFunc func(context.Context)
}

func (m *mockBackendStartRenewal) StartTokenRenewal(ctx context.Context) {
	if m.startFunc != nil {
		m.startFunc(ctx)
	}
}

// TestClient_GetAPIClient tests GetAPIClient delegation
func TestClient_GetAPIClient(t *testing.T) {
	getCalled := false
	testAPIClient := &api.Client{}

	mock := &mockBackendGetAPIClient{
		getFunc: func() *api.Client {
			getCalled = true
			return testAPIClient
		},
	}

	client := &Client{backend: mock}

	apiClient := client.GetAPIClient()

	if !getCalled {
		t.Error("GetAPIClient() did not call backend")
	}

	if apiClient != testAPIClient {
		t.Error("GetAPIClient() returned wrong client")
	}
}

// mockBackendGetAPIClient for testing GetAPIClient
type mockBackendGetAPIClient struct {
	mockBackendTest
	getFunc func() *api.Client
}

func (m *mockBackendGetAPIClient) GetAPIClient() *api.Client {
	if m.getFunc != nil {
		return m.getFunc()
	}
	return nil
}
