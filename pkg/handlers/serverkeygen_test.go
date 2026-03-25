package handlers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mabunixda/est-service/pkg/auth"
	"github.com/mabunixda/est-service/pkg/backend"
	"github.com/openbao/openbao/api/v2"
)

// Mock backend for serverkeygen tests
type mockServerKeyGenBackend struct {
	signCSRFunc              func(ctx context.Context, mount, role string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error)
	signCSRVerbatimFunc      func(ctx context.Context, mount string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error)
	cloneWithTokenFunc       func(ctx context.Context, token string) (backend.Backend, error)
	closeFunc                func() error
	authenticateUserpassFunc func(ctx context.Context, mount, username, password string) (string, error)
	authenticateLDAPFunc     func(ctx context.Context, mount, username, password string) (string, error)
	authenticateAppRoleFunc  func(ctx context.Context, mount, roleID, secretID string) (string, error)
	authenticateCertFunc     func(ctx context.Context, mount string, connState *tls.ConnectionState, role string) (string, error)
	validateTokenFunc        func(ctx context.Context, token string) (bool, error)
	lookupTokenFunc          func(ctx context.Context, token string) (map[string]interface{}, error)
}

func (m *mockServerKeyGenBackend) SignCSR(ctx context.Context, mount, role string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
	if m.signCSRFunc != nil {
		return m.signCSRFunc(ctx, mount, role, csr, ttl)
	}
	return createMockCertificate(csr), nil
}

func (m *mockServerKeyGenBackend) SignCSRVerbatim(ctx context.Context, mount string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
	if m.signCSRVerbatimFunc != nil {
		return m.signCSRVerbatimFunc(ctx, mount, csr, ttl)
	}
	return createMockCertificate(csr), nil
}

func (m *mockServerKeyGenBackend) CloneWithToken(ctx context.Context, token string) (backend.Backend, error) {
	if m.cloneWithTokenFunc != nil {
		return m.cloneWithTokenFunc(ctx, token)
	}
	return m, nil
}

func (m *mockServerKeyGenBackend) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

func (m *mockServerKeyGenBackend) GetCACertificate(ctx context.Context, mount string) (*x509.Certificate, error) {
	return nil, nil
}

func (m *mockServerKeyGenBackend) GetCAChain(ctx context.Context, mount string) ([]*x509.Certificate, error) {
	return nil, nil
}

func (m *mockServerKeyGenBackend) GetIssuerPEM(ctx context.Context, mount, issuer string) (string, error) {
	return "", nil
}

func (m *mockServerKeyGenBackend) AuthenticateUserpass(ctx context.Context, mount, username, password string) (string, error) {
	if m.authenticateUserpassFunc != nil {
		return m.authenticateUserpassFunc(ctx, mount, username, password)
	}
	return "", nil
}

func (m *mockServerKeyGenBackend) AuthenticateLDAP(ctx context.Context, mount, username, password string) (string, error) {
	if m.authenticateLDAPFunc != nil {
		return m.authenticateLDAPFunc(ctx, mount, username, password)
	}
	return "", nil
}

func (m *mockServerKeyGenBackend) AuthenticateAppRole(ctx context.Context, mount, roleID, secretID string) (string, error) {
	if m.authenticateAppRoleFunc != nil {
		return m.authenticateAppRoleFunc(ctx, mount, roleID, secretID)
	}
	return "", nil
}

func (m *mockServerKeyGenBackend) AuthenticateCert(ctx context.Context, mount string, connState *tls.ConnectionState, role, entityAliasPrefix, tokenTTL string) (string, error) {
	if m.authenticateCertFunc != nil {
		return m.authenticateCertFunc(ctx, mount, connState, role)
	}
	return "", nil
}

func (m *mockServerKeyGenBackend) ValidateToken(ctx context.Context, token string) (bool, error) {
	if m.validateTokenFunc != nil {
		return m.validateTokenFunc(ctx, token)
	}
	return true, nil
}

func (m *mockServerKeyGenBackend) LookupToken(ctx context.Context, token string) (map[string]interface{}, error) {
	if m.lookupTokenFunc != nil {
		return m.lookupTokenFunc(ctx, token)
	}
	return nil, nil
}

func (m *mockServerKeyGenBackend) RenewToken(ctx context.Context) error {
	return nil
}

func (m *mockServerKeyGenBackend) StartTokenRenewal(ctx context.Context) {
}

func (m *mockServerKeyGenBackend) GetAPIClient() *api.Client {
	return nil
}

func (m *mockServerKeyGenBackend) GenerateExportableKey(ctx context.Context, transitMount, keyType string, keyBits int) (interface{}, interface{}, error) {
	return nil, nil, nil
}

func (m *mockServerKeyGenBackend) Type() backend.BackendType {
	return backend.BackendTypeOpenBao
}

func (m *mockServerKeyGenBackend) Health(ctx context.Context) (*api.HealthResponse, error) {
	return &api.HealthResponse{}, nil
}

func (m *mockServerKeyGenBackend) CreateOrUpdateEntity(ctx context.Context, name string, metadata map[string]string, policies []string) (string, error) {
	return "entity-id", nil
}

func (m *mockServerKeyGenBackend) CreateOrUpdateEntityAlias(ctx context.Context, entityID, aliasName, mountAccessor string) (string, error) {
	return "alias-id", nil
}

func (m *mockServerKeyGenBackend) CreateTokenForEntity(ctx context.Context, entityID string, policies []string, ttl string) (string, error) {
	return "entity-token", nil
}

func TestServerKeyGenHandler_RSAKeyGeneration(t *testing.T) {
	logger := slog.Default()
	mockBackend := &mockServerKeyGenBackend{}
	mockAuth := createMockAuthManager()

	config := &ServerKeyGenConfig{
		Enabled:        true,
		DefaultKeyType: "rsa",
		DefaultKeySize: 2048,
		DefaultMount:   "pki",
		MaxCSRSize:     4096,
		DefaultPolicy: LabelPolicy{
			Type:  "role",
			Value: "test-role",
		},
	}

	handler := NewServerKeyGenHandler(mockBackend, mockAuth, config, logger, nil)

	// Create test CSR
	csrPEM := createTestCSRPEM(t, "test.example.com")
	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/serverkeygen", bytes.NewReader(csrPEM))
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(body))
	}

	// Verify multipart response
	mediaType, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("Failed to parse Content-Type: %v", err)
	}

	if !strings.HasPrefix(mediaType, "multipart/") {
		t.Errorf("Expected multipart Content-Type, got %s", mediaType)
	}

	// Parse multipart response
	mr := multipart.NewReader(resp.Body, params["boundary"])

	// Part 1: Certificate
	part1, err := mr.NextPart()
	if err != nil {
		t.Fatalf("Failed to read first part: %v", err)
	}

	certContentType := part1.Header.Get("Content-Type")
	if !strings.Contains(certContentType, "application/pkcs7-mime") {
		t.Errorf("Expected PKCS7 content type, got %s", certContentType)
	}

	certData, err := io.ReadAll(part1)
	if err != nil {
		t.Fatalf("Failed to read certificate data: %v", err)
	}

	if len(certData) == 0 {
		t.Error("Certificate data is empty")
	}

	// Part 2: Private key
	part2, err := mr.NextPart()
	if err != nil {
		t.Fatalf("Failed to read second part: %v", err)
	}

	keyContentType := part2.Header.Get("Content-Type")
	if !strings.Contains(keyContentType, "application/pkcs8") {
		t.Errorf("Expected PKCS8 content type, got %s", keyContentType)
	}

	keyData, err := io.ReadAll(part2)
	if err != nil {
		t.Fatalf("Failed to read key data: %v", err)
	}

	if len(keyData) == 0 {
		t.Error("Private key data is empty")
	}

	// Decode and verify private key is valid RSA
	keyDER, err := base64.StdEncoding.DecodeString(string(keyData))
	if err != nil {
		t.Fatalf("Failed to decode private key: %v", err)
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		t.Fatalf("Failed to parse PKCS8 private key: %v", err)
	}

	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		t.Errorf("Expected RSA private key, got %T", privateKey)
	}

	if rsaKey.N.BitLen() != 2048 {
		t.Errorf("Expected 2048-bit RSA key, got %d bits", rsaKey.N.BitLen())
	}
}

func TestServerKeyGenHandler_ECDSAKeyGeneration(t *testing.T) {
	logger := slog.Default()
	mockBackend := &mockServerKeyGenBackend{}
	mockAuth := createMockAuthManager()

	tests := []struct {
		name         string
		keySize      int
		expectedBits int
	}{
		{"P-256", 256, 256},
		{"P-384", 384, 384},
		{"P-521", 521, 521},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &ServerKeyGenConfig{
				Enabled:        true,
				DefaultKeyType: "ecdsa",
				DefaultKeySize: tt.keySize,
				DefaultMount:   "pki",
				MaxCSRSize:     4096,
				DefaultPolicy: LabelPolicy{
					Type:  "role",
					Value: "test-role",
				},
			}

			handler := NewServerKeyGenHandler(mockBackend, mockAuth, config, logger, nil)

			csrPEM := createTestCSRPEM(t, "test.example.com")
			req := httptest.NewRequest(http.MethodPost, "/.well-known/est/serverkeygen", bytes.NewReader(csrPEM))
			req.Header.Set("Authorization", "Bearer test-token")
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(body))
			}

			// Parse multipart to get private key
			_, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
			if err != nil {
				t.Fatalf("Failed to parse Content-Type: %v", err)
			}

			mr := multipart.NewReader(resp.Body, params["boundary"])

			// Skip certificate part
			_, err = mr.NextPart()
			if err != nil {
				t.Fatalf("Failed to read first part: %v", err)
			}

			// Read private key part
			part2, err := mr.NextPart()
			if err != nil {
				t.Fatalf("Failed to read second part: %v", err)
			}

			keyData, err := io.ReadAll(part2)
			if err != nil {
				t.Fatalf("Failed to read key data: %v", err)
			}

			keyDER, err := base64.StdEncoding.DecodeString(string(keyData))
			if err != nil {
				t.Fatalf("Failed to decode private key: %v", err)
			}

			privateKey, err := x509.ParsePKCS8PrivateKey(keyDER)
			if err != nil {
				t.Fatalf("Failed to parse PKCS8 private key: %v", err)
			}

			ecKey, ok := privateKey.(*ecdsa.PrivateKey)
			if !ok {
				t.Errorf("Expected ECDSA private key, got %T", privateKey)
			}

			// Verify key size
			keyBits := ecKey.Curve.Params().BitSize
			if keyBits != tt.expectedBits {
				t.Errorf("Expected %d-bit ECDSA key, got %d bits", tt.expectedBits, keyBits)
			}
		})
	}
}

func TestServerKeyGenHandler_Authentication(t *testing.T) {
	logger := slog.Default()
	mockBackend := &mockServerKeyGenBackend{}

	tests := []struct {
		name           string
		authHeader     string
		mockAuth       *auth.Manager
		expectedStatus int
	}{
		{
			name:           "No authentication",
			authHeader:     "",
			mockAuth:       createMockAuthManager(),
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Valid token",
			authHeader:     "Bearer valid-token",
			mockAuth:       createMockAuthManager(),
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &ServerKeyGenConfig{
				Enabled:        true,
				DefaultKeyType: "rsa",
				DefaultKeySize: 2048,
				DefaultMount:   "pki",
				MaxCSRSize:     4096,
				DefaultPolicy: LabelPolicy{
					Type:  "role",
					Value: "test-role",
				},
			}

			handler := NewServerKeyGenHandler(mockBackend, tt.mockAuth, config, logger, nil)

			csrPEM := createTestCSRPEM(t, "test.example.com")
			req := httptest.NewRequest(http.MethodPost, "/.well-known/est/serverkeygen", bytes.NewReader(csrPEM))

			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == http.StatusUnauthorized {
				wwwAuth := w.Header().Get("WWW-Authenticate")
				if wwwAuth == "" {
					t.Error("Expected WWW-Authenticate header for 401 response")
				}
			}
		})
	}
}

func TestServerKeyGenHandler_MethodValidation(t *testing.T) {
	logger := slog.Default()
	mockBackend := &mockServerKeyGenBackend{}
	mockAuth := createMockAuthManager()

	config := &ServerKeyGenConfig{
		Enabled:        true,
		DefaultKeyType: "rsa",
		DefaultKeySize: 2048,
		DefaultMount:   "pki",
		MaxCSRSize:     4096,
		DefaultPolicy: LabelPolicy{
			Type:  "role",
			Value: "test-role",
		},
	}

	handler := NewServerKeyGenHandler(mockBackend, mockAuth, config, logger, nil)

	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/.well-known/est/serverkeygen", nil)
			req.Header.Set("Authorization", "Bearer test-token")
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("Expected status 405 for %s, got %d", method, w.Code)
			}
		})
	}
}

func TestServerKeyGenHandler_InvalidCSR(t *testing.T) {
	logger := slog.Default()
	mockBackend := &mockServerKeyGenBackend{}
	mockAuth := createMockAuthManager()

	config := &ServerKeyGenConfig{
		Enabled:        true,
		DefaultKeyType: "rsa",
		DefaultKeySize: 2048,
		DefaultMount:   "pki",
		MaxCSRSize:     4096,
		DefaultPolicy: LabelPolicy{
			Type:  "role",
			Value: "test-role",
		},
	}

	handler := NewServerKeyGenHandler(mockBackend, mockAuth, config, logger, nil)

	tests := []struct {
		name           string
		body           []byte
		expectedStatus int
	}{
		{
			name:           "Empty body",
			body:           []byte{},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Invalid base64",
			body:           []byte("not-valid-base64!!!"),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Invalid CSR",
			body:           []byte(base64.StdEncoding.EncodeToString([]byte("invalid csr data"))),
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/.well-known/est/serverkeygen", bytes.NewReader(tt.body))
			req.Header.Set("Authorization", "Bearer test-token")
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

func TestServerKeyGenHandler_KeySizeRestrictions(t *testing.T) {
	logger := slog.Default()
	mockBackend := &mockServerKeyGenBackend{}
	mockAuth := createMockAuthManager()

	tests := []struct {
		name         string
		keyType      string
		keySize      int
		allowedSizes []int
		expectError  bool
	}{
		{
			name:         "RSA 2048 allowed",
			keyType:      "rsa",
			keySize:      2048,
			allowedSizes: []int{2048, 3072, 4096},
			expectError:  false,
		},
		{
			name:         "RSA 1024 rejected",
			keyType:      "rsa",
			keySize:      1024,
			allowedSizes: []int{2048, 3072, 4096},
			expectError:  true,
		},
		{
			name:         "ECDSA P-256 allowed",
			keyType:      "ecdsa",
			keySize:      256,
			allowedSizes: []int{256, 384},
			expectError:  false,
		},
		{
			name:         "ECDSA P-521 rejected",
			keyType:      "ecdsa",
			keySize:      521,
			allowedSizes: []int{256, 384},
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &ServerKeyGenConfig{
				Enabled:         true,
				DefaultKeyType:  tt.keyType,
				DefaultKeySize:  tt.keySize,
				DefaultMount:    "pki",
				MaxCSRSize:      4096,
				AllowedKeySizes: tt.allowedSizes,
				DefaultPolicy: LabelPolicy{
					Type:  "role",
					Value: "test-role",
				},
			}

			handler := NewServerKeyGenHandler(mockBackend, mockAuth, config, logger, nil)

			csrPEM := createTestCSRPEM(t, "test.example.com")
			req := httptest.NewRequest(http.MethodPost, "/.well-known/est/serverkeygen", bytes.NewReader(csrPEM))
			req.Header.Set("Authorization", "Bearer test-token")
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if tt.expectError {
				if w.Code == http.StatusOK {
					t.Error("Expected error for disallowed key size, but got 200 OK")
				}
			} else {
				if w.Code != http.StatusOK {
					body, _ := io.ReadAll(w.Body)
					t.Errorf("Expected success for allowed key size, got %d: %s", w.Code, string(body))
				}
			}
		})
	}
}

func TestServerKeyGenHandler_KeyTypeRestrictions(t *testing.T) {
	logger := slog.Default()
	mockBackend := &mockServerKeyGenBackend{}
	mockAuth := createMockAuthManager()

	tests := []struct {
		name          string
		keyType       string
		keySize       int
		allowedTypes  []string
		expectSuccess bool
	}{
		{
			name:          "RSA allowed",
			keyType:       "rsa",
			keySize:       2048,
			allowedTypes:  []string{"rsa", "ecdsa"},
			expectSuccess: true,
		},
		{
			name:          "ECDSA allowed",
			keyType:       "ecdsa",
			keySize:       256,
			allowedTypes:  []string{"rsa", "ecdsa"},
			expectSuccess: true,
		},
		{
			name:          "RSA rejected when only ECDSA allowed",
			keyType:       "rsa",
			keySize:       2048,
			allowedTypes:  []string{"ecdsa"},
			expectSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &ServerKeyGenConfig{
				Enabled:         true,
				DefaultKeyType:  tt.keyType,
				DefaultKeySize:  tt.keySize,
				DefaultMount:    "pki",
				MaxCSRSize:      4096,
				AllowedKeyTypes: tt.allowedTypes,
				DefaultPolicy: LabelPolicy{
					Type:  "role",
					Value: "test-role",
				},
			}

			handler := NewServerKeyGenHandler(mockBackend, mockAuth, config, logger, nil)

			csrPEM := createTestCSRPEM(t, "test.example.com")
			req := httptest.NewRequest(http.MethodPost, "/.well-known/est/serverkeygen", bytes.NewReader(csrPEM))
			req.Header.Set("Authorization", "Bearer test-token")
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if tt.expectSuccess {
				if w.Code != http.StatusOK {
					body, _ := io.ReadAll(w.Body)
					t.Errorf("Expected 200 OK, got %d: %s", w.Code, string(body))
				}
			} else {
				if w.Code == http.StatusOK {
					t.Error("Expected error for disallowed key type, but got 200 OK")
				}
			}
		})
	}
}

// Helper functions

func createTestCSRPEM(t *testing.T, commonName string) []byte {
	t.Helper()

	// Generate temporary key for CSR
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames: []string{commonName},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	// Encode as PEM then base64 (EST format)
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return []byte(base64.StdEncoding.EncodeToString(csrPEM))
}

func createMockCertificate(csr *x509.CertificateRequest) *x509.Certificate {
	return &x509.Certificate{
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		SerialNumber: big.NewInt(12345),
	}
}

func createMockAuthManager() *auth.Manager {
	// Create a minimal mock backend for auth
	mockBackend := &mockServerKeyGenBackend{
		validateTokenFunc: func(ctx context.Context, token string) (bool, error) {
			return true, nil
		},
	}

	// Create auth config that enables token authentication
	config := &auth.Config{
		TokenEnabled: true,
	}

	return auth.NewManager(mockBackend, config, slog.Default())
}

// Tests for encrypted private key generation (Issue 1.3 - Security)

func TestServerKeyGenHandler_EncryptedPrivateKey(t *testing.T) {
	logger := slog.Default()
	mockBackend := &mockServerKeyGenBackend{}
	mockAuth := createMockAuthManager()

	// Generate a test client certificate for password encryption
	clientCert, clientKey := createTestClientCertificate(t)

	config := &ServerKeyGenConfig{
		Enabled:           true,
		EncryptPrivateKey: true, // Enable encryption
		DefaultKeyType:    "rsa",
		DefaultKeySize:    2048,
		DefaultMount:      "pki",
		MaxCSRSize:        4096,
		DefaultPolicy: LabelPolicy{
			Type:  "role",
			Value: "test-role",
		},
	}

	handler := NewServerKeyGenHandler(mockBackend, mockAuth, config, logger, nil)

	csrPEM := createTestCSRPEM(t, "test.example.com")
	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/serverkeygen", bytes.NewReader(csrPEM))
	req.Header.Set("Authorization", "Bearer test-token")

	// Add client certificate to TLS state
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{clientCert},
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(body))
	}

	// Parse multipart response
	_, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("Failed to parse Content-Type: %v", err)
	}

	mr := multipart.NewReader(resp.Body, params["boundary"])

	// Part 1: Certificate (skip for this test)
	_, err = mr.NextPart()
	if err != nil {
		t.Fatalf("Failed to read certificate part: %v", err)
	}

	// Part 2: Encrypted private key
	part2, err := mr.NextPart()
	if err != nil {
		t.Fatalf("Failed to read private key part: %v", err)
	}

	keyContentType := part2.Header.Get("Content-Type")
	if !strings.Contains(keyContentType, "pkcs8-encrypted") {
		t.Errorf("Expected application/pkcs8-encrypted content type, got %s", keyContentType)
	}

	encryptedKeyData, err := io.ReadAll(part2)
	if err != nil {
		t.Fatalf("Failed to read encrypted key data: %v", err)
	}

	if len(encryptedKeyData) == 0 {
		t.Fatal("Encrypted key data is empty")
	}

	// Part 3: Encrypted password
	part3, err := mr.NextPart()
	if err != nil {
		t.Fatalf("Failed to read encrypted password part: %v", err)
	}

	passwordContentType := part3.Header.Get("Content-Type")
	if !strings.Contains(passwordContentType, "application/octet-stream") {
		t.Errorf("Expected application/octet-stream content type for password, got %s", passwordContentType)
	}

	encryptedPasswordData, err := io.ReadAll(part3)
	if err != nil {
		t.Fatalf("Failed to read encrypted password data: %v", err)
	}

	if len(encryptedPasswordData) == 0 {
		t.Fatal("Encrypted password data is empty")
	}

	// Decode base64 data
	encryptedKeyDER, err := base64.StdEncoding.DecodeString(string(encryptedKeyData))
	if err != nil {
		t.Fatalf("Failed to decode encrypted key: %v", err)
	}

	encryptedPassword, err := base64.StdEncoding.DecodeString(string(encryptedPasswordData))
	if err != nil {
		t.Fatalf("Failed to decode encrypted password: %v", err)
	}

	// Decrypt password using client's private key
	password, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, clientKey, encryptedPassword, nil)
	if err != nil {
		t.Fatalf("Failed to decrypt password: %v", err)
	}

	if len(password) != 32 {
		t.Errorf("Expected 32-byte password, got %d bytes", len(password))
	}

	// Decrypt the private key using the password
	pemBlock, _ := pem.Decode(encryptedKeyDER)
	if pemBlock == nil {
		t.Fatal("Failed to decode PEM block")
	}

	if pemBlock.Type != "ENCRYPTED PRIVATE KEY" {
		t.Errorf("Expected ENCRYPTED PRIVATE KEY type, got %s", pemBlock.Type)
	}

	// Check encryption method in PEM headers
	if encMethod := pemBlock.Headers["Encryption"]; encMethod != "AES-256-GCM" {
		t.Errorf("Expected AES-256-GCM encryption, got %s", encMethod)
	}

	// Decrypt using AES-GCM (modern authenticated encryption)
	decryptedDER, err := decryptWithAESGCM(pemBlock.Bytes, password)
	if err != nil {
		t.Fatalf("Failed to decrypt private key: %v", err)
	}

	// Parse decrypted private key
	privateKey, err := x509.ParsePKCS8PrivateKey(decryptedDER)
	if err != nil {
		t.Fatalf("Failed to parse decrypted private key: %v", err)
	}

	// Verify it's an RSA key
	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		t.Errorf("Expected RSA private key, got %T", privateKey)
	}

	if rsaKey.N.BitLen() != 2048 {
		t.Errorf("Expected 2048-bit RSA key, got %d bits", rsaKey.N.BitLen())
	}

	t.Log("Successfully decrypted and verified encrypted private key")
}

func TestServerKeyGenHandler_UnencryptedFallback(t *testing.T) {
	logger := slog.Default()
	mockBackend := &mockServerKeyGenBackend{}
	mockAuth := createMockAuthManager()

	config := &ServerKeyGenConfig{
		Enabled:           true,
		EncryptPrivateKey: false, // Encryption disabled
		DefaultKeyType:    "rsa",
		DefaultKeySize:    2048,
		DefaultMount:      "pki",
		MaxCSRSize:        4096,
		DefaultPolicy: LabelPolicy{
			Type:  "role",
			Value: "test-role",
		},
	}

	handler := NewServerKeyGenHandler(mockBackend, mockAuth, config, logger, nil)

	csrPEM := createTestCSRPEM(t, "test.example.com")
	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/serverkeygen", bytes.NewReader(csrPEM))
	req.Header.Set("Authorization", "Bearer test-token")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(body))
	}

	// Parse multipart response
	_, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("Failed to parse Content-Type: %v", err)
	}

	mr := multipart.NewReader(resp.Body, params["boundary"])

	// Part 1: Certificate (skip)
	_, err = mr.NextPart()
	if err != nil {
		t.Fatalf("Failed to read certificate part: %v", err)
	}

	// Part 2: Private key (should be unencrypted PKCS#8)
	part2, err := mr.NextPart()
	if err != nil {
		t.Fatalf("Failed to read private key part: %v", err)
	}

	keyContentType := part2.Header.Get("Content-Type")
	// Should be application/pkcs8, NOT pkcs8-encrypted
	if strings.Contains(keyContentType, "pkcs8-encrypted") {
		t.Errorf("Expected unencrypted application/pkcs8 content type, got %s", keyContentType)
	}

	keyData, err := io.ReadAll(part2)
	if err != nil {
		t.Fatalf("Failed to read key data: %v", err)
	}

	// Decode and verify it's an unencrypted PKCS#8 key
	keyDER, err := base64.StdEncoding.DecodeString(string(keyData))
	if err != nil {
		t.Fatalf("Failed to decode private key: %v", err)
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		t.Fatalf("Failed to parse unencrypted PKCS8 private key: %v", err)
	}

	_, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		t.Errorf("Expected RSA private key, got %T", privateKey)
	}

	// Part 3: Should not exist (no encrypted password)
	_, err = mr.NextPart()
	if err != io.EOF {
		t.Error("Expected only 2 parts for unencrypted mode, found 3rd part")
	}
}

// createTestClientCertificate creates a self-signed RSA certificate for testing
func createTestClientCertificate(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate client key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-client",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create client certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse client certificate: %v", err)
	}

	return cert, privateKey
}
