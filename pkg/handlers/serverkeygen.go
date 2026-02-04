package handlers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/mabunixda/est-service/pkg/auth"
	"github.com/mabunixda/est-service/pkg/backend"
	"github.com/mabunixda/est-service/pkg/est"
)

// ServerKeyGenHandler handles POST /.well-known/est/serverkeygen
// RFC 7030 Section 4.4 - Server-Side Key Generation
type ServerKeyGenHandler struct {
	backend   backend.Backend
	authMgr   *auth.Manager
	config    *ServerKeyGenConfig
	logger    *slog.Logger
	telemetry Telemetry
}

// ServerKeyGenConfig configures server-side key generation
type ServerKeyGenConfig struct {
	Enabled              bool
	DefaultKeyType       string // "rsa" or "ecdsa"
	DefaultKeySize       int    // RSA: 2048, 3072, 4096; ECDSA: 256, 384, 521
	DefaultMount         string
	Labels               map[string]LabelPolicy
	DefaultPolicy        LabelPolicy
	MaxCSRSize           int64
	AllowedKeyTypes      []string // ["rsa", "ecdsa"] - empty means all
	AllowedKeySizes      []int    // [2048, 3072, 4096, 256, 384, 521] - empty means all
	UseAuthToken         bool
	EncryptPrivateKey    bool   // If true, encrypt private key in PKCS#8
	UseVaultTransit      bool   // If true, use Vault/OpenBao Transit engine for key generation
	TransitMount         string // Transit engine mount path (default: "transit")
	TransitKeyNamePrefix string // Optional prefix for Transit key names (default: "temp-keygen-")
}

// ServerKeyGenRequest represents the parsed server-side key generation request
type ServerKeyGenRequest struct {
	CSR          *x509.CertificateRequest
	Label        string
	AuthToken    string
	AuthMethod   string
	AuthIdentity string
	Policy       LabelPolicy
}

// EncryptedPrivateKey contains an encrypted private key and the encrypted password
type EncryptedPrivateKey struct {
	EncryptedKeyDER   []byte // PEM-encrypted PKCS#8 private key
	EncryptedPassword []byte // Password encrypted with client's public key
	PasswordEncrypted bool   // True if password encryption was successful
}

// NewServerKeyGenHandler creates a new server-side key generation handler
func NewServerKeyGenHandler(backend backend.Backend, authMgr *auth.Manager, config *ServerKeyGenConfig, logger *slog.Logger, telemetry Telemetry) *ServerKeyGenHandler {
	if logger == nil {
		logger = slog.Default()
	}
	if telemetry == nil {
		telemetry = &NoOpTelemetry{}
	}
	if config.MaxCSRSize == 0 {
		config.MaxCSRSize = DefaultServerKeyGenCSRMaxSize
	}
	if config.DefaultKeyType == "" {
		config.DefaultKeyType = "rsa"
	}
	if config.DefaultKeySize == 0 {
		if config.DefaultKeyType == "rsa" {
			config.DefaultKeySize = DefaultRSAKeySize
		} else {
			config.DefaultKeySize = DefaultECDSAKeySize
		}
	}

	// Set Transit defaults if using Vault Transit
	if config.UseVaultTransit {
		if config.TransitMount == "" {
			config.TransitMount = "transit"
		}
		if config.TransitKeyNamePrefix == "" {
			config.TransitKeyNamePrefix = "temp-keygen-"
		}
	}

	return &ServerKeyGenHandler{
		backend:   backend,
		authMgr:   authMgr,
		config:    config,
		logger:    logger,
		telemetry: telemetry,
	}
}

// ServeHTTP handles the server-side key generation request
// @Summary Server-Side Key Generation
// @Description Generates a key pair on the server and returns both the certificate and encrypted private key. Per RFC 7030 Section 4.4, this is an optional feature for scenarios where client-side key generation is not feasible.
// @Tags EST
// @Accept application/pkcs10
// @Produce application/multipart-core
// @Param body body string true "Certificate request attributes in PKCS#10 format (base64)"
// @Success 200 {string} string "Multipart response with certificate and private key"
// @Failure 400 {string} string "Invalid request"
// @Failure 401 {string} string "Authentication required"
// @Failure 403 {string} string "Permission denied"
// @Failure 500 {string} string "Server error"
// @Router /.well-known/est/serverkeygen [post]
func (h *ServerKeyGenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.logger.Debug("Invalid method for /serverkeygen", "method", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	// Authenticate request
	authResult := h.authMgr.Authenticate(ctx, r)
	if !authResult.Authenticated {
		h.logger.Warn("Authentication failed for serverkeygen", "error", authResult.Error)
		// Set WWW-Authenticate headers
		for _, header := range h.authMgr.GetWWWAuthenticateHeaders() {
			w.Header().Add("WWW-Authenticate", header)
		}
		if authResult.Error != nil {
			h.telemetry.RecordAuthFailure(ctx, authResult.Method, authResult.Error.Error())
		}
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	h.telemetry.RecordAuthSuccess(ctx, authResult.Method, authResult.Identity)

	// Parse request
	req, err := h.parseServerKeyGenRequest(r, authResult)
	if err != nil {
		if errors.Is(err, est.ErrRequestTooLarge) {
			h.logger.Error("CSR request too large", "error", err)
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		h.logger.Error("Failed to parse serverkeygen request", "error", err)
		h.telemetry.RecordCertificateRejected(ctx, "serverkeygen", err.Error())
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	h.logger.Info("Processing serverkeygen request",
		"subject", req.CSR.Subject.CommonName,
		"auth_method", req.AuthMethod,
		"auth_identity", req.AuthIdentity,
		"label", req.Label)

	// Generate key pair
	privateKey, _, err := h.generateKeyPair()
	if err != nil {
		h.logger.Error("Failed to generate key pair", "error", err)
		h.telemetry.RecordCertificateRejected(ctx, "serverkeygen", err.Error())
		http.Error(w, "Failed to generate key pair", http.StatusInternalServerError)
		return
	}

	// Create new CSR with generated public key
	// Note: We don't set SignatureAlgorithm here because x509.CreateCertificateRequest
	// will automatically choose the appropriate algorithm based on the private key type
	csrTemplate := &x509.CertificateRequest{
		Subject:         req.CSR.Subject,
		DNSNames:        req.CSR.DNSNames,
		EmailAddresses:  req.CSR.EmailAddresses,
		IPAddresses:     req.CSR.IPAddresses,
		URIs:            req.CSR.URIs,
		ExtraExtensions: req.CSR.ExtraExtensions,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	if err != nil {
		h.logger.Error("Failed to create CSR with generated key", "error", err)
		h.telemetry.RecordCertificateRejected(ctx, "serverkeygen", err.Error())
		http.Error(w, "Failed to create CSR", http.StatusInternalServerError)
		return
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		h.logger.Error("Failed to parse generated CSR", "error", err)
		h.telemetry.RecordCertificateRejected(ctx, "serverkeygen", err.Error())
		http.Error(w, "Failed to parse CSR", http.StatusInternalServerError)
		return
	}

	// Sign CSR using backend
	enrollReq := &EnrollmentRequest{
		CSR:          csr,
		Label:        req.Label,
		IsReenroll:   false,
		AuthToken:    req.AuthToken,
		AuthMethod:   req.AuthMethod,
		AuthIdentity: req.AuthIdentity,
		Policy:       req.Policy,
	}

	cert, err := processCSRSigning(ctx, h.backend, enrollReq, &EnrollmentConfig{
		DefaultMount:          h.config.DefaultMount,
		Labels:                convertToLabelPolicyMap(h.config.Labels),
		DefaultPolicy:         h.config.DefaultPolicy,
		UseAuthenticatedToken: h.config.UseAuthToken,
	})
	if err != nil {
		h.logger.Error("Failed to sign CSR", "error", err)
		SendBackendError(w, err, "certificate signing")
		h.telemetry.RecordCertificateRejected(ctx, "serverkeygen", err.Error())
		return
	}

	// Encode private key (PKCS#8 format, encrypted if configured)
	var clientCert *x509.Certificate
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		clientCert = r.TLS.PeerCertificates[0]
	}

	encryptedKey, err := h.encodePrivateKey(privateKey, clientCert)
	if err != nil {
		h.logger.Error("Failed to encode private key", "error", err)
		h.telemetry.RecordCertificateRejected(ctx, "serverkeygen", err.Error())
		http.Error(w, "Failed to encode private key", http.StatusInternalServerError)
		return
	}

	// Create multipart response per RFC 7030 Section 4.4.2
	err = h.sendServerKeyGenResponse(w, cert, encryptedKey)
	if err != nil {
		h.logger.Error("Failed to send response", "error", err)
		return
	}

	h.telemetry.RecordCertificateIssued(ctx, "serverkeygen",
		cert.Subject.CommonName,
		cert.SerialNumber.String(),
		cert.NotAfter.Sub(cert.NotBefore).String())

	h.logger.Info("Server-side key generation successful",
		"subject", cert.Subject.CommonName,
		"serial", cert.SerialNumber.String(),
		"key_type", h.config.DefaultKeyType,
		"key_size", h.config.DefaultKeySize)
}

// parseServerKeyGenRequest parses the incoming server key generation request
func (h *ServerKeyGenHandler) parseServerKeyGenRequest(r *http.Request, authResult *auth.Result) (*ServerKeyGenRequest, error) {
	// Parse CSR from request body
	csr, err := est.ReadCSRPayloadWithLimit(r, h.config.MaxCSRSize)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	// Extract label from path (e.g., /.well-known/est/label/serverkeygen)
	label := extractLabel(r.URL.Path, "serverkeygen")

	// Determine policy
	policy := h.config.DefaultPolicy
	if label != "" {
		if labelPolicy, ok := h.config.Labels[label]; ok {
			policy = labelPolicy
		}
	}

	return &ServerKeyGenRequest{
		CSR:          csr,
		Label:        label,
		AuthToken:    authResult.Token,
		AuthMethod:   authResult.Method,
		AuthIdentity: authResult.Identity,
		Policy:       policy,
	}, nil
}

// generateKeyPair generates a new key pair based on configuration
func (h *ServerKeyGenHandler) generateKeyPair() (crypto.PrivateKey, crypto.PublicKey, error) {
	keyType := strings.ToLower(h.config.DefaultKeyType)

	// Validate key type if restrictions are configured
	if len(h.config.AllowedKeyTypes) > 0 {
		allowed := false
		for _, allowedType := range h.config.AllowedKeyTypes {
			if strings.EqualFold(allowedType, keyType) {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, nil, fmt.Errorf("key type %s not allowed", keyType)
		}
	}

	// Use Vault/OpenBao Transit engine if configured
	if h.config.UseVaultTransit {
		return h.generateKeyPairViaTransit(keyType)
	}

	// Fallback to local key generation
	switch keyType {
	case "rsa":
		return h.generateRSAKeyPair()
	case "ecdsa", "ec":
		return h.generateECDSAKeyPair()
	default:
		return nil, nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// generateKeyPairViaTransit generates a key pair using Vault/OpenBao Transit engine
func (h *ServerKeyGenHandler) generateKeyPairViaTransit(keyType string) (crypto.PrivateKey, crypto.PublicKey, error) {
	ctx := context.Background()

	h.logger.Debug("Generating key pair via Vault Transit engine",
		"key_type", keyType,
		"key_bits", h.config.DefaultKeySize,
		"transit_mount", h.config.TransitMount)

	privateKey, publicKey, err := h.backend.GenerateExportableKey(
		ctx,
		h.config.TransitMount,
		keyType,
		h.config.DefaultKeySize,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key via Transit: %w", err)
	}

	h.logger.Info("Successfully generated key pair via Vault Transit",
		"key_type", keyType,
		"key_bits", h.config.DefaultKeySize)

	return privateKey, publicKey, nil
}

// generateRSAKeyPair generates an RSA key pair locally
func (h *ServerKeyGenHandler) generateRSAKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	keySize := h.config.DefaultKeySize

	// Validate key size if restrictions are configured
	if len(h.config.AllowedKeySizes) > 0 {
		allowed := false
		for _, allowedSize := range h.config.AllowedKeySizes {
			if allowedSize == keySize {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, nil, fmt.Errorf("RSA key size %d not allowed", keySize)
		}
	}

	// Security check: enforce minimum RSA key size
	if keySize < MinRSAKeySize {
		return nil, nil, fmt.Errorf("RSA key size must be at least %d bits", MinRSAKeySize)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	return privateKey, &privateKey.PublicKey, nil
}

// generateECDSAKeyPair generates an ECDSA key pair
func (h *ServerKeyGenHandler) generateECDSAKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	keySize := h.config.DefaultKeySize

	// Validate key size if restrictions are configured
	if len(h.config.AllowedKeySizes) > 0 {
		allowed := false
		for _, allowedSize := range h.config.AllowedKeySizes {
			if allowedSize == keySize {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, nil, fmt.Errorf("ECDSA key size %d not allowed", keySize)
		}
	}

	var curve elliptic.Curve
	switch keySize {
	case ECDSACurveP256:
		curve = elliptic.P256()
	case ECDSACurveP384:
		curve = elliptic.P384()
	case ECDSACurveP521:
		curve = elliptic.P521()
	default:
		return nil, nil, fmt.Errorf("unsupported ECDSA key size: %d (must be %s)", keySize, ValidECDSACurveSizesString())
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	return privateKey, &privateKey.PublicKey, nil
}

// encodePrivateKey encodes the private key in PKCS#8 format with optional encryption
func (h *ServerKeyGenHandler) encodePrivateKey(privateKey crypto.PrivateKey, clientCert *x509.Certificate) (*EncryptedPrivateKey, error) {
	// Marshal to PKCS#8 format first
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	result := &EncryptedPrivateKey{
		PasswordEncrypted: false,
	}

	// If encryption is not enabled, return unencrypted key
	// SECURITY WARNING: This transmits private keys in plaintext!
	if !h.config.EncryptPrivateKey {
		h.logger.Warn("Returning UNENCRYPTED private key - encrypt_private_key is disabled")
		result.EncryptedKeyDER = pkcs8DER
		return result, nil
	}

	// Generate a random password for AES-256 encryption
	password := make([]byte, AES256KeySizeBytes)
	if _, err := rand.Read(password); err != nil {
		return nil, fmt.Errorf("failed to generate encryption password: %w", err)
	}

	// Create PEM block with PKCS#8 data
	pemBlock := &pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: pkcs8DER,
	}

	// Encrypt the PEM block using AES-256-CBC
	encryptedPEM, err := x509.EncryptPEMBlock(rand.Reader, pemBlock.Type, pemBlock.Bytes, password, x509.PEMCipherAES256)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	// Encode the encrypted PEM block to DER format for transmission
	result.EncryptedKeyDER = pem.EncodeToMemory(encryptedPEM)

	// Encrypt the password using the client's certificate public key (hybrid encryption)
	if clientCert != nil {
		encryptedPassword, err := h.encryptPasswordForClient(password, clientCert)
		if err != nil {
			h.logger.Warn("Failed to encrypt password with client certificate", "error", err)
			// Continue without password encryption - client won't be able to decrypt the key
		} else {
			result.EncryptedPassword = encryptedPassword
			result.PasswordEncrypted = true
		}
	} else {
		h.logger.Warn("No client certificate available for password encryption")
	}

	return result, nil
}

// encryptPasswordForClient encrypts the password using the client's certificate public key
func (h *ServerKeyGenHandler) encryptPasswordForClient(password []byte, clientCert *x509.Certificate) ([]byte, error) {
	publicKey := clientCert.PublicKey

	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		// Use RSA-OAEP with SHA-256 for encryption
		encryptedPassword, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, password, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt password with RSA: %w", err)
		}
		return encryptedPassword, nil

	case *ecdsa.PublicKey:
		// ECDSA keys don't support direct encryption
		// We would need to use ECIES (Elliptic Curve Integrated Encryption Scheme)
		// For now, return error and fall back to unencrypted password delivery
		return nil, fmt.Errorf("ECDSA client certificates not supported for password encryption (ECIES not implemented)")

	default:
		return nil, fmt.Errorf("unsupported client certificate public key type: %T", pub)
	}
}

// sendServerKeyGenResponse sends the multipart response with certificate and private key
// RFC 7030 Section 4.4.2 specifies a multipart/mixed response with:
// 1. application/pkcs7-mime (certificate)
// 2. application/pkcs8 (private key - encrypted if configured)
// 3. application/octet-stream (encrypted password - only if password encryption succeeded)
func (h *ServerKeyGenHandler) sendServerKeyGenResponse(w http.ResponseWriter, cert *x509.Certificate, encryptedKey *EncryptedPrivateKey) error {
	// Create PKCS#7 certs-only structure for the certificate
	pkcs7Cert, err := est.CreatePKCS7CertsOnly([]*x509.Certificate{cert})
	if err != nil {
		return fmt.Errorf("failed to create PKCS#7: %w", err)
	}

	// Base64 encode certificate and key
	certB64 := base64.StdEncoding.EncodeToString(pkcs7Cert)
	keyB64 := base64.StdEncoding.EncodeToString(encryptedKey.EncryptedKeyDER)

	// RFC 7030 Section 4.4.2: Use multipart/mixed with base64 encoding
	boundary := MultipartBoundaryServerKeyGen

	w.Header().Set("Content-Type", fmt.Sprintf("multipart/mixed; boundary=%s", boundary))
	w.WriteHeader(http.StatusOK)

	// Build multipart response
	var response strings.Builder

	// Part 1: Certificate
	response.WriteString(fmt.Sprintf(`--%s
Content-Type: application/pkcs7-mime; smime-type=certs-only
Content-Transfer-Encoding: base64

%s
`, boundary, certB64))

	// Part 2: Private key (encrypted or unencrypted)
	keyContentType := "application/pkcs8"
	if h.config.EncryptPrivateKey {
		keyContentType = "application/pkcs8-encrypted"
	}
	response.WriteString(fmt.Sprintf(`--%s
Content-Type: %s
Content-Transfer-Encoding: base64

%s
`, boundary, keyContentType, keyB64))

	// Part 3: Encrypted password (only if encryption succeeded)
	if encryptedKey.PasswordEncrypted && len(encryptedKey.EncryptedPassword) > 0 {
		passwordB64 := base64.StdEncoding.EncodeToString(encryptedKey.EncryptedPassword)
		response.WriteString(fmt.Sprintf(`--%s
Content-Type: application/octet-stream
Content-Description: encrypted-key-password
Content-Transfer-Encoding: base64

%s
`, boundary, passwordB64))
	}

	// Final boundary
	response.WriteString(fmt.Sprintf(`--%s--
`, boundary))

	if _, err := w.Write([]byte(response.String())); err != nil {
		return fmt.Errorf("failed to write response: %w", err)
	}

	return nil
}

// convertToLabelPolicyMap converts map[string]LabelPolicy to the format needed by EnrollmentConfig
func convertToLabelPolicyMap(labels map[string]LabelPolicy) map[string]LabelPolicy {
	// Already in the right format
	return labels
}

// extractLabel extracts the label from EST paths like /.well-known/est/label/serverkeygen
func extractLabel(path, endpoint string) string {
	// Remove /.well-known/est/ prefix
	path = strings.TrimPrefix(path, "/.well-known/est/")

	// Remove endpoint suffix
	path = strings.TrimSuffix(path, "/"+endpoint)
	path = strings.TrimSuffix(path, endpoint)

	// What remains is the label (if any)
	if path == "" || path == "/" {
		return ""
	}

	return strings.Trim(path, "/")
}
