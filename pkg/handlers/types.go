package handlers

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/mabunixda/est-service/pkg/backend"
)

// EnrollmentRequest represents a parsed EST enrollment request
type EnrollmentRequest struct {
	CSR          *x509.CertificateRequest
	ClientCert   *x509.Certificate // For reenrollment
	Label        string
	IsReenroll   bool
	AuthToken    string
	AuthMethod   string
	AuthIdentity string
	Policy       LabelPolicy // Policy to use for this request (includes TTL)
}

// EnrollmentConfig holds configuration for enrollment operations
type EnrollmentConfig struct {
	DefaultMount          string
	Labels                map[string]LabelPolicy
	DefaultPolicy         LabelPolicy
	MaxCSRSize            int64
	AllowedSignatureAlgos []string
	UseAuthenticatedToken bool // If true, use authenticated user's token for PKI operations
}

// LabelPolicy defines how a label should be processed
type LabelPolicy struct {
	Type  string // "role" or "sign-verbatim"
	Value string // role name (if type=role)
	Mount string // PKI mount to use (optional)
	TTL   string // Certificate TTL (optional)
}

// processCSRSigning handles the common CSR signing logic for both enrollment and reenrollment
func processCSRSigning(ctx context.Context, backendClient backend.Backend, req *EnrollmentRequest, config *EnrollmentConfig) (*x509.Certificate, error) {
	policy := req.Policy
	mount := policy.Mount
	if mount == "" {
		mount = config.DefaultMount
	}

	// Use the authenticated user's token for backend operations
	if req.AuthToken == "" {
		return nil, fmt.Errorf("no authentication available")
	}

	authenticatedClient, err := backendClient.CloneWithToken(ctx, req.AuthToken)
	if err != nil {
		return nil, fmt.Errorf("failed to create authenticated backend client: %w", err)
	}
	// SECURITY: Always cleanup the cloned client to scrub the token from memory
	// This minimizes the window of token exposure, especially for per-request tokens
	defer func() {
		// Best-effort cleanup - ignore errors since the original error takes precedence
		_ = authenticatedClient.Close()
	}()

	var cert *x509.Certificate

	switch policy.Type {
	case "role":
		cert, err = authenticatedClient.SignCSR(ctx, mount, policy.Value, req.CSR, req.Policy.TTL)
	case "sign-verbatim":
		cert, err = authenticatedClient.SignCSRVerbatim(ctx, mount, req.CSR, req.Policy.TTL)
	default:
		return nil, fmt.Errorf("invalid policy type: %s", policy.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to sign CSR: %w", err)
	}

	return cert, nil
}
