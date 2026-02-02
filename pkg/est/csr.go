package est

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ExtractCSRFromPKCS7 extracts a CSR from a PKCS#7 blob as required by EST.
// EST requires CSRs to be wrapped in a PKCS#7 SignedData structure with empty signatures.
func ExtractCSRFromPKCS7(data []byte) (*x509.CertificateRequest, error) {
	// Parse the PKCS#7 structure
	certs, err := ParsePKCS7(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#7: %w", err)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PKCS#7")
	}

	// The first "certificate" in the PKCS#7 structure is actually the CSR
	// encoded as a certificate request
	cert := certs[0]

	// Re-parse as a CSR
	csr, err := x509.ParseCertificateRequest(cert.Raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR from PKCS#7: %w", err)
	}

	return csr, nil
}

// ReadCSRPayload reads the CSR from an HTTP request body.
// EST requires the CSR to be base64-encoded DER format with application/pkcs10 content type.
func ReadCSRPayload(r *http.Request) (*x509.CertificateRequest, error) {
	const maxCSRSize = 10 * 1024 * 1024 // 10 MB limit
	return ReadCSRPayloadWithLimit(r, maxCSRSize)
}

// ReadCSRPayloadWithLimit reads the CSR payload with a custom max size.
func ReadCSRPayloadWithLimit(r *http.Request, maxSize int64) (*x509.CertificateRequest, error) {
	if maxSize <= 0 {
		maxSize = 10 * 1024 * 1024 // 10 MB limit
	}

	limited := io.LimitedReader{R: r.Body, N: maxSize + 1}
	body, err := io.ReadAll(&limited)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}
	if int64(len(body)) > maxSize {
		return nil, fmt.Errorf("request body too large")
	}

	// RFC 7030: CSR should be base64-encoded
	decoded, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		// If base64 decode fails, try as raw DER
		decoded = body
	}

	// Try to decode as PEM first
	if block, _ := pem.Decode(decoded); block != nil {
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PEM CSR: %w", err)
		}
		return csr, nil
	}

	// Otherwise try as raw DER
	csr, err := x509.ParseCertificateRequest(decoded)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER CSR: %w", err)
	}

	return csr, nil
}

// ValidateCSRSignatureAlgorithm ensures the CSR signature algorithm is allowed.
// If allowed is empty, all algorithms are permitted.
func ValidateCSRSignatureAlgorithm(csr *x509.CertificateRequest, allowed []string) error {
	if len(allowed) == 0 {
		return nil
	}

	allowedSet := make(map[x509.SignatureAlgorithm]struct{}, len(allowed))
	for _, name := range allowed {
		if alg, ok := parseSignatureAlgorithm(name); ok {
			allowedSet[alg] = struct{}{}
		}
	}

	if len(allowedSet) == 0 {
		return fmt.Errorf("no valid signature algorithms configured")
	}

	if _, ok := allowedSet[csr.SignatureAlgorithm]; !ok {
		return fmt.Errorf("signature algorithm not allowed: %s", csr.SignatureAlgorithm.String())
	}

	return nil
}

func parseSignatureAlgorithm(name string) (x509.SignatureAlgorithm, bool) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "MD5WITHRSA":
		return x509.MD5WithRSA, true
	case "SHA1WITHRSA":
		return x509.SHA1WithRSA, true
	case "SHA256WITHRSA":
		return x509.SHA256WithRSA, true
	case "SHA384WITHRSA":
		return x509.SHA384WithRSA, true
	case "SHA512WITHRSA":
		return x509.SHA512WithRSA, true
	case "ECDSAWITHSHA1":
		return x509.ECDSAWithSHA1, true
	case "ECDSAWITHSHA256":
		return x509.ECDSAWithSHA256, true
	case "ECDSAWITHSHA384":
		return x509.ECDSAWithSHA384, true
	case "ECDSAWITHSHA512":
		return x509.ECDSAWithSHA512, true
	default:
		return x509.UnknownSignatureAlgorithm, false
	}
}

// ValidateCSRSignature checks that the CSR's signature is valid.
func ValidateCSRSignature(csr *x509.CertificateRequest) error {
	return csr.CheckSignature()
}

// ValidateCSRMatchesCertificate checks if a CSR matches the public key in a certificate.
// This is used for re-enrollment to ensure the CSR comes from the same entity.
func ValidateCSRMatchesCertificate(csr *x509.CertificateRequest, cert *x509.Certificate) error {
	csrPubKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal CSR public key: %w", err)
	}

	certPubKey, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal certificate public key: %w", err)
	}

	if len(csrPubKey) != len(certPubKey) {
		return fmt.Errorf("public key mismatch: different key types or sizes")
	}

	for i := range csrPubKey {
		if csrPubKey[i] != certPubKey[i] {
			return fmt.Errorf("public key mismatch: CSR does not match certificate")
		}
	}

	return nil
}

// ExtractTLSClientCertificate extracts the client certificate from an HTTP request's TLS state.
// This is used for TLS client certificate authentication in EST.
func ExtractTLSClientCertificate(r *http.Request) (*x509.Certificate, error) {
	if r.TLS == nil {
		return nil, fmt.Errorf("no TLS connection state")
	}

	if len(r.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no client certificate provided")
	}

	// Return the first certificate (the client's certificate)
	// The rest of the chain is in PeerCertificates[1:]
	return r.TLS.PeerCertificates[0], nil
}
