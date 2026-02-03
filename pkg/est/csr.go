package est

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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

// OID for ChangeSubjectName attribute per RFC 6402 Section 6
var oidChangeSubjectName = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 9, 8}

// ValidateReenrollmentSubject validates that the CSR Subject and SubjectAltName match
// the existing certificate per RFC 7030 Section 4.2.2, unless the ChangeSubjectName
// attribute is present in the CSR.
//
// RFC 7030 Section 4.2.2 states:
// "The request Subject field and SubjectAltName extension MUST be identical to the
// corresponding fields in the certificate being renewed/rekeyed. The ChangeSubjectName
// attribute, as defined in [RFC6402], MAY be included in the CSR to request that these
// fields be changed in the new certificate."
func ValidateReenrollmentSubject(csr *x509.CertificateRequest, existingCert *x509.Certificate) error {
	// Check if ChangeSubjectName attribute is present in CSR
	hasChangeSubjectName := false
	for _, attr := range csr.Attributes {
		if attr.Type.Equal(oidChangeSubjectName) {
			hasChangeSubjectName = true
			break
		}
	}

	// If ChangeSubjectName is present, allow subject changes
	if hasChangeSubjectName {
		return nil
	}

	// Validate Subject field matches
	if csr.Subject.String() != existingCert.Subject.String() {
		return fmt.Errorf("CSR Subject (%s) does not match existing certificate Subject (%s); include ChangeSubjectName attribute to request subject changes",
			csr.Subject.String(), existingCert.Subject.String())
	}

	// Validate SubjectAltName extension matches
	if err := validateSubjectAltNameMatch(csr, existingCert); err != nil {
		return err
	}

	return nil
}

// validateSubjectAltNameMatch checks that the SubjectAltName extension in the CSR
// matches the SubjectAltName in the existing certificate
func validateSubjectAltNameMatch(csr *x509.CertificateRequest, cert *x509.Certificate) error {
	// Extract SAN from CSR and certificate
	csrDNSNames := csr.DNSNames
	csrEmailAddresses := csr.EmailAddresses
	csrIPAddresses := csr.IPAddresses
	csrURIs := csr.URIs

	certDNSNames := cert.DNSNames
	certEmailAddresses := cert.EmailAddresses
	certIPAddresses := cert.IPAddresses
	certURIs := cert.URIs

	// Compare DNS names
	if !stringSlicesEqual(csrDNSNames, certDNSNames) {
		return fmt.Errorf("CSR DNS names (%v) do not match certificate DNS names (%v)",
			csrDNSNames, certDNSNames)
	}

	// Compare email addresses
	if !stringSlicesEqual(csrEmailAddresses, certEmailAddresses) {
		return fmt.Errorf("CSR email addresses (%v) do not match certificate email addresses (%v)",
			csrEmailAddresses, certEmailAddresses)
	}

	// Compare IP addresses
	if !ipSlicesEqual(csrIPAddresses, certIPAddresses) {
		return fmt.Errorf("CSR IP addresses (%v) do not match certificate IP addresses (%v)",
			csrIPAddresses, certIPAddresses)
	}

	// Compare URIs
	if !uriSlicesEqual(csrURIs, certURIs) {
		return fmt.Errorf("CSR URIs (%v) do not match certificate URIs (%v)",
			csrURIs, certURIs)
	}

	return nil
}

// stringSlicesEqual checks if two string slices contain the same elements (order-independent)
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	// Create maps to count occurrences
	aMap := make(map[string]int)
	bMap := make(map[string]int)

	for _, s := range a {
		aMap[s]++
	}
	for _, s := range b {
		bMap[s]++
	}

	// Compare maps
	if len(aMap) != len(bMap) {
		return false
	}

	for k, v := range aMap {
		if bMap[k] != v {
			return false
		}
	}

	return true
}

// ipSlicesEqual checks if two IP address slices contain the same elements (order-independent)
func ipSlicesEqual(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}

	// Convert to strings for comparison
	aStrs := make([]string, len(a))
	bStrs := make([]string, len(b))

	for i, ip := range a {
		aStrs[i] = ip.String()
	}
	for i, ip := range b {
		bStrs[i] = ip.String()
	}

	return stringSlicesEqual(aStrs, bStrs)
}

// uriSlicesEqual checks if two URI slices contain the same elements (order-independent)
func uriSlicesEqual(a, b []*url.URL) bool {
	if len(a) != len(b) {
		return false
	}

	// Convert to strings for comparison
	aStrs := make([]string, len(a))
	bStrs := make([]string, len(b))

	for i, u := range a {
		aStrs[i] = u.String()
	}
	for i, u := range b {
		bStrs[i] = u.String()
	}

	return stringSlicesEqual(aStrs, bStrs)
}
