package est

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
)

// PKCS7ContentType is the MIME type for PKCS#7 certificate responses per RFC 7030
const PKCS7ContentType = "application/pkcs7-mime; smime-type=certs-only"

// pkcs7ContentInfo is the trimmed-down PKCS#7 ContentInfo shape used for EST responses.
type pkcs7ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// pkcs7SignedData encodes the degenerate SignedData form (certificates only).
type pkcs7SignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	ContentInfo      pkcs7ContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue
}

var (
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
)

// CreatePKCS7CertsOnly creates a certs-only PKCS#7 blob for EST responses.
// This implements the degenerate PKCS#7 SignedData format required by RFC 7030.
func CreatePKCS7CertsOnly(certs []*x509.Certificate) ([]byte, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates provided")
	}

	// Convert certificates to raw DER
	var rawCerts []byte
	for _, cert := range certs {
		rawCerts = append(rawCerts, cert.Raw...)
	}

	// Create a degenerate SignedData structure (certificates only, no signature)
	signedData := pkcs7SignedData{
		Version: 1,
		DigestAlgorithms: asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      []byte{}, // Empty set
		},
		ContentInfo: pkcs7ContentInfo{
			ContentType: oidData,
		},
		Certificates: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      rawCerts,
		},
		SignerInfos: asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      []byte{}, // Empty set
		},
	}

	// Marshal the SignedData
	signedDataBytes, err := asn1.Marshal(signedData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SignedData: %w", err)
	}

	// Wrap in ContentInfo
	contentInfo := pkcs7ContentInfo{
		ContentType: oidSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      signedDataBytes,
		},
	}

	// Marshal the ContentInfo
	der, err := asn1.Marshal(contentInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ContentInfo: %w", err)
	}

	return der, nil
}

// ParsePKCS7 extracts certificates from a PKCS#7 blob.
func ParsePKCS7(data []byte) ([]*x509.Certificate, error) {
	// Try to parse as PEM first
	if block, _ := pem.Decode(data); block != nil {
		data = block.Bytes
	}

	// Parse the ContentInfo
	var contentInfo pkcs7ContentInfo
	rest, err := asn1.Unmarshal(data, &contentInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#7 ContentInfo: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after PKCS#7 ContentInfo")
	}

	// Check if it's SignedData
	if !contentInfo.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("PKCS#7 ContentInfo is not SignedData")
	}

	// Parse the SignedData
	var signedData pkcs7SignedData
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &signedData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#7 SignedData: %w", err)
	}

	// Extract certificates
	var certs []*x509.Certificate
	if len(signedData.Certificates.Bytes) > 0 {
		// Parse the certificates
		// The certificates are in a SEQUENCE, each certificate is a SEQUENCE
		var certSeq asn1.RawValue
		rest := signedData.Certificates.Bytes
		for len(rest) > 0 {
			rest, err = asn1.Unmarshal(rest, &certSeq)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate in PKCS#7: %w", err)
			}

			cert, err := x509.ParseCertificate(certSeq.FullBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse X.509 certificate: %w", err)
			}

			certs = append(certs, cert)
		}
	}

	return certs, nil
}

// BuildCAChain builds a certificate chain from PEM-encoded certificates.
// This is used to assemble the CA chain for EST /cacerts responses.
func BuildCAChain(certPEM string, chainPEMs []string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	parsePEM := func(pemData []byte) error {
		for len(pemData) > 0 {
			block, rest := pem.Decode(pemData)
			if block == nil {
				break
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse certificate: %w", err)
			}

			certs = append(certs, cert)
			pemData = rest
		}
		return nil
	}

	// Parse the main certificate
	if err := parsePEM([]byte(certPEM)); err != nil {
		return nil, err
	}

	// Parse chain certificates
	for _, chainEntry := range chainPEMs {
		if chainEntry == "" {
			continue
		}
		if err := parsePEM([]byte(chainEntry)); err != nil {
			return nil, err
		}
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates provided")
	}

	return certs, nil
}
