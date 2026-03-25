package backend

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// mapToTransitKeyType maps EST key type and size to OpenBao Transit engine key types
func mapToTransitKeyType(keyType string, keyBits int) (string, error) {
	switch keyType {
	case "rsa":
		switch keyBits {
		case 2048:
			return "rsa-2048", nil
		case 3072:
			return "rsa-3072", nil
		case 4096:
			return "rsa-4096", nil
		default:
			return "", fmt.Errorf("unsupported RSA key size: %d (must be 2048, 3072, or 4096)", keyBits)
		}
	case "ecdsa", "ec":
		switch keyBits {
		case 256:
			return "ecdsa-p256", nil
		case 384:
			return "ecdsa-p384", nil
		case 521:
			return "ecdsa-p521", nil
		default:
			return "", fmt.Errorf("unsupported ECDSA curve size: %d (must be 256, 384, or 521)", keyBits)
		}
	default:
		return "", fmt.Errorf("unsupported key type: %s (must be 'rsa' or 'ecdsa')", keyType)
	}
}

// parseExportedKey parses a PEM-encoded private key exported from Transit engine
// Returns the private key and its corresponding public key
// Supports both PKCS#8 and PKCS#1 (RSA-specific) formats
func parseExportedKey(keyPEM string) (privateKey interface{}, publicKey interface{}, err error) {
	// Decode PEM block
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try PKCS#8 first (modern standard format for all key types)
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		// Successfully parsed as PKCS#8
		switch pk := parsedKey.(type) {
		case *rsa.PrivateKey:
			return pk, &pk.PublicKey, nil
		case *ecdsa.PrivateKey:
			return pk, &pk.PublicKey, nil
		default:
			return nil, nil, fmt.Errorf("unsupported private key type: %T", pk)
		}
	}

	// If PKCS#8 fails, try PKCS#1 (legacy RSA-specific format)
	// Transit engine may return RSA keys in PKCS#1 format
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		// Successfully parsed as PKCS#1 RSA key
		return rsaKey, &rsaKey.PublicKey, nil
	}

	// If both fail, try parsing as EC private key (SEC 1, ASN.1 DER form)
	ecKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err == nil {
		// Successfully parsed as EC private key
		return ecKey, &ecKey.PublicKey, nil
	}

	return nil, nil, fmt.Errorf("failed to parse private key: not PKCS#8, PKCS#1, or EC format")
}
