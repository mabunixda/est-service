package backend

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// mapToTransitKeyType maps EST key type and size to Vault/OpenBao Transit engine key types
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
func parseExportedKey(keyPEM string) (privateKey interface{}, publicKey interface{}, err error) {
	// Decode PEM block
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode PEM block")
	}

	// Parse PKCS#8 private key
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
	}

	// Extract public key based on private key type
	switch pk := parsedKey.(type) {
	case *rsa.PrivateKey:
		return pk, &pk.PublicKey, nil
	case *ecdsa.PrivateKey:
		return pk, &pk.PublicKey, nil
	default:
		return nil, nil, fmt.Errorf("unsupported private key type: %T", pk)
	}
}
