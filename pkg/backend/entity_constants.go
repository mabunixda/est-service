package backend

import "fmt"

// Entity and alias naming constants for certificate-based authentication.
// These constants define the format for OpenBao entities and aliases
// created for EST clients authenticating with certificates.
//
// Note: Entity naming is now configurable via CertAuthConfig.EntityAliasPrefix
// with a default of "est-cert-" for backward compatibility.

const (
	// Default Entity Naming Format
	// Entities are named: <prefix><CN>-<fingerprint-prefix>
	// Example: est-cert-device123-a1b2c3d4e5f6g7h8
	DefaultEntityNamePrefix = "est-cert-"

	// Entity Alias Format
	// Aliases uniquely identify the client certificate
	// Format: cert:SHA256:<full-fingerprint>:CN=<common-name>
	// Example: cert:SHA256:a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6:CN=device123
	EntityAliasFormat = "cert:SHA256:%s:CN=%s"

	// Fingerprint Parameters
	// Use first 16 characters of SHA256 fingerprint in entity name
	// Full fingerprint (64 hex chars) used in alias for unique identification
	FingerprintPrefixLength = 16

	// Default Token TTL for certificate-based authentication
	DefaultTokenTTL = "24h"
)

// FormatEntityName creates a standardized entity name for a certificate-authenticated client.
// The entity name includes the certificate's Common Name (CN) and a prefix of the SHA256 fingerprint.
//
// Parameters:
//   - prefix: Entity name prefix (e.g., "est-cert-")
//   - cn: Certificate Common Name (subject CN)
//   - fingerprintPrefix: First N characters of certificate SHA256 fingerprint (where N = FingerprintPrefixLength)
//
// Returns: Formatted entity name (e.g., "est-cert-device123-a1b2c3d4e5f6g7h8")
func FormatEntityName(prefix, cn, fingerprintPrefix string) string {
	return fmt.Sprintf("%s%s-%s", prefix, cn, fingerprintPrefix)
}

// FormatEntityAlias creates a standardized entity alias for a certificate.
// The alias uniquely identifies the certificate using its full SHA256 fingerprint and CN.
//
// Parameters:
//   - fingerprint: Full SHA256 fingerprint of the certificate (64 hex characters)
//   - cn: Certificate Common Name (subject CN)
//
// Returns: Formatted entity alias (e.g., "cert:SHA256:a1b2...o5p6:CN=device123")
func FormatEntityAlias(fingerprint, cn string) string {
	return fmt.Sprintf(EntityAliasFormat, fingerprint, cn)
}
