package handlers

// Cryptographic constants for EST server-side key generation and certificate operations.
// These constants define secure defaults for key sizes, encryption parameters, and
// supported cryptographic algorithms.

const (
	// RSA Key Parameters
	// NIST SP 800-57 recommends minimum 2048-bit RSA keys for security beyond 2030
	DefaultRSAKeySize = 2048 // Default RSA key size in bits
	MinRSAKeySize     = 2048 // Minimum allowed RSA key size (security requirement)

	// ECDSA Curve Parameters
	// NIST P-256, P-384, and P-521 curves are approved by FIPS 186-4
	DefaultECDSAKeySize = 256 // Default ECDSA curve size (P-256)
	ECDSACurveP256      = 256 // NIST P-256 curve (secp256r1) - 128-bit security
	ECDSACurveP384      = 384 // NIST P-384 curve (secp384r1) - 192-bit security
	ECDSACurveP521      = 521 // NIST P-521 curve (secp521r1) - 256-bit security

	// Symmetric Encryption Parameters
	// AES-256 is approved by NIST FIPS 197 and provides 256-bit security
	AES256KeySizeBytes = 32 // 32 bytes = 256 bits for AES-256 encryption

	// CSR Size Limits for Server-Side Key Generation
	// Separate from general CSR limits to allow different policies
	DefaultServerKeyGenCSRMaxSize = 4096 // 4 KB default for serverkeygen endpoint

	// Multipart Response Boundary
	// RFC 7030 Section 4.4.2 - Multipart response for serverkeygen
	MultipartBoundaryServerKeyGen = "EstServerKeyGenBoundary"
)

// ValidECDSACurveSizes returns the list of supported ECDSA curve sizes.
// These correspond to NIST-approved elliptic curves: P-256, P-384, and P-521.
func ValidECDSACurveSizes() []int {
	return []int{ECDSACurveP256, ECDSACurveP384, ECDSACurveP521}
}

// IsValidECDSACurveSize checks if the given curve size is supported.
// Returns true for P-256 (256), P-384 (384), or P-521 (521).
func IsValidECDSACurveSize(size int) bool {
	return size == ECDSACurveP256 || size == ECDSACurveP384 || size == ECDSACurveP521
}

// ValidECDSACurveSizesString returns a formatted string of valid curve sizes for error messages.
func ValidECDSACurveSizesString() string {
	return "256, 384, or 521"
}
