package handlers

import (
	"encoding/asn1"
	"encoding/base64"
	"log/slog"
	"net/http"
)

// CSRAttrsHandler handles GET /.well-known/est/csrattrs
// RFC 7030 Section 4.5
type CSRAttrsHandler struct {
	logger     *slog.Logger
	attributes []asn1.ObjectIdentifier
}

// Common OIDs for CSR attributes
var (
	// challengePassword OID (1.2.840.113549.1.9.7)
	OIDChallengePassword = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}

	// extensionRequest OID (1.2.840.113549.1.9.14) - for requesting extensions
	OIDExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}

	// Subject Alternative Name extension OID (2.5.29.17)
	OIDSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

	// Key Usage extension OID (2.5.29.15)
	OIDKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 15}

	// Extended Key Usage extension OID (2.5.29.37)
	OIDExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// NewCSRAttrsHandler creates a new CSR attributes handler
func NewCSRAttrsHandler(logger *slog.Logger, customAttrs []string) *CSRAttrsHandler {
	if logger == nil {
		logger = slog.Default()
	}

	// Default attributes if none specified
	var attributes []asn1.ObjectIdentifier
	if len(customAttrs) > 0 {
		// Parse custom OIDs from configuration
		for _, oidStr := range customAttrs {
			oid, err := parseOID(oidStr)
			if err != nil {
				logger.Warn("Invalid OID in configuration, skipping", "oid", oidStr, "error", err)
				continue
			}
			attributes = append(attributes, oid)
		}
	} else {
		// RFC 7030 Section 4.5.2: Default attributes
		// Commonly requested: extensionRequest for SAN and key usage extensions
		attributes = []asn1.ObjectIdentifier{
			OIDExtensionRequest, // Signals client should include extension requests
		}
	}

	return &CSRAttrsHandler{
		logger:     logger,
		attributes: attributes,
	}
}

// ServeHTTP handles the CSR attributes request
// @Summary Get CSR Attributes
// @Description Returns a list of OID attributes that should be included in certificate requests. Per RFC 7030 Section 4.5, this helps clients understand what information to include in their CSRs.
// @Tags EST
// @Produce application/csrattrs
// @Success 200 {string} string "CSR attributes in base64-encoded ASN.1 format"
// @Success 204 "No specific attributes required"
// @Failure 500 {string} string "Failed to encode CSR attributes"
// @Router /.well-known/est/csrattrs [get]
func (h *CSRAttrsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.logger.Debug("Invalid method for /csrattrs", "method", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// RFC 7030 Section 4.5.2: If no specific attributes are required,
	// the server MAY return 204 No Content
	if len(h.attributes) == 0 {
		h.logger.Debug("No CSR attributes configured, returning 204")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Encode attributes as ASN.1 SEQUENCE OF OBJECT IDENTIFIER
	// This is the format expected by RFC 7030 Section 4.5.2
	asn1Data, err := encodeCSRAttributes(h.attributes)
	if err != nil {
		h.logger.Error("Failed to encode CSR attributes", "error", err)
		http.Error(w, "Failed to encode CSR attributes", http.StatusInternalServerError)
		return
	}

	// RFC 7030 requires base64 encoding for EST responses
	base64Data := base64.StdEncoding.EncodeToString(asn1Data)

	// RFC 7030 Section 4.5.2 specifies Content-Type: application/csrattrs
	w.Header().Set("Content-Type", "application/csrattrs")
	w.Header().Set("Content-Transfer-Encoding", "base64")
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write([]byte(base64Data)); err != nil {
		h.logger.Error("Failed to write response", "error", err)
		return
	}

	h.logger.Info("CSR attributes served",
		"attributes_count", len(h.attributes),
		"bytes", len(asn1Data))
}

// encodeCSRAttributes encodes OIDs as ASN.1 SEQUENCE
// RFC 7030 Section 4.5.2 specifies the format:
//
//	CsrAttrs ::= SEQUENCE SIZE (0..MAX) OF AttrOrOID
//	AttrOrOID ::= CHOICE {
//	  oid        OBJECT IDENTIFIER,
//	  attribute  Attribute {{AttrSet}} }
//
// For simplicity, we use SEQUENCE OF OBJECT IDENTIFIER
func encodeCSRAttributes(oids []asn1.ObjectIdentifier) ([]byte, error) {
	return asn1.Marshal(oids)
}

// parseOID converts a string like "1.2.3.4" to an asn1.ObjectIdentifier
func parseOID(oidStr string) (asn1.ObjectIdentifier, error) {
	var oid asn1.ObjectIdentifier
	var component int
	var current int

	for i := 0; i < len(oidStr); i++ {
		if oidStr[i] == '.' {
			oid = append(oid, current)
			current = 0
			continue
		}
		if oidStr[i] < '0' || oidStr[i] > '9' {
			return nil, asn1.SyntaxError{Msg: "invalid OID format"}
		}
		component = int(oidStr[i] - '0')
		current = current*10 + component
	}
	oid = append(oid, current)

	if len(oid) < 2 {
		return nil, asn1.SyntaxError{Msg: "OID must have at least 2 components"}
	}

	return oid, nil
}
