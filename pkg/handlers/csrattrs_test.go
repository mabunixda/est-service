package handlers

import (
	"encoding/asn1"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCSRAttrsHandler_ServeHTTP_Success(t *testing.T) {
	logger := slog.Default()
	handler := NewCSRAttrsHandler(logger, nil) // Use default attributes

	req := httptest.NewRequest(http.MethodGet, "/.well-known/est/csrattrs", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/csrattrs" {
		t.Errorf("Expected Content-Type 'application/csrattrs', got '%s'", contentType)
	}

	encoding := resp.Header.Get("Content-Transfer-Encoding")
	if encoding != "base64" {
		t.Errorf("Expected Content-Transfer-Encoding 'base64', got '%s'", encoding)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if len(body) == 0 {
		t.Error("Expected non-empty response body")
	}

	// Verify base64 encoding
	decoded, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		t.Errorf("Response is not valid base64: %v", err)
	}

	// Verify ASN.1 structure
	var oids []asn1.ObjectIdentifier
	_, err = asn1.Unmarshal(decoded, &oids)
	if err != nil {
		t.Errorf("Failed to decode ASN.1 response: %v", err)
	}

	if len(oids) == 0 {
		t.Error("Expected at least one OID in response")
	}

	// Verify default OID is extensionRequest
	expectedOID := OIDExtensionRequest
	if !oids[0].Equal(expectedOID) {
		t.Errorf("Expected OID %v, got %v", expectedOID, oids[0])
	}
}

func TestCSRAttrsHandler_ServeHTTP_CustomAttributes(t *testing.T) {
	logger := slog.Default()
	customOIDs := []string{
		"1.2.840.113549.1.9.14", // extensionRequest
		"2.5.29.17",             // subjectAltName
		"2.5.29.15",             // keyUsage
	}

	handler := NewCSRAttrsHandler(logger, customOIDs)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/est/csrattrs", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		t.Errorf("Response is not valid base64: %v", err)
	}

	var oids []asn1.ObjectIdentifier
	_, err = asn1.Unmarshal(decoded, &oids)
	if err != nil {
		t.Errorf("Failed to decode ASN.1 response: %v", err)
	}

	if len(oids) != 3 {
		t.Errorf("Expected 3 OIDs, got %d", len(oids))
	}

	// Verify each OID
	expectedOIDs := []asn1.ObjectIdentifier{
		{1, 2, 840, 113549, 1, 9, 14}, // extensionRequest
		{2, 5, 29, 17},                // subjectAltName
		{2, 5, 29, 15},                // keyUsage
	}

	for i, expected := range expectedOIDs {
		if !oids[i].Equal(expected) {
			t.Errorf("OID %d: expected %v, got %v", i, expected, oids[i])
		}
	}
}

func TestCSRAttrsHandler_ServeHTTP_NoAttributes(t *testing.T) {
	logger := slog.Default()
	handler := &CSRAttrsHandler{
		logger:     logger,
		attributes: []asn1.ObjectIdentifier{}, // Empty attributes
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/est/csrattrs", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// RFC 7030 Section 4.5.2: Server MAY return 204 No Content if no attributes required
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if len(body) != 0 {
		t.Errorf("Expected empty body for 204, got %d bytes", len(body))
	}
}

func TestCSRAttrsHandler_ServeHTTP_MethodNotAllowed(t *testing.T) {
	logger := slog.Default()
	handler := NewCSRAttrsHandler(logger, nil)

	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/.well-known/est/csrattrs", nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("Expected status 405 for %s, got %d", method, resp.StatusCode)
			}
		})
	}
}

func TestCSRAttrsHandler_InvalidOIDHandling(t *testing.T) {
	logger := slog.Default()
	invalidOIDs := []string{
		"invalid",
		"1.2.abc",
		"1",         // Too short
		"",          // Empty
		"1.2.3.4.5", // Valid, should be accepted
	}

	handler := NewCSRAttrsHandler(logger, invalidOIDs)

	// Handler should skip invalid OIDs and only include valid ones
	req := httptest.NewRequest(http.MethodGet, "/.well-known/est/csrattrs", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Should return 200 with the one valid OID (1.2.3.4.5)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		t.Errorf("Response is not valid base64: %v", err)
	}

	var oids []asn1.ObjectIdentifier
	_, err = asn1.Unmarshal(decoded, &oids)
	if err != nil {
		t.Errorf("Failed to decode ASN.1 response: %v", err)
	}

	// Should have exactly 1 valid OID
	if len(oids) != 1 {
		t.Errorf("Expected 1 valid OID, got %d", len(oids))
	}

	expectedOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	if !oids[0].Equal(expectedOID) {
		t.Errorf("Expected OID %v, got %v", expectedOID, oids[0])
	}
}

func TestParseOID(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  asn1.ObjectIdentifier
		expectErr bool
	}{
		{
			name:      "Valid OID - extensionRequest",
			input:     "1.2.840.113549.1.9.14",
			expected:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14},
			expectErr: false,
		},
		{
			name:      "Valid OID - subjectAltName",
			input:     "2.5.29.17",
			expected:  asn1.ObjectIdentifier{2, 5, 29, 17},
			expectErr: false,
		},
		{
			name:      "Invalid - too short",
			input:     "1",
			expected:  nil,
			expectErr: true,
		},
		{
			name:      "Invalid - letters",
			input:     "1.2.abc",
			expected:  nil,
			expectErr: true,
		},
		{
			name:      "Invalid - empty",
			input:     "",
			expected:  nil,
			expectErr: true,
		},
		{
			name:      "Valid - simple OID",
			input:     "2.5",
			expected:  asn1.ObjectIdentifier{2, 5},
			expectErr: false,
		},
		{
			name:      "Invalid - special characters",
			input:     "1.2.3-4",
			expected:  nil,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseOID(tt.input)

			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error for input '%s', got nil", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for input '%s': %v", tt.input, err)
				}

				if !result.Equal(tt.expected) {
					t.Errorf("For input '%s': expected %v, got %v", tt.input, tt.expected, result)
				}
			}
		})
	}
}

func TestEncodeCSRAttributes(t *testing.T) {
	oids := []asn1.ObjectIdentifier{
		{1, 2, 840, 113549, 1, 9, 14}, // extensionRequest
		{2, 5, 29, 17},                // subjectAltName
	}

	data, err := encodeCSRAttributes(oids)
	if err != nil {
		t.Fatalf("Failed to encode attributes: %v", err)
	}

	if len(data) == 0 {
		t.Error("Expected non-empty encoded data")
	}

	// Verify we can decode it back
	var decoded []asn1.ObjectIdentifier
	_, err = asn1.Unmarshal(data, &decoded)
	if err != nil {
		t.Errorf("Failed to decode ASN.1 data: %v", err)
	}

	if len(decoded) != len(oids) {
		t.Errorf("Expected %d OIDs, got %d", len(oids), len(decoded))
	}

	for i, oid := range oids {
		if !decoded[i].Equal(oid) {
			t.Errorf("OID %d mismatch: expected %v, got %v", i, oid, decoded[i])
		}
	}
}

func TestCommonOIDConstants(t *testing.T) {
	// Verify common OID constants are correctly defined
	tests := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		expected []int
	}{
		{
			name:     "OIDChallengePassword",
			oid:      OIDChallengePassword,
			expected: []int{1, 2, 840, 113549, 1, 9, 7},
		},
		{
			name:     "OIDExtensionRequest",
			oid:      OIDExtensionRequest,
			expected: []int{1, 2, 840, 113549, 1, 9, 14},
		},
		{
			name:     "OIDSubjectAltName",
			oid:      OIDSubjectAltName,
			expected: []int{2, 5, 29, 17},
		},
		{
			name:     "OIDKeyUsage",
			oid:      OIDKeyUsage,
			expected: []int{2, 5, 29, 15},
		},
		{
			name:     "OIDExtendedKeyUsage",
			oid:      OIDExtendedKeyUsage,
			expected: []int{2, 5, 29, 37},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expectedOID := asn1.ObjectIdentifier(tt.expected)
			if !tt.oid.Equal(expectedOID) {
				t.Errorf("%s: expected %v, got %v", tt.name, expectedOID, tt.oid)
			}
		})
	}
}
