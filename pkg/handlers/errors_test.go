package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseBackendError_Nil(t *testing.T) {
	result := ParseBackendError(nil)
	if result != nil {
		t.Errorf("Expected nil for nil error, got %+v", result)
	}
}

func TestParseBackendError_PermissionDenied(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		expected int
	}{
		{"permission denied lowercase", "permission denied", http.StatusForbidden},
		{"Permission Denied uppercase", "Permission Denied", http.StatusForbidden},
		{"code 403", "Error: code: 403", http.StatusForbidden},
		{"forbidden", "Forbidden access", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := errors.New(tt.errMsg)
			result := ParseBackendError(err)

			if result == nil {
				t.Fatal("Expected non-nil BackendError")
			}
			if result.StatusCode != tt.expected {
				t.Errorf("Expected status %d, got %d", tt.expected, result.StatusCode)
			}
			if !strings.Contains(result.Message, "permission") {
				t.Errorf("Expected message to contain 'permission', got: %s", result.Message)
			}
		})
	}
}

func TestParseBackendError_Unauthorized(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		expected int
	}{
		{"authentication failed", "authentication failed", http.StatusUnauthorized},
		{"code 401", "code: 401", http.StatusUnauthorized},
		{"unauthorized", "unauthorized access", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := errors.New(tt.errMsg)
			result := ParseBackendError(err)

			if result == nil {
				t.Fatal("Expected non-nil BackendError")
			}
			if result.StatusCode != tt.expected {
				t.Errorf("Expected status %d, got %d", tt.expected, result.StatusCode)
			}
			if !strings.Contains(result.Message, "authentication") {
				t.Errorf("Expected message to contain 'authentication', got: %s", result.Message)
			}
		})
	}
}

func TestParseBackendError_BadRequest(t *testing.T) {
	tests := []struct {
		name   string
		errMsg string
	}{
		{"code 400", "code: 400"},
		{"bad request", "bad request"},
		{"invalid data", "invalid certificate data"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := errors.New(tt.errMsg)
			result := ParseBackendError(err)

			if result == nil {
				t.Fatal("Expected non-nil BackendError")
			}
			if result.StatusCode != http.StatusBadRequest {
				t.Errorf("Expected status %d, got %d", http.StatusBadRequest, result.StatusCode)
			}
			if !strings.Contains(result.Message, "Invalid") {
				t.Errorf("Expected message to contain 'Invalid', got: %s", result.Message)
			}
		})
	}
}

func TestParseBackendError_NotFound(t *testing.T) {
	tests := []struct {
		name   string
		errMsg string
	}{
		{"code 404", "code: 404"},
		{"not found", "PKI mount not found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := errors.New(tt.errMsg)
			result := ParseBackendError(err)

			if result == nil {
				t.Fatal("Expected non-nil BackendError")
			}
			if result.StatusCode != http.StatusNotFound {
				t.Errorf("Expected status %d, got %d", http.StatusNotFound, result.StatusCode)
			}
			if !strings.Contains(result.Message, "not found") {
				t.Errorf("Expected message to contain 'not found', got: %s", result.Message)
			}
		})
	}
}

func TestParseBackendError_ServiceUnavailable(t *testing.T) {
	tests := []struct {
		name   string
		errMsg string
	}{
		{"connection refused", "connection refused"},
		{"connection reset", "connection reset by peer"},
		{"no such host", "no such host"},
		{"timeout", "request timeout"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := errors.New(tt.errMsg)
			result := ParseBackendError(err)

			if result == nil {
				t.Fatal("Expected non-nil BackendError")
			}
			if result.StatusCode != http.StatusServiceUnavailable {
				t.Errorf("Expected status %d, got %d", http.StatusServiceUnavailable, result.StatusCode)
			}
			if !strings.Contains(result.Message, "unavailable") {
				t.Errorf("Expected message to contain 'unavailable', got: %s", result.Message)
			}
			if result.Details != "Unable to connect to PKI backend" {
				t.Errorf("Expected specific details message, got: %s", result.Details)
			}
		})
	}
}

func TestParseBackendError_BackendError(t *testing.T) {
	tests := []struct {
		name   string
		errMsg string
	}{
		{"code 500", "code: 500"},
		{"code 502", "code: 502"},
		{"internal server error", "internal server error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := errors.New(tt.errMsg)
			result := ParseBackendError(err)

			if result == nil {
				t.Fatal("Expected non-nil BackendError")
			}
			if result.StatusCode != http.StatusBadGateway {
				t.Errorf("Expected status %d, got %d", http.StatusBadGateway, result.StatusCode)
			}
			if !strings.Contains(result.Message, "backend error") {
				t.Errorf("Expected message to contain 'backend error', got: %s", result.Message)
			}
		})
	}
}

func TestParseBackendError_GenericError(t *testing.T) {
	err := errors.New("some random unexpected error")
	result := ParseBackendError(err)

	if result == nil {
		t.Fatal("Expected non-nil BackendError")
	}
	if result.StatusCode != http.StatusBadGateway {
		t.Errorf("Expected status %d for generic error, got %d", http.StatusBadGateway, result.StatusCode)
	}
	if !strings.Contains(result.Message, "backend error") {
		t.Errorf("Expected message to contain 'backend error', got: %s", result.Message)
	}
}

func TestExtractVaultError_WithErrorsFormat(t *testing.T) {
	errStr := "API call failed with status 400. Errors:\n\n* invalid common name"
	result := extractVaultError(errStr)

	if result != "invalid common name" {
		t.Errorf("Expected 'invalid common name', got: %s", result)
	}
}

func TestExtractVaultError_WithCodeFormat(t *testing.T) {
	errStr := "Something went wrong. Code: 403. Errors: permission denied"
	result := extractVaultError(errStr)

	if !strings.Contains(result, "Code: 403") {
		t.Errorf("Expected result to contain 'Code: 403', got: %s", result)
	}
}

func TestExtractVaultError_LongError(t *testing.T) {
	longError := strings.Repeat("x", 250)
	result := extractVaultError(longError)

	if len(result) != 203 { // 200 chars + "..."
		t.Errorf("Expected truncated error (203 chars), got %d chars", len(result))
	}
	if !strings.HasSuffix(result, "...") {
		t.Errorf("Expected error to end with '...', got: %s", result[len(result)-10:])
	}
}

func TestExtractVaultError_ShortError(t *testing.T) {
	shortError := "simple error"
	result := extractVaultError(shortError)

	if result != shortError {
		t.Errorf("Expected unchanged error '%s', got: %s", shortError, result)
	}
}

func TestSendBackendError_Forbidden(t *testing.T) {
	w := httptest.NewRecorder()
	err := errors.New("permission denied")

	SendBackendError(w, err, "certificate signing")

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status %d, got %d", http.StatusForbidden, w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "insufficient permissions") {
		t.Errorf("Expected body to contain 'insufficient permissions', got: %s", body)
	}
	if !strings.Contains(body, "Details:") {
		t.Errorf("Expected body to contain 'Details:', got: %s", body)
	}
}

func TestSendBackendError_ServiceUnavailable(t *testing.T) {
	w := httptest.NewRecorder()
	err := errors.New("connection refused")

	SendBackendError(w, err, "certificate enrollment")

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "unavailable") {
		t.Errorf("Expected body to contain 'unavailable', got: %s", body)
	}
	if !strings.Contains(body, "try again later") {
		t.Errorf("Expected body to contain 'try again later', got: %s", body)
	}
}

func TestSendBackendError_BadGateway(t *testing.T) {
	w := httptest.NewRecorder()
	err := errors.New("code: 500 internal error")

	SendBackendError(w, err, "certificate enrollment")

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected status %d, got %d", http.StatusBadGateway, w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "certificate enrollment") {
		t.Errorf("Expected body to contain operation name 'certificate enrollment', got: %s", body)
	}
	if !strings.Contains(body, "backend error") {
		t.Errorf("Expected body to contain 'backend error', got: %s", body)
	}
}

func TestSendBackendError_OtherErrors(t *testing.T) {
	w := httptest.NewRecorder()
	err := errors.New("code: 400 invalid CSR")

	SendBackendError(w, err, "certificate enrollment")

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Details:") {
		t.Errorf("Expected body to contain 'Details:', got: %s", body)
	}
}

func TestBackendError_AllFieldsSet(t *testing.T) {
	err := errors.New("Vault API error. Code: 403. Errors:\n\n* permission denied for role")
	result := ParseBackendError(err)

	if result == nil {
		t.Fatal("Expected non-nil BackendError")
	}

	if result.StatusCode == 0 {
		t.Error("Expected StatusCode to be set")
	}
	if result.Message == "" {
		t.Error("Expected Message to be set")
	}
	if result.Details == "" {
		t.Error("Expected Details to be set")
	}

	// Verify details extraction worked
	if result.Details != "permission denied for role" {
		t.Errorf("Expected details 'permission denied for role', got: %s", result.Details)
	}
}
