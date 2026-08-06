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
		name               string
		errMsg             string
		expectedRetryAfter int
	}{
		{"connection refused", "connection refused", 30},
		{"connection reset", "connection reset by peer", 30},
		{"no such host", "no such host", 30},
		{"timeout", "request timeout", 30},
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
			if result.RetryAfter != tt.expectedRetryAfter {
				t.Errorf("Expected RetryAfter %d, got %d", tt.expectedRetryAfter, result.RetryAfter)
			}
		})
	}
}

func TestParseBackendError_ServiceUnavailable_Sealed(t *testing.T) {
	tests := []struct {
		name               string
		errMsg             string
		expectedRetryAfter int
	}{
		{"sealed", "OpenBao is sealed", 120},
		{"standby", "OpenBao is in standby mode", 120},
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
			if result.RetryAfter != tt.expectedRetryAfter {
				t.Errorf("Expected RetryAfter %d seconds for %s, got %d", tt.expectedRetryAfter, tt.name, result.RetryAfter)
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

func TestExtractBackendError_WithErrorsFormat(t *testing.T) {
	errStr := "API call failed with status 400. Errors:\n\n* invalid common name"
	result := extractBackendError(errStr)

	if result != "invalid common name" {
		t.Errorf("Expected 'invalid common name', got: %s", result)
	}
}

func TestExtractBackendError_WithCodeFormat(t *testing.T) {
	errStr := "Something went wrong. Code: 403. Errors: permission denied"
	result := extractBackendError(errStr)

	if !strings.Contains(result, "Code: 403") {
		t.Errorf("Expected result to contain 'Code: 403', got: %s", result)
	}
}

func TestExtractBackendError_LongError(t *testing.T) {
	longError := strings.Repeat("x", 250)
	result := extractBackendError(longError)

	if len(result) != 203 { // 200 chars + "..."
		t.Errorf("Expected truncated error (203 chars), got %d chars", len(result))
	}
	if !strings.HasSuffix(result, "...") {
		t.Errorf("Expected error to end with '...', got: %s", result[len(result)-10:])
	}
}

func TestExtractBackendError_ShortError(t *testing.T) {
	shortError := "simple error"
	result := extractBackendError(shortError)

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
	if strings.Contains(body, "Details:") {
		t.Errorf("Expected body to omit details, got: %s", body)
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
	if !strings.Contains(body, "retry after") {
		t.Errorf("Expected body to contain 'retry after', got: %s", body)
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
	if strings.Contains(body, "Details:") {
		t.Errorf("Expected body to omit details, got: %s", body)
	}
}

func TestBackendError_AllFieldsSet(t *testing.T) {
	err := errors.New("OpenBao API error. Code: 403. Errors:\n\n* permission denied for role")
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

func TestSendBackendError_ServiceUnavailable_IncludesRetryAfter(t *testing.T) {
	err := errors.New("connection refused")
	w := httptest.NewRecorder()

	SendBackendError(w, err, "certificate enrollment")

	// Verify HTTP status code
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
	}

	// Verify Retry-After header is present
	retryAfter := w.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Error("Expected Retry-After header to be set")
	}

	// Verify Retry-After value is correct
	if retryAfter != "30" {
		t.Errorf("Expected Retry-After: 30, got: %s", retryAfter)
	}

	// Verify error message mentions retry time
	body := w.Body.String()
	if !strings.Contains(body, "30 seconds") {
		t.Errorf("Expected error message to mention retry time, got: %s", body)
	}
}

func TestSendBackendError_ServiceUnavailable_Sealed_LongerRetry(t *testing.T) {
	err := errors.New("OpenBao is sealed")
	w := httptest.NewRecorder()

	SendBackendError(w, err, "certificate enrollment")

	// Verify Retry-After is 120 seconds for sealed state
	retryAfter := w.Header().Get("Retry-After")
	if retryAfter != "120" {
		t.Errorf("Expected Retry-After: 120 for sealed OpenBao, got: %s", retryAfter)
	}

	// Verify error message mentions retry time
	body := w.Body.String()
	if !strings.Contains(body, "120 seconds") {
		t.Errorf("Expected error message to mention 120 second retry time, got: %s", body)
	}
}

func TestSendBackendError_OtherErrors_NoRetryAfter(t *testing.T) {
	tests := []struct {
		name   string
		errMsg string
	}{
		{"permission denied", "permission denied"},
		{"not found", "mount not found"},
		{"bad request", "invalid data"},
		{"backend error", "code: 500"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := errors.New(tt.errMsg)
			w := httptest.NewRecorder()

			SendBackendError(w, err, "operation")

			// Verify Retry-After header is NOT set for non-503 errors
			retryAfter := w.Header().Get("Retry-After")
			if retryAfter != "" {
				t.Errorf("Expected no Retry-After header for %s, got: %s", tt.name, retryAfter)
			}
		})
	}
}
