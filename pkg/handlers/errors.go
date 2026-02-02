package handlers

import (
	"fmt"
	"net/http"
	"strings"
)

// BackendError represents an error response from the backend with HTTP status code
type BackendError struct {
	StatusCode int
	Message    string
	Details    string
}

// ParseBackendError analyzes an error from the backend and returns appropriate HTTP status code and message
func ParseBackendError(err error) *BackendError {
	if err == nil {
		return nil
	}

	errStr := err.Error()
	errLower := strings.ToLower(errStr)

	// Permission denied / forbidden
	if strings.Contains(errLower, "permission denied") ||
		strings.Contains(errLower, "code: 403") ||
		strings.Contains(errLower, "forbidden") {
		return &BackendError{
			StatusCode: http.StatusForbidden,
			Message:    "Certificate signing request rejected: insufficient permissions",
			Details:    extractVaultError(errStr),
		}
	}

	// Authentication failed
	if strings.Contains(errLower, "authentication failed") ||
		strings.Contains(errLower, "code: 401") ||
		strings.Contains(errLower, "unauthorized") {
		return &BackendError{
			StatusCode: http.StatusUnauthorized,
			Message:    "Backend authentication failed",
			Details:    extractVaultError(errStr),
		}
	}

	// Bad request / invalid data
	if strings.Contains(errLower, "code: 400") ||
		strings.Contains(errLower, "bad request") ||
		strings.Contains(errLower, "invalid") {
		return &BackendError{
			StatusCode: http.StatusBadRequest,
			Message:    "Invalid certificate request",
			Details:    extractVaultError(errStr),
		}
	}

	// Not found
	if strings.Contains(errLower, "code: 404") ||
		strings.Contains(errLower, "not found") {
		return &BackendError{
			StatusCode: http.StatusNotFound,
			Message:    "PKI mount or role not found",
			Details:    extractVaultError(errStr),
		}
	}

	// Service unavailable / connection issues
	if strings.Contains(errLower, "connection refused") ||
		strings.Contains(errLower, "connection reset") ||
		strings.Contains(errLower, "no such host") ||
		strings.Contains(errLower, "timeout") {
		return &BackendError{
			StatusCode: http.StatusServiceUnavailable,
			Message:    "Backend service unavailable",
			Details:    "Unable to connect to PKI backend",
		}
	}

	// Backend error (502 Bad Gateway)
	if strings.Contains(errLower, "code: 5") ||
		strings.Contains(errLower, "internal server error") {
		return &BackendError{
			StatusCode: http.StatusBadGateway,
			Message:    "PKI backend error",
			Details:    extractVaultError(errStr),
		}
	}

	// Generic backend error
	return &BackendError{
		StatusCode: http.StatusBadGateway,
		Message:    "PKI backend error",
		Details:    extractVaultError(errStr),
	}
}

// extractVaultError extracts the meaningful error message from Vault API errors
func extractVaultError(errStr string) string {
	// Look for "Errors:\n\n* <message>"
	if idx := strings.Index(errStr, "Errors:\n\n* "); idx != -1 {
		msg := errStr[idx+len("Errors:\n\n* "):]
		if endIdx := strings.Index(msg, "\n"); endIdx != -1 {
			msg = msg[:endIdx]
		}
		return msg
	}

	// Look for "Code: XXX. Errors:"
	if idx := strings.Index(errStr, "Code: "); idx != -1 {
		return errStr[idx:]
	}

	// Return truncated error if too long
	if len(errStr) > 200 {
		return errStr[:200] + "..."
	}

	return errStr
}

// SendBackendError sends an appropriate HTTP error response based on backend error
func SendBackendError(w http.ResponseWriter, err error, operation string) {
	backendErr := ParseBackendError(err)

	// Format user-friendly error message
	var errorMsg string
	switch backendErr.StatusCode {
	case http.StatusForbidden:
		errorMsg = fmt.Sprintf("%s. The EST service may lack permissions to sign certificates with the configured PKI role.",
			backendErr.Message)
	case http.StatusServiceUnavailable:
		errorMsg = fmt.Sprintf("%s. Please try again later or contact your administrator.",
			backendErr.Message)
	case http.StatusBadGateway:
		errorMsg = fmt.Sprintf("%s during %s.",
			backendErr.Message, operation)
	default:
		errorMsg = backendErr.Message
	}

	http.Error(w, errorMsg, backendErr.StatusCode)
}
