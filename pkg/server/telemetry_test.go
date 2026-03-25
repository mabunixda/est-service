package server

import (
	"context"
	"log/slog"
	"net/http"
	"testing"
	"time"
)

// TestTelemetry_Disabled tests telemetry initialization with all exporters disabled
func TestTelemetry_Disabled(t *testing.T) {
	cfg := &TelemetryConfig{
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		PrometheusPort: 0,  // Disabled
		OTLPEndpoint:   "", // Disabled
	}

	ctx := context.Background()
	tel, err := NewTelemetry(ctx, cfg, slog.Default())

	if err != nil {
		t.Fatalf("NewTelemetry failed: %v", err)
	}

	if tel == nil {
		t.Error("Expected telemetry instance, got nil")
	}

	// Verify we can use the telemetry instance
	if tel.meter == nil {
		t.Error("Expected meter to be initialized")
	}
}

// TestTelemetry_WithPrometheus tests telemetry with Prometheus enabled
func TestTelemetry_WithPrometheus(t *testing.T) {
	cfg := &TelemetryConfig{
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		PrometheusPort: 9090,
		OTLPEndpoint:   "",
	}

	ctx := context.Background()
	tel, err := NewTelemetry(ctx, cfg, slog.Default())

	if err != nil {
		t.Fatalf("NewTelemetry with Prometheus failed: %v", err)
	}

	if tel == nil {
		t.Error("Expected telemetry instance, got nil")
	}

	// Verify counters are initialized
	if tel.requestCounter == nil {
		t.Error("Request counter not initialized")
	}
	if tel.errorCounter == nil {
		t.Error("Error counter not initialized")
	}
}

// TestTelemetry_NilLogger tests that nil logger doesn't cause panic
func TestTelemetry_NilLogger(t *testing.T) {
	cfg := &TelemetryConfig{
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		PrometheusPort: 0,
		OTLPEndpoint:   "",
	}

	ctx := context.Background()
	tel, err := NewTelemetry(ctx, cfg, nil) // nil logger

	if err != nil {
		t.Fatalf("NewTelemetry with nil logger failed: %v", err)
	}

	if tel == nil {
		t.Error("Expected telemetry instance, got nil")
	}
}

// TestTelemetry_RecordRequest tests recording HTTP requests
func TestTelemetry_RecordRequest(t *testing.T) {
	tel := setupTestTelemetry(t)
	ctx := context.Background()

	// Record various request types
	tel.RecordRequest(ctx, "GET", "/health", http.StatusOK, 100*time.Millisecond)
	tel.RecordRequest(ctx, "POST", "/.well-known/est/simpleenroll", http.StatusCreated, 250*time.Millisecond)
	tel.RecordRequest(ctx, "GET", "/.well-known/est/cacerts", http.StatusOK, 50*time.Millisecond)

	// Record errors
	tel.RecordRequest(ctx, "POST", "/.well-known/est/simpleenroll", http.StatusBadRequest, 10*time.Millisecond)
	tel.RecordRequest(ctx, "GET", "/.well-known/est/cacerts", http.StatusInternalServerError, 5*time.Millisecond)
}

// TestTelemetry_ActiveConnections tests connection tracking
func TestTelemetry_ActiveConnections(t *testing.T) {
	tel := setupTestTelemetry(t)
	ctx := context.Background()

	// Simulate connections
	tel.IncrementActiveConnections(ctx)
	tel.IncrementActiveConnections(ctx)
	tel.IncrementActiveConnections(ctx)

	tel.DecrementActiveConnections(ctx)
	tel.DecrementActiveConnections(ctx)

	tel.IncrementActiveConnections(ctx)
	tel.DecrementActiveConnections(ctx)
	tel.DecrementActiveConnections(ctx)
}

// TestTelemetry_RecordRateLimitReject tests rate limit rejection tracking
func TestTelemetry_RecordRateLimitReject(t *testing.T) {
	tel := setupTestTelemetry(t)
	ctx := context.Background()

	tel.RecordRateLimitReject(ctx, "192.168.1.1")
	tel.RecordRateLimitReject(ctx, "192.168.1.2")
	tel.RecordRateLimitReject(ctx, "192.168.1.1") // Same IP again
	tel.RecordRateLimitReject(ctx, "10.0.0.1")
}

// TestTelemetry_RecordAuthSuccess tests successful authentication tracking
func TestTelemetry_RecordAuthSuccess(t *testing.T) {
	tel := setupTestTelemetry(t)
	ctx := context.Background()

	tel.RecordAuthSuccess(ctx, "certificate", "test-role")
	tel.RecordAuthSuccess(ctx, "userpass", "admin")
	tel.RecordAuthSuccess(ctx, "token", "")
	tel.RecordAuthSuccess(ctx, "certificate", "device-role")
}

// TestTelemetry_RecordAuthFailure tests failed authentication tracking
func TestTelemetry_RecordAuthFailure(t *testing.T) {
	tel := setupTestTelemetry(t)
	ctx := context.Background()

	tel.RecordAuthFailure(ctx, "certificate", "invalid certificate")
	tel.RecordAuthFailure(ctx, "userpass", "wrong password")
	tel.RecordAuthFailure(ctx, "token", "expired token")
	tel.RecordAuthFailure(ctx, "certificate", "unknown CA")
}

// TestTelemetry_RecordCertificateIssued tests certificate issuance tracking
func TestTelemetry_RecordCertificateIssued(t *testing.T) {
	tel := setupTestTelemetry(t)
	ctx := context.Background()

	tel.RecordCertificateIssued(ctx, "simpleenroll", "CN=device1", "1234567890", "720h")
	tel.RecordCertificateIssued(ctx, "simpleenroll", "CN=server1", "1234567891", "8760h")
	tel.RecordCertificateIssued(ctx, "simplereenroll", "CN=device1", "1234567892", "720h")
	tel.RecordCertificateIssued(ctx, "simpleenroll", "CN=client1", "1234567893", "168h")
}

// TestTelemetry_RecordCertificateRejected tests certificate rejection tracking
func TestTelemetry_RecordCertificateRejected(t *testing.T) {
	tel := setupTestTelemetry(t)
	ctx := context.Background()

	tel.RecordCertificateRejected(ctx, "simpleenroll", "invalid CSR")
	tel.RecordCertificateRejected(ctx, "simpleenroll", "authentication failed")
	tel.RecordCertificateRejected(ctx, "simplereenroll", "expired certificate")
	tel.RecordCertificateRejected(ctx, "simpleenroll", "policy violation")
}

// TestTelemetry_CombinedScenario tests realistic usage patterns
func TestTelemetry_CombinedScenario(t *testing.T) {
	tel := setupTestTelemetry(t)
	ctx := context.Background()

	// Simulate enrollment flow
	tel.IncrementActiveConnections(ctx)
	tel.RecordAuthSuccess(ctx, "certificate", "bootstrap-role")
	tel.RecordCertificateIssued(ctx, "simpleenroll", "CN=device1", "ABC123", "720h")
	tel.RecordRequest(ctx, "POST", "/.well-known/est/simpleenroll", http.StatusCreated, 200*time.Millisecond)
	tel.DecrementActiveConnections(ctx)

	// Simulate failed enrollment
	tel.IncrementActiveConnections(ctx)
	tel.RecordAuthFailure(ctx, "certificate", "invalid cert")
	tel.RecordCertificateRejected(ctx, "simpleenroll", "auth failed")
	tel.RecordRequest(ctx, "POST", "/.well-known/est/simpleenroll", http.StatusUnauthorized, 50*time.Millisecond)
	tel.DecrementActiveConnections(ctx)

	// Simulate rate limiting
	tel.RecordRateLimitReject(ctx, "10.0.0.100")
	tel.RecordRequest(ctx, "GET", "/.well-known/est/cacerts", http.StatusTooManyRequests, 1*time.Millisecond)

	// Simulate CA certs retrieval
	tel.IncrementActiveConnections(ctx)
	tel.RecordRequest(ctx, "GET", "/.well-known/est/cacerts", http.StatusOK, 10*time.Millisecond)
	tel.DecrementActiveConnections(ctx)
}

// Helper function to set up telemetry for testing
func setupTestTelemetry(t *testing.T) *Telemetry {
	t.Helper()

	cfg := &TelemetryConfig{
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0-test",
		PrometheusPort: 0,  // Disabled for tests
		OTLPEndpoint:   "", // Disabled for tests
	}

	ctx := context.Background()
	tel, err := NewTelemetry(ctx, cfg, slog.Default())
	if err != nil {
		t.Fatalf("Failed to create telemetry: %v", err)
	}

	return tel
}
