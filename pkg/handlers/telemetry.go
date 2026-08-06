package handlers

import "context"

// Telemetry is an interface for recording metrics
// This allows handlers to be decoupled from the specific telemetry implementation
type Telemetry interface {
	// RecordAuthSuccess records a successful authentication
	RecordAuthSuccess(ctx context.Context, method, identity string)

	// RecordAuthFailure records a failed authentication
	RecordAuthFailure(ctx context.Context, method, reason string)

	// RecordCertificateIssued records a successful certificate issuance
	RecordCertificateIssued(ctx context.Context, operation, subject, serialNumber string, ttl string)

	// RecordCertificateRejected records a rejected certificate request
	RecordCertificateRejected(ctx context.Context, operation, reason string)
}

// NoOpTelemetry is a no-op implementation of Telemetry
type NoOpTelemetry struct{}

func (n *NoOpTelemetry) RecordAuthSuccess(ctx context.Context, method, identity string) {}
func (n *NoOpTelemetry) RecordAuthFailure(ctx context.Context, method, reason string)   {}
func (n *NoOpTelemetry) RecordCertificateIssued(ctx context.Context, operation, subject, serialNumber string, ttl string) {
}
func (n *NoOpTelemetry) RecordCertificateRejected(ctx context.Context, operation, reason string) {}
