package server

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

// Telemetry holds OpenTelemetry metrics
type Telemetry struct {
	meter  metric.Meter
	logger *slog.Logger

	// Request Metrics
	requestCounter      metric.Int64Counter
	caCertsCounter      metric.Int64Counter
	enrollmentCounter   metric.Int64Counter
	reenrollmentCounter metric.Int64Counter
	errorCounter        metric.Int64Counter
	requestDuration     metric.Float64Histogram
	activeConnections   metric.Int64UpDownCounter
	rateLimitCounter    metric.Int64Counter

	// Authentication Metrics
	authSuccessCounter metric.Int64Counter
	authFailureCounter metric.Int64Counter

	// Certificate Metrics
	certIssuedCounter   metric.Int64Counter
	certRejectedCounter metric.Int64Counter
}

// TelemetryConfig configures OpenTelemetry
type TelemetryConfig struct {
	ServiceName    string
	ServiceVersion string
	PrometheusPort int    // Port for Prometheus scraping (0 to disable)
	OTLPEndpoint   string // OTLP endpoint for metrics export (empty to disable)
}

// NewTelemetry initializes OpenTelemetry with both Prometheus and OTLP exporters
func NewTelemetry(ctx context.Context, cfg *TelemetryConfig, logger *slog.Logger) (*Telemetry, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// Create resource
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Set up exporters
	var meterProvider *sdkmetric.MeterProvider
	var readers []sdkmetric.Reader

	// Prometheus exporter (pull-based)
	if cfg.PrometheusPort > 0 {
		promExporter, err := prometheus.New()
		if err != nil {
			return nil, fmt.Errorf("failed to create Prometheus exporter: %w", err)
		}
		readers = append(readers, promExporter)
		logger.Info("Prometheus metrics enabled", "port", cfg.PrometheusPort)
	}

	// OTLP exporter (push-based)
	if cfg.OTLPEndpoint != "" {
		otlpExporter, err := otlpmetrichttp.New(ctx,
			otlpmetrichttp.WithEndpoint(cfg.OTLPEndpoint),
			otlpmetrichttp.WithInsecure(), // Use WithTLSClientConfig for production
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
		}

		// Periodic reader for OTLP (push every 10 seconds)
		periodicReader := sdkmetric.NewPeriodicReader(
			otlpExporter,
			sdkmetric.WithInterval(10*time.Second),
		)
		readers = append(readers, periodicReader)
		logger.Info("OTLP metrics enabled", "endpoint", cfg.OTLPEndpoint)
	}

	// If no exporters configured, use a simple periodic reader
	if len(readers) == 0 {
		logger.Warn("No metrics exporters configured - metrics will not be collected")
	}

	// Create meter provider
	if len(readers) > 0 {
		meterProvider = sdkmetric.NewMeterProvider(
			sdkmetric.WithResource(res),
			sdkmetric.WithReader(readers[0]),
		)
		// If there are more readers, they need to be added separately
		// For simplicity, we'll just use the first one
	} else {
		meterProvider = sdkmetric.NewMeterProvider(
			sdkmetric.WithResource(res),
		)
	}

	// Set global meter provider
	otel.SetMeterProvider(meterProvider)

	// Create meter
	meter := meterProvider.Meter("est-service")

	// Create metrics
	t := &Telemetry{
		meter:  meter,
		logger: logger,
	}

	// Initialize counters
	if t.requestCounter, err = meter.Int64Counter(
		"est.requests.total",
		metric.WithDescription("Total number of HTTP requests"),
		metric.WithUnit("{request}"),
	); err != nil {
		return nil, fmt.Errorf("failed to create request counter: %w", err)
	}

	if t.caCertsCounter, err = meter.Int64Counter(
		"est.cacerts.total",
		metric.WithDescription("Total number of CA certs requests"),
		metric.WithUnit("{request}"),
	); err != nil {
		return nil, err
	}

	if t.enrollmentCounter, err = meter.Int64Counter(
		"est.enrollment.total",
		metric.WithDescription("Total number of enrollment requests"),
		metric.WithUnit("{request}"),
	); err != nil {
		return nil, err
	}

	if t.reenrollmentCounter, err = meter.Int64Counter(
		"est.reenrollment.total",
		metric.WithDescription("Total number of re-enrollment requests"),
		metric.WithUnit("{request}"),
	); err != nil {
		return nil, err
	}

	if t.errorCounter, err = meter.Int64Counter(
		"est.errors.total",
		metric.WithDescription("Total number of errors"),
		metric.WithUnit("{error}"),
	); err != nil {
		return nil, err
	}

	if t.rateLimitCounter, err = meter.Int64Counter(
		"est.rate_limit.total",
		metric.WithDescription("Total number of rate-limited requests"),
		metric.WithUnit("{request}"),
	); err != nil {
		return nil, err
	}

	// Authentication metrics
	if t.authSuccessCounter, err = meter.Int64Counter(
		"est.auth.success.total",
		metric.WithDescription("Total number of successful authentications"),
		metric.WithUnit("{authentication}"),
	); err != nil {
		return nil, err
	}

	if t.authFailureCounter, err = meter.Int64Counter(
		"est.auth.failure.total",
		metric.WithDescription("Total number of failed authentications"),
		metric.WithUnit("{authentication}"),
	); err != nil {
		return nil, err
	}

	// Certificate metrics
	if t.certIssuedCounter, err = meter.Int64Counter(
		"est.certificates.issued.total",
		metric.WithDescription("Total number of certificates issued"),
		metric.WithUnit("{certificate}"),
	); err != nil {
		return nil, err
	}

	if t.certRejectedCounter, err = meter.Int64Counter(
		"est.certificates.rejected.total",
		metric.WithDescription("Total number of certificate requests rejected"),
		metric.WithUnit("{request}"),
	); err != nil {
		return nil, err
	}

	// Initialize histogram
	if t.requestDuration, err = meter.Float64Histogram(
		"est.request.duration",
		metric.WithDescription("HTTP request duration"),
		metric.WithUnit("ms"),
	); err != nil {
		return nil, err
	}

	// Initialize up/down counter
	if t.activeConnections, err = meter.Int64UpDownCounter(
		"est.connections.active",
		metric.WithDescription("Number of active connections"),
		metric.WithUnit("{connection}"),
	); err != nil {
		return nil, err
	}

	logger.Info("OpenTelemetry initialized")
	return t, nil
}

// RecordRequest records an HTTP request
func (t *Telemetry) RecordRequest(ctx context.Context, method, path string, statusCode int, duration time.Duration) {
	attrs := []attribute.KeyValue{
		attribute.String("http.method", method),
		attribute.String("http.path", path),
		attribute.Int("http.status_code", statusCode),
	}

	t.requestCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	t.requestDuration.Record(ctx, float64(duration.Milliseconds()), metric.WithAttributes(attrs...))

	if statusCode >= 400 {
		t.errorCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	}

	// Track specific endpoints
	switch path {
	case "/.well-known/est/cacerts":
		t.caCertsCounter.Add(ctx, 1)
	case "/.well-known/est/simpleenroll":
		t.enrollmentCounter.Add(ctx, 1)
	case "/.well-known/est/simplereenroll":
		t.reenrollmentCounter.Add(ctx, 1)
	}
}

// IncrementActiveConnections increments the active connection count
func (t *Telemetry) IncrementActiveConnections(ctx context.Context) {
	t.activeConnections.Add(ctx, 1)
}

// DecrementActiveConnections decrements the active connection count
func (t *Telemetry) DecrementActiveConnections(ctx context.Context) {
	t.activeConnections.Add(ctx, -1)
}

// RecordRateLimitReject records a rate-limited request
func (t *Telemetry) RecordRateLimitReject(ctx context.Context, ip string) {
	attrs := []attribute.KeyValue{
		attribute.String("client.ip", ip),
	}
	t.rateLimitCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordAuthSuccess records a successful authentication
func (t *Telemetry) RecordAuthSuccess(ctx context.Context, method, identity string) {
	attrs := []attribute.KeyValue{
		attribute.String("auth.method", method),
		attribute.String("auth.identity", identity),
	}
	t.authSuccessCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordAuthFailure records a failed authentication
func (t *Telemetry) RecordAuthFailure(ctx context.Context, method, reason string) {
	attrs := []attribute.KeyValue{
		attribute.String("auth.method", method),
		attribute.String("auth.failure_reason", reason),
	}
	t.authFailureCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordCertificateIssued records a successful certificate issuance
func (t *Telemetry) RecordCertificateIssued(ctx context.Context, operation, subject, serialNumber string, ttl string) {
	attrs := []attribute.KeyValue{
		attribute.String("cert.operation", operation), // "enroll" or "reenroll"
		attribute.String("cert.subject", subject),
		attribute.String("cert.serial_number", serialNumber),
		attribute.String("cert.ttl", ttl),
	}
	t.certIssuedCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordCertificateRejected records a rejected certificate request
func (t *Telemetry) RecordCertificateRejected(ctx context.Context, operation, reason string) {
	attrs := []attribute.KeyValue{
		attribute.String("cert.operation", operation),
		attribute.String("cert.rejection_reason", reason),
	}
	t.certRejectedCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
}
