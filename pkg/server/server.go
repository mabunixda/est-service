package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/mabunixda/est-service/pkg/auth"
	"github.com/mabunixda/est-service/pkg/backend"
	"github.com/mabunixda/est-service/pkg/handlers"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	httpSwagger "github.com/swaggo/http-swagger/v2"
)

// Server represents the EST service HTTP server
type Server struct {
	httpServer  *http.Server
	backend     *backend.Client
	authMgr     *auth.Manager
	config      *Config
	logger      *slog.Logger
	telemetry   *Telemetry
	rateLimiter *RateLimiter
}

// Config holds server configuration
type Config struct {
	ListenAddr   string
	TLSConfig    *TLSConfig
	RateLimit    *RateLimitConfig
	Telemetry    *TelemetryConfig
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	// EST configuration
	PKIMount         string
	AuthConfig       *auth.Config
	EnrollmentConfig *handlers.EnrollmentConfig
}

// TLSConfig holds TLS configuration
type TLSConfig struct {
	CertFile           string
	KeyFile            string
	ClientCAFile       string
	ClientAuthRequired bool
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	Enabled           bool
	RequestsPerSecond int
	Burst             int
}

// New creates a new EST server
func New(backend *backend.Client, cfg *Config, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// Set defaults
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 15 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 15 * time.Second
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 60 * time.Second
	}

	// Create authentication manager
	authMgr := auth.NewManager(backend, cfg.AuthConfig, logger)

	// Create telemetry if enabled
	var telemetry *Telemetry
	if cfg.Telemetry != nil {
		var err error
		telemetry, err = NewTelemetry(context.Background(), cfg.Telemetry, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize telemetry: %w", err)
		}
	}

	// Create rate limiter if enabled
	var rateLimiter *RateLimiter
	if cfg.RateLimit != nil && cfg.RateLimit.Enabled {
		rateLimiter = NewRateLimiterWithTelemetry(cfg.RateLimit.RequestsPerSecond, cfg.RateLimit.Burst, telemetry)
		logger.Info("Rate limiting enabled",
			"requests_per_second", cfg.RateLimit.RequestsPerSecond,
			"burst", cfg.RateLimit.Burst)
	}

	// Create server
	s := &Server{
		backend:     backend,
		authMgr:     authMgr,
		config:      cfg,
		logger:      logger,
		telemetry:   telemetry,
		rateLimiter: rateLimiter,
	}

	// Setup routes
	mux := s.setupRoutes()

	// Wrap mux with rate limiting if enabled
	var handler http.Handler = mux
	if s.rateLimiter != nil {
		handler = s.rateLimiter.Middleware(handler)
	}

	// Create HTTP server
	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadTimeout:       cfg.ReadTimeout,
		ReadHeaderTimeout: 10 * time.Second, // Prevent Slowloris attacks
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}

	// Configure TLS if cert/key files are provided
	if cfg.TLSConfig != nil && cfg.TLSConfig.CertFile != "" && cfg.TLSConfig.KeyFile != "" {
		tlsConfig, err := s.setupTLS(cfg.TLSConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to setup TLS: %w", err)
		}
		httpServer.TLSConfig = tlsConfig
	}

	s.httpServer = httpServer

	return s, nil
}

// setupRoutes configures the HTTP routes for EST endpoints
func (s *Server) setupRoutes() *http.ServeMux {
	mux := http.NewServeMux()

	// Create handlers
	caCertsHandler := handlers.NewCACertsHandler(s.backend, s.config.PKIMount, s.logger)

	// Get telemetry interface or use no-op
	var telemetry handlers.Telemetry = &handlers.NoOpTelemetry{}
	if s.telemetry != nil {
		telemetry = s.telemetry
	}

	simpleEnrollHandler := handlers.NewSimpleEnrollHandler(s.backend, s.authMgr, s.config.EnrollmentConfig, s.logger, telemetry)
	simpleReenrollHandler := handlers.NewSimpleReenrollHandler(s.backend, s.authMgr, s.config.EnrollmentConfig, s.logger, telemetry)

	// EST endpoints per RFC 7030
	mux.Handle("/.well-known/est/cacerts", s.loggingMiddleware(s.recoveryMiddleware(caCertsHandler)))
	mux.Handle("/.well-known/est/simpleenroll", s.loggingMiddleware(s.recoveryMiddleware(simpleEnrollHandler)))
	mux.Handle("/.well-known/est/simplereenroll", s.loggingMiddleware(s.recoveryMiddleware(simpleReenrollHandler)))

	// Health check
	mux.HandleFunc("/health", s.healthHandler)
	mux.HandleFunc("/ready", s.readyHandler)

	// Swagger documentation
	mux.Handle("/swagger/", httpSwagger.WrapHandler)

	// Prometheus metrics endpoint (if telemetry is enabled)
	if s.telemetry != nil {
		mux.Handle("/metrics", promhttp.Handler())
	}

	return mux
}

// setupTLS configures TLS settings including optional client certificate authentication
func (s *Server) setupTLS(cfg *TLSConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	// Load client CA for client certificate authentication
	if cfg.ClientCAFile != "" {
		caCert, err := os.ReadFile(cfg.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read client CA file: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse client CA certificate")
		}

		// Count CA certificates by parsing the PEM data manually
		// Note: Subjects() is deprecated in Go 1.18+
		var caCount int
		block, rest := pem.Decode(caCert)
		for block != nil {
			if block.Type == "CERTIFICATE" {
				caCount++
			}
			block, rest = pem.Decode(rest)
		}

		switch caCount {
		case 0:
			return nil, fmt.Errorf("no valid CA certificates found in %s", cfg.ClientCAFile)
		case 1:
			s.logger.Info("TLS client CA configured",
				"ca_file", cfg.ClientCAFile,
				"ca_count", caCount)
			s.logger.Warn("Single CA configured - re-enrollment with device certs may fail",
				"recommendation", "Use combined CA bundle for RFC 7030 compliant re-enrollment")
		default:
			s.logger.Info("TLS client CA bundle configured (multi-CA setup)",
				"ca_file", cfg.ClientCAFile,
				"ca_count", caCount,
				"note", "Supports both bootstrap certs and device cert re-enrollment")
		}

		tlsConfig.ClientCAs = caCertPool

		if cfg.ClientAuthRequired {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}

	return tlsConfig, nil
}

// Start starts the EST server
func (s *Server) Start(ctx context.Context) error {
	s.logger.Info("Starting EST server", "address", s.config.ListenAddr)

	// Start server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		if s.config.TLSConfig != nil && s.config.TLSConfig.CertFile != "" && s.config.TLSConfig.KeyFile != "" {
			s.logger.Info("Starting HTTPS server",
				"cert", s.config.TLSConfig.CertFile,
				"key", s.config.TLSConfig.KeyFile)

			// IMPORTANT: We must use ServeTLS (not ListenAndServeTLS) because we have
			// custom TLS configuration (client certificate auth) in httpServer.TLSConfig.
			// ListenAndServeTLS would ignore our TLSConfig and create its own.

			// Create listener
			ln, err := net.Listen("tcp", s.httpServer.Addr)
			if err != nil {
				errChan <- err
				return
			}

			// Wrap with TLS using our configured TLSConfig
			tlsListener := tls.NewListener(ln, s.httpServer.TLSConfig)

			// Serve using the TLS listener
			if err := s.httpServer.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
				errChan <- err
			}
		} else {
			s.logger.Info("Starting HTTP server")
			if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				errChan <- err
			}
		}
	}()

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		s.logger.Info("Shutting down server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return s.Shutdown(shutdownCtx)
	case err := <-errChan:
		return fmt.Errorf("server error: %w", err)
	}
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("Server shutdown initiated")

	// Shutdown rate limiter cleanup goroutine
	if s.rateLimiter != nil {
		s.rateLimiter.Shutdown()
	}

	return s.httpServer.Shutdown(ctx)
}

// loggingMiddleware logs HTTP requests
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Track active connections
		if s.telemetry != nil {
			s.telemetry.IncrementActiveConnections(r.Context())
			defer s.telemetry.DecrementActiveConnections(r.Context())
		}

		// Wrap response writer to capture status code
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Call the next handler
		next.ServeHTTP(rw, r)

		// Record metrics
		if s.telemetry != nil {
			duration := time.Since(start)
			s.telemetry.RecordRequest(r.Context(), r.Method, r.URL.Path, rw.statusCode, duration)
		}

		// Log the request
		s.logger.Info("HTTP request",
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
			"user_agent", r.UserAgent(),
			"status", rw.statusCode,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

// recoveryMiddleware recovers from panics
func (s *Server) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				s.logger.Error("Panic recovered",
					"error", err,
					"method", r.Method,
					"path", r.URL.Path)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// healthHandler handles health check requests
// @Summary Health check
// @Description Check if the service and backend are healthy and operational
// @Tags Health
// @Produce json
// @Success 200 {object} map[string]string "Service is healthy"
// @Failure 503 {string} string "Service or backend unavailable"
// @Router /health [get]
func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check backend health
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	health, err := s.backend.Health(ctx)
	if err != nil {
		s.logger.Error("Backend health check failed", "error", err)
		http.Error(w, "Backend unavailable", http.StatusServiceUnavailable)
		return
	}

	if health.Sealed {
		s.logger.Warn("Backend is sealed")
		http.Error(w, "Backend sealed", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprintf(w, `{"status":"ok","backend":"healthy"}`); err != nil {
		s.logger.Error("Failed to write health response", "error", err)
	}
}

// readyHandler handles readiness check requests
// @Summary Readiness check
// @Description Check if the service is ready to accept requests
// @Tags Health
// @Produce json
// @Success 200 {object} map[string]string "Service is ready"
// @Router /ready [get]
func (s *Server) readyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprintf(w, `{"status":"ready"}`); err != nil {
		s.logger.Error("Failed to write ready response", "error", err)
	}
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
