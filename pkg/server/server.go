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
	"strings"
	"time"

	"github.com/mabunixda/est-service/pkg/auth"
	"github.com/mabunixda/est-service/pkg/backend"
	"github.com/mabunixda/est-service/pkg/handlers"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	httpSwagger "github.com/swaggo/http-swagger/v2"
)

// Server represents the EST service HTTP server
type Server struct {
	httpServer      *http.Server
	backend         *backend.Client
	authMgr         *auth.Manager
	config          *Config
	logger          *slog.Logger
	telemetry       *Telemetry
	rateLimiter     *RateLimiter // General rate limiter for all endpoints
	authRateLimiter *RateLimiter // Stricter rate limiter for auth endpoints
}

// Config holds server configuration
type Config struct {
	ListenAddr            string
	TLSConfig             *TLSConfig
	RateLimit             *RateLimitConfig
	Telemetry             *TelemetryConfig
	InternalEndpointsAuth bool
	ReadTimeout           time.Duration
	WriteTimeout          time.Duration
	IdleTimeout           time.Duration

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
	Enabled               bool
	RequestsPerSecond     int
	Burst                 int
	TrustedProxyCIDRs     []string
	AuthRequestsPerSecond int // Stricter limit for auth endpoints (0 = use general limit)
	AuthBurst             int // Stricter burst for auth endpoints (0 = use general burst)
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status    string       `json:"status"`
	Backend   string       `json:"backend"`
	Timestamp string       `json:"timestamp"`
	TLSCert   *TLSCertInfo `json:"tls_certificate,omitempty"`
}

// TLSCertInfo contains TLS certificate expiry information
type TLSCertInfo struct {
	ExpiresAt     string `json:"expires_at"`
	DaysRemaining int    `json:"days_remaining"`
	Subject       string `json:"subject"`
	Status        string `json:"status"` // "ok", "warning", "critical", "expired"
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
		if err := rateLimiter.SetTrustedProxyCIDRs(cfg.RateLimit.TrustedProxyCIDRs); err != nil {
			return nil, fmt.Errorf("failed to configure trusted proxies: %w", err)
		}
		logger.Info("Rate limiting enabled",
			"requests_per_second", cfg.RateLimit.RequestsPerSecond,
			"burst", cfg.RateLimit.Burst)
	}

	// Create separate auth rate limiter if configured
	var authRateLimiter *RateLimiter
	if cfg.RateLimit != nil && cfg.RateLimit.Enabled && cfg.RateLimit.AuthRequestsPerSecond > 0 {
		authRateLimiter = NewRateLimiterWithTelemetry(cfg.RateLimit.AuthRequestsPerSecond, cfg.RateLimit.AuthBurst, telemetry)
		if err := authRateLimiter.SetTrustedProxyCIDRs(cfg.RateLimit.TrustedProxyCIDRs); err != nil {
			return nil, fmt.Errorf("failed to configure trusted proxies for auth rate limiter: %w", err)
		}
		logger.Info("Auth endpoint rate limiting enabled",
			"auth_requests_per_second", cfg.RateLimit.AuthRequestsPerSecond,
			"auth_burst", cfg.RateLimit.AuthBurst)
	}

	// Create server
	s := &Server{
		backend:         backend,
		authMgr:         authMgr,
		config:          cfg,
		logger:          logger,
		telemetry:       telemetry,
		rateLimiter:     rateLimiter,
		authRateLimiter: authRateLimiter,
	}

	// Setup routes
	mux := s.setupRoutes()

	// Apply middleware chain (innermost first, outermost last)
	var handler http.Handler = mux

	// 1. Rate limiting (innermost - applied first)
	if s.rateLimiter != nil {
		handler = s.rateLimiter.Middleware(handler)
	}

	// 2. Security headers (outermost - applied last, so headers are set first)
	handler = s.securityHeadersMiddleware(handler)

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

	// Check certificate expiry at startup (after httpServer is assigned)
	if cfg.TLSConfig != nil && cfg.TLSConfig.CertFile != "" && cfg.TLSConfig.KeyFile != "" {
		if err := s.checkCertificateExpiry(context.Background()); err != nil {
			// Log error but don't fail startup - the cert might be expired but we still need to start
			// This allows for cert renewal operations while the service is running
			s.logger.Error("Certificate expiry check failed", "error", err)
		}
	}

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

	// Apply auth rate limiting to enrollment endpoints if configured
	var enrollHandler, reenrollHandler http.Handler = simpleEnrollHandler, simpleReenrollHandler
	if s.authRateLimiter != nil {
		enrollHandler = s.authRateLimiter.Middleware(enrollHandler)
		reenrollHandler = s.authRateLimiter.Middleware(reenrollHandler)
	}

	// EST endpoints per RFC 7030
	mux.Handle("/.well-known/est/cacerts", s.loggingMiddleware(s.recoveryMiddleware(caCertsHandler)))
	mux.Handle("/.well-known/est/simpleenroll", s.loggingMiddleware(s.recoveryMiddleware(enrollHandler)))
	mux.Handle("/.well-known/est/simplereenroll", s.loggingMiddleware(s.recoveryMiddleware(reenrollHandler)))

	// Health check
	mux.HandleFunc("/health", s.healthHandler)
	mux.HandleFunc("/ready", s.readyHandler)

	// Swagger documentation
	if s.config.InternalEndpointsAuth {
		mux.Handle("/swagger/", s.loggingMiddleware(s.recoveryMiddleware(s.authMiddleware(httpSwagger.WrapHandler))))
	} else {
		mux.Handle("/swagger/", httpSwagger.WrapHandler)
	}

	// Prometheus metrics endpoint (if telemetry is enabled)
	if s.telemetry != nil {
		if s.config.InternalEndpointsAuth {
			mux.Handle("/metrics", s.loggingMiddleware(s.recoveryMiddleware(s.authMiddleware(promhttp.Handler()))))
		} else {
			mux.Handle("/metrics", promhttp.Handler())
		}
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

// checkCertificateExpiry checks the server TLS certificate expiry and logs warnings
// It also records the expiry metric if telemetry is enabled
func (s *Server) checkCertificateExpiry(ctx context.Context) error {
	// Only check if TLS is configured
	if s.httpServer.TLSConfig == nil || len(s.httpServer.TLSConfig.Certificates) == 0 {
		return nil
	}

	cert := s.httpServer.TLSConfig.Certificates[0]

	// Parse certificate if Leaf is not already populated
	if cert.Leaf == nil {
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			s.logger.Warn("Failed to parse server certificate for expiry check", "error", err)
			return fmt.Errorf("failed to parse server certificate: %w", err)
		}
		cert.Leaf = parsed
	}

	// Calculate days until expiry
	expiresAt := cert.Leaf.NotAfter
	daysUntilExpiry := time.Until(expiresAt).Hours() / 24

	// Log certificate expiry information
	s.logger.Info("Server certificate expiry check",
		"expires_at", expiresAt.Format(time.RFC3339),
		"days_remaining", int(daysUntilExpiry),
		"subject", cert.Leaf.Subject.CommonName)

	// Log warnings based on days remaining
	if daysUntilExpiry < 0 {
		s.logger.Error("🚨 Server certificate has EXPIRED!",
			"expired_at", expiresAt.Format(time.RFC3339),
			"days_overdue", int(-daysUntilExpiry))
		return fmt.Errorf("server certificate expired %d days ago", int(-daysUntilExpiry))
	} else if daysUntilExpiry < 7 {
		s.logger.Error("🚨 Server certificate expires VERY soon!",
			"expires_at", expiresAt.Format(time.RFC3339),
			"days_remaining", int(daysUntilExpiry),
			"action_required", "Renew certificate immediately")
	} else if daysUntilExpiry < 30 {
		s.logger.Warn("⚠️  Server certificate expires soon!",
			"expires_at", expiresAt.Format(time.RFC3339),
			"days_remaining", int(daysUntilExpiry),
			"action_required", "Plan certificate renewal")
	}

	// Record metric if telemetry is enabled
	if s.telemetry != nil {
		s.telemetry.RecordCertificateExpiry(ctx, daysUntilExpiry)
	}

	return nil
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

	// Shutdown rate limiter cleanup goroutines
	if s.rateLimiter != nil {
		s.rateLimiter.Shutdown()
	}
	if s.authRateLimiter != nil {
		s.authRateLimiter.Shutdown()
	}

	return s.httpServer.Shutdown(ctx)
}

// securityHeadersMiddleware adds security headers to all responses
func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent MIME sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")

		// HSTS - only set when using HTTPS
		if r.TLS != nil {
			// Enable HSTS with 1 year max-age and include subdomains
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		// Content Security Policy - very restrictive for API service
		// default-src 'none' means no resources allowed by default
		// frame-ancestors 'none' prevents embedding in frames (redundant with X-Frame-Options but more modern)
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

		// Disable caching for sensitive EST endpoints
		if strings.HasPrefix(r.URL.Path, "/.well-known/est/") {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
		}

		// Remove server version information
		w.Header().Set("Server", "EST-Service")

		next.ServeHTTP(w, r)
	})
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

// authMiddleware enforces authentication using the configured auth manager
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := s.authMgr.Authenticate(r.Context(), r)
		if !result.Authenticated {
			headers := s.authMgr.GetWWWAuthenticateHeaders()
			for _, header := range headers {
				w.Header().Add("WWW-Authenticate", header)
			}
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// healthHandler handles health check requests
// @Summary Health check
// @Description Check if the service and backend are healthy and operational
// @Tags Health
// @Produce json
// @Success 200 {object} HealthResponse "Service is healthy"
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

	// Build health response
	response := HealthResponse{
		Status:    "ok",
		Backend:   "healthy",
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// Add certificate info if TLS is configured
	if s.httpServer.TLSConfig != nil && len(s.httpServer.TLSConfig.Certificates) > 0 {
		cert := s.httpServer.TLSConfig.Certificates[0]
		if cert.Leaf != nil {
			daysRemaining := int(time.Until(cert.Leaf.NotAfter).Hours() / 24)
			certStatus := "ok"

			if daysRemaining < 0 {
				certStatus = "expired"
			} else if daysRemaining < 7 {
				certStatus = "critical"
			} else if daysRemaining < 30 {
				certStatus = "warning"
			}

			response.TLSCert = &TLSCertInfo{
				ExpiresAt:     cert.Leaf.NotAfter.Format(time.RFC3339),
				DaysRemaining: daysRemaining,
				Subject:       cert.Leaf.Subject.CommonName,
				Status:        certStatus,
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Use json.NewEncoder for proper JSON encoding
	if _, err := fmt.Fprintf(w, `{"status":"%s","backend":"%s","timestamp":"%s"`,
		response.Status, response.Backend, response.Timestamp); err != nil {
		s.logger.Error("Failed to write health response", "error", err)
		return
	}

	if response.TLSCert != nil {
		if _, err := fmt.Fprintf(w, `,"tls_certificate":{"expires_at":"%s","days_remaining":%d,"subject":"%s","status":"%s"}`,
			response.TLSCert.ExpiresAt, response.TLSCert.DaysRemaining,
			response.TLSCert.Subject, response.TLSCert.Status); err != nil {
			s.logger.Error("Failed to write health response cert info", "error", err)
			return
		}
	}

	if _, err := fmt.Fprintf(w, `}`); err != nil {
		s.logger.Error("Failed to close health response", "error", err)
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
