package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	_ "github.com/mabunixda/est-service/docs" // Swagger docs
	"github.com/mabunixda/est-service/internal/version"
	"github.com/mabunixda/est-service/pkg/auth"
	"github.com/mabunixda/est-service/pkg/backend"
	"github.com/mabunixda/est-service/pkg/config"
	"github.com/mabunixda/est-service/pkg/handlers"
	"github.com/mabunixda/est-service/pkg/observability"
	"github.com/mabunixda/est-service/pkg/server"
	"github.com/openbao/openbao/api/v2"
)

// @title EST Service API
// @version 1.0.0
// @description Enrollment over Secure Transport (EST) Service implementing RFC 7030.
// @description This service provides a standards-compliant EST implementation that uses OpenBao or HashiCorp Vault as the backend PKI system.
// @description
// @description **Authentication Methods:**
// @description - HTTP Basic Auth (mapped to backend userpass, LDAP, or AppRole)
// @description - TLS Client Certificates (mapped to backend cert auth)
// @description - Bearer Token (backend token authentication)

// @contact.name EST Service
// @contact.url https://github.com/mabunixda/est-service

// @license.name MPL-2.0
// @license.url https://www.mozilla.org/en-US/MPL/2.0/

// @host localhost:8443
// @BasePath /
// @schemes https http

// @tag.name EST
// @tag.description EST protocol endpoints (RFC 7030)
// @tag.name Health
// @tag.description Health and readiness checks
// @tag.name Metrics
// @tag.description Observability endpoints

// @securityDefinitions.basic BasicAuth
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization

func main() {
	var (
		configFile  = flag.String("config", "configs/est-service.yaml", "Path to configuration file")
		showVersion = flag.Bool("version", false, "Show version information")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("EST Service %s (commit: %s, built: %s)\n",
			version.Version, version.GitCommit, version.BuildDate)
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.Load(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	loggingStdout := true
	if cfg.Observability.Logging.Stdout != nil {
		loggingStdout = *cfg.Observability.Logging.Stdout
	}

	// Initialize logger
	logger, err := observability.SetupLogger(&observability.Config{
		LogLevel:  cfg.Observability.Logging.Level,
		LogFormat: cfg.Observability.Logging.Format,
		Stdout:    loggingStdout,
		File:      cfg.Observability.Logging.File,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	logger.Info("Starting EST Service", "version", version.Version)

	// Warn if in developer mode with enhanced safeguards
	if cfg.DeveloperMode {
		// Check for production environment indicators
		productionIndicators := map[string]string{
			"ENVIRONMENT":    os.Getenv("ENVIRONMENT"),
			"ENV":            os.Getenv("ENV"),
			"DEPLOYMENT_ENV": os.Getenv("DEPLOYMENT_ENV"),
			"GO_ENV":         os.Getenv("GO_ENV"),
		}

		for envVar, value := range productionIndicators {
			if value != "" {
				valueLower := strings.ToLower(value)
				if valueLower == "production" || valueLower == "prod" {
					logger.Error("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
					logger.Error("❌ FATAL SECURITY ERROR: developer_mode enabled in production")
					logger.Error("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
					logger.Error("❌ Environment variable indicates production deployment", "var", envVar, "value", value)
					logger.Error("❌ developer_mode MUST be disabled in production environments")
					logger.Error("❌ This configuration bypasses critical security controls")
					logger.Error("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
					os.Exit(1)
				}
			}
		}

		// Require explicit confirmation to use developer mode
		confirmationValue := os.Getenv("ALLOW_INSECURE_DEV_MODE")
		if confirmationValue != "yes-i-understand-the-risks" {
			logger.Error("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
			logger.Error("❌ developer_mode requires explicit confirmation")
			logger.Error("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
			logger.Error("❌ To use developer_mode, you must set:")
			logger.Error("❌   export ALLOW_INSECURE_DEV_MODE=yes-i-understand-the-risks")
			logger.Error("❌")
			logger.Error("❌ developer_mode disables critical security features:")
			logger.Error("❌   - TLS/HTTPS enforcement is DISABLED")
			logger.Error("❌   - All traffic may be UNENCRYPTED")
			logger.Error("❌   - Authentication may be weakened")
			logger.Error("❌   - This mode is for LOCAL DEVELOPMENT ONLY")
			logger.Error("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
			os.Exit(1)
		}

		// Print prominent warnings
		logger.Error("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		logger.Error("⚠️  ⚠️  ⚠️  ⚠️  ⚠️  DEVELOPER MODE ENABLED  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️")
		logger.Error("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		logger.Warn("⚠️  TLS enforcement is DISABLED")
		if cfg.Server.TLS.CertFile == "" || cfg.Server.TLS.KeyFile == "" {
			logger.Warn("⚠️  Running without TLS certificates - ALL TRAFFIC IS UNENCRYPTED")
		}
		logger.Warn("⚠️  Security controls may be relaxed")
		logger.Warn("⚠️  This mode is ONLY for local development and testing")
		logger.Warn("⚠️  NEVER use developer_mode in production environments")
		logger.Warn("⚠️  NEVER expose this service to the internet in developer_mode")
		logger.Error("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	}

	// Create backend client (OpenBao/Vault)
	ctx := context.Background()

	// Configure TLS for backend connection
	var backendTLSConfig *api.TLSConfig
	if cfg.Backend.CACert != "" || cfg.Backend.CAPath != "" || cfg.Backend.ClientCert != "" || cfg.Backend.TLSSkipVerify || cfg.Backend.TLSServerName != "" {
		backendTLSConfig = &api.TLSConfig{
			CACert:        cfg.Backend.CACert,
			CAPath:        cfg.Backend.CAPath,
			ClientCert:    cfg.Backend.ClientCert,
			ClientKey:     cfg.Backend.ClientKey,
			TLSServerName: cfg.Backend.TLSServerName,
			Insecure:      cfg.Backend.TLSSkipVerify,
		}
	}

	backendCfg := &backend.Config{
		Address:              cfg.Backend.Address,
		Token:                cfg.Backend.Token,
		Namespace:            cfg.Backend.Namespace,
		TLSConfig:            backendTLSConfig,
		TokenRenewalInterval: cfg.Backend.TokenRenewalInterval,
		Timeout:              cfg.Backend.Timeout,
		MaxRetries:           cfg.Backend.MaxRetries,
		MinRetryWait:         cfg.Backend.MinRetryWait,
		MaxRetryWait:         cfg.Backend.MaxRetryWait,
		Type:                 backend.BackendType(cfg.Backend.Type), // Pass configured type (or empty for auto-detect)
	}
	backendClient, err := backend.NewClient(ctx, backendCfg, logger)
	if err != nil {
		logger.Error("Failed to create backend client", "error", err)
		os.Exit(1)
	}

	// Configure authentication
	authCfg := &auth.Config{
		UserpassEnabled:       cfg.EST.Authenticators.Userpass.Enabled,
		UserpassMountPath:     cfg.EST.Authenticators.Userpass.MountPath,
		LDAPEnabled:           cfg.EST.Authenticators.LDAP.Enabled,
		LDAPMountPath:         cfg.EST.Authenticators.LDAP.MountPath,
		AppRoleEnabled:        cfg.EST.Authenticators.AppRole.Enabled,
		AppRoleMountPath:      cfg.EST.Authenticators.AppRole.MountPath,
		CertEnabled:           cfg.EST.Authenticators.Cert.Enabled,
		CertMountPath:         cfg.EST.Authenticators.Cert.MountPath,
		CertRole:              cfg.EST.Authenticators.Cert.CertRole,
		CertEntityAliasPrefix: cfg.EST.Authenticators.Cert.EntityAliasPrefix,
		CertTokenTTL:          cfg.EST.Authenticators.Cert.TokenTTL,
		TokenEnabled:          cfg.EST.Authenticators.Token.Enabled,
	}

	// Configure enrollment
	enrollmentCfg := &handlers.EnrollmentConfig{
		DefaultMount: cfg.EST.DefaultMount,
		DefaultPolicy: handlers.LabelPolicy{
			Type:  cfg.EST.DefaultPolicy.Type,
			Value: cfg.EST.DefaultPolicy.Value,
			TTL:   cfg.EST.DefaultPolicy.TTL, // Certificate TTL
		},
		Labels:                make(map[string]handlers.LabelPolicy),
		MaxCSRSize:            int64(cfg.EST.CSRValidation.MaxSizeBytes),
		AllowedSignatureAlgos: cfg.EST.CSRValidation.AllowedSignatureAlgorithms,
	}

	// Convert label configs
	for name, labelCfg := range cfg.EST.Labels {
		enrollmentCfg.Labels[name] = handlers.LabelPolicy{
			Type:  labelCfg.Type,
			Value: labelCfg.Value,
			TTL:   labelCfg.TTL, // Certificate TTL for this label
		}
	}

	auditStdout := true
	if cfg.Observability.Audit.Stdout != nil {
		auditStdout = *cfg.Observability.Audit.Stdout
	}
	var auditLogger *slog.Logger
	if cfg.Observability.Audit.Enabled {
		auditLogger, err = observability.SetupAuditLogger(&observability.AuditConfig{
			Enabled: cfg.Observability.Audit.Enabled,
			Stdout:  auditStdout,
			File:    cfg.Observability.Audit.File,
		})
		if err != nil {
			logger.Error("Failed to initialize audit logger", "error", err)
			os.Exit(1)
		}
	}

	// Create and start server
	srvCfg := &server.Config{
		ListenAddr:       cfg.Server.ListenAddress,
		ReadTimeout:      cfg.Server.ReadTimeout,
		WriteTimeout:     cfg.Server.WriteTimeout,
		IdleTimeout:      cfg.Server.IdleTimeout,
		PKIMount:         cfg.EST.DefaultMount,
		AuthConfig:       authCfg,
		EnrollmentConfig: enrollmentCfg,
		InternalEndpointsAuth: func() bool {
			if cfg.Server.InternalEndpointsAuth == nil {
				return !cfg.DeveloperMode
			}
			return *cfg.Server.InternalEndpointsAuth
		}(),
		AuditEnabled:    cfg.Observability.Audit.Enabled,
		AuditLogger:     auditLogger,
		CSRAttrsEnabled: cfg.EST.CSRAttributes.Enabled,
		CSRAttrsOIDs:    cfg.EST.CSRAttributes.Attributes,

		// RFC 7030 Section 4.4 - Server-side key generation
		ServerKeyGenEnabled:              cfg.EST.ServerKeyGen.Enabled,
		ServerKeyGenKeyType:              cfg.EST.ServerKeyGen.DefaultKeyType,
		ServerKeyGenKeySize:              cfg.EST.ServerKeyGen.DefaultKeySize,
		ServerKeyGenAllowedTypes:         cfg.EST.ServerKeyGen.AllowedKeyTypes,
		ServerKeyGenAllowedSizes:         cfg.EST.ServerKeyGen.AllowedKeySizes,
		ServerKeyGenMaxCSRSize:           cfg.EST.ServerKeyGen.MaxCSRSize,
		ServerKeyGenUseAuthToken:         cfg.EST.ServerKeyGen.UseAuthToken,
		ServerKeyGenEncryptKey:           cfg.EST.ServerKeyGen.EncryptPrivateKey,
		ServerKeyGenUseVaultTransit:      cfg.EST.ServerKeyGen.UseVaultTransit,
		ServerKeyGenTransitMount:         cfg.EST.ServerKeyGen.TransitMount,
		ServerKeyGenTransitKeyNamePrefix: cfg.EST.ServerKeyGen.TransitKeyNamePrefix,
	}

	// Configure telemetry (OpenTelemetry)
	if cfg.Observability.Metrics.Enabled {
		srvCfg.Telemetry = &server.TelemetryConfig{
			ServiceName:    "est-service",
			ServiceVersion: version.Version,
			PrometheusPort: cfg.Observability.Metrics.PrometheusPort,
			OTLPEndpoint:   cfg.Observability.Metrics.OTLPEndpoint,
			OTLPInsecure:   cfg.Observability.Metrics.OTLPInsecure,
		}
	}

	// Configure rate limiting
	if cfg.Server.RateLimit.Enabled {
		srvCfg.RateLimit = &server.RateLimitConfig{
			Enabled:               cfg.Server.RateLimit.Enabled,
			RequestsPerSecond:     cfg.Server.RateLimit.RequestsPerSecond,
			Burst:                 cfg.Server.RateLimit.Burst,
			TrustedProxyCIDRs:     cfg.Server.RateLimit.TrustedProxyCIDRs,
			AuthRequestsPerSecond: cfg.Server.RateLimit.AuthRequestsPerSecond,
			AuthBurst:             cfg.Server.RateLimit.AuthBurst,
		}
	}
	// Configure TLS if cert/key files are provided
	if cfg.Server.TLS.CertFile != "" && cfg.Server.TLS.KeyFile != "" {
		srvCfg.TLSConfig = &server.TLSConfig{
			CertFile:           cfg.Server.TLS.CertFile,
			KeyFile:            cfg.Server.TLS.KeyFile,
			ClientCAFile:       cfg.Server.TLS.ClientCAFile,
			ClientAuthRequired: cfg.Server.TLS.ClientAuthType == "require",
		}
	}

	srv, err := server.New(backendClient, srvCfg, logger)
	if err != nil {
		logger.Error("Failed to create server", "error", err)
		os.Exit(1)
	}

	// Handle shutdown gracefully
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Info("Received shutdown signal")
		cancel()
	}()

	if err := srv.Start(ctx); err != nil {
		logger.Error("Server error", "error", err)
		os.Exit(1)
	}

	logger.Info("EST Service stopped")
}
