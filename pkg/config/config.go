package config

import (
	"time"
)

// Config represents the complete service configuration
type Config struct {
	DeveloperMode bool                `yaml:"developer_mode"` // Allows HTTP without TLS (NOT for production)
	Server        ServerConfig        `yaml:"server"`
	Backend       BackendConfig       `yaml:"backend"`
	EST           ESTConfig           `yaml:"est"`
	Observability ObservabilityConfig `yaml:"observability"`
}

// ServerConfig configures the HTTP server
type ServerConfig struct {
	ListenAddress string          `yaml:"listen_address"`
	TLS           TLSConfig       `yaml:"tls"`
	RateLimit     RateLimitConfig `yaml:"rate_limit"`
	// InternalEndpointsAuth controls auth for internal endpoints like /metrics and /swagger
	InternalEndpointsAuth *bool         `yaml:"internal_endpoints_auth"`
	ReadTimeout           time.Duration `yaml:"read_timeout"`
	WriteTimeout          time.Duration `yaml:"write_timeout"`
	IdleTimeout           time.Duration `yaml:"idle_timeout"`
}

// TLSConfig configures TLS settings
// TLS is required by default unless developer_mode is enabled
type TLSConfig struct {
	CertFile       string `yaml:"cert_file"`
	KeyFile        string `yaml:"key_file"`
	ClientCAFile   string `yaml:"client_ca_file"`
	ClientAuthType string `yaml:"client_auth_type"` // none, request, require
}

// RateLimitConfig configures rate limiting per IP
type RateLimitConfig struct {
	Enabled           bool `yaml:"enabled"`             // Enable rate limiting
	RequestsPerSecond int  `yaml:"requests_per_second"` // Requests per second per IP (general endpoints)
	Burst             int  `yaml:"burst"`               // Maximum burst size (general endpoints)
	// TrustedProxyCIDRs defines which proxy IPs can be trusted for X-Forwarded-For
	TrustedProxyCIDRs []string `yaml:"trusted_proxy_cidrs"`
	// Authentication endpoint specific rate limits (stricter to prevent brute force)
	AuthRequestsPerSecond int `yaml:"auth_requests_per_second"` // Requests per second for auth endpoints (0 = use general limit)
	AuthBurst             int `yaml:"auth_burst"`               // Burst size for auth endpoints (0 = use general burst)
}

// BackendConfig configures the backend client (OpenBao or Vault)
type BackendConfig struct {
	Type                 string        `yaml:"type"`                   // "openbao" or "vault" (optional, auto-detected)
	Address              string        `yaml:"address"`                // Backend server address
	Token                string        `yaml:"token"`                  // Authentication token (for non-cert auth)
	TokenFile            string        `yaml:"token_file"`             // Alternative: read token from file
	TokenRenewalInterval time.Duration `yaml:"token_renewal_interval"` // Token renewal interval (default: 15m)
	Namespace            string        `yaml:"namespace"`              // Namespace (Enterprise feature)
	TLSSkipVerify        bool          `yaml:"tls_skip_verify"`        // Skip TLS verification (not recommended)
	CACert               string        `yaml:"ca_cert"`                // CA certificate for TLS verification
	ClientCert           string        `yaml:"client_cert"`            // Client certificate for mTLS to backend
	ClientKey            string        `yaml:"client_key"`             // Client key for mTLS to backend
	Timeout              time.Duration `yaml:"timeout"`                // Request timeout
}

// ESTConfig configures EST protocol behavior
type ESTConfig struct {
	Enabled        bool                   `yaml:"enabled"`
	DefaultMount   string                 `yaml:"default_mount"`
	Labels         map[string]LabelConfig `yaml:"labels"`
	DefaultPolicy  PolicyConfig           `yaml:"default_policy"`
	Authenticators AuthenticatorsConfig   `yaml:"authenticators"`
	CSRValidation  CSRValidationConfig    `yaml:"csr_validation"`
	CSRAttributes  CSRAttributesConfig    `yaml:"csr_attributes"` // RFC 7030 Section 4.5 - /csrattrs endpoint
}

// LabelConfig configures a specific EST label
type LabelConfig struct {
	Type  string `yaml:"type"`  // "role" or "sign-verbatim"
	Value string `yaml:"value"` // role name (if type=role)
	TTL   string `yaml:"ttl"`   // Certificate TTL (e.g., "24h", "30d")
}

// PolicyConfig configures policy behavior
type PolicyConfig struct {
	Type  string `yaml:"type"`
	Value string `yaml:"value"`
	TTL   string `yaml:"ttl"` // Certificate TTL (e.g., "24h", "30d")
}

// AuthenticatorsConfig configures authentication methods
type AuthenticatorsConfig struct {
	Userpass UserpassAuthConfig `yaml:"userpass"`
	LDAP     LDAPAuthConfig     `yaml:"ldap"`
	AppRole  AppRoleAuthConfig  `yaml:"approle"`
	Cert     CertAuthConfig     `yaml:"cert"`
	Token    TokenAuthConfig    `yaml:"token"`
}

// UserpassAuthConfig configures userpass authentication
type UserpassAuthConfig struct {
	Enabled   bool   `yaml:"enabled"`
	MountPath string `yaml:"mount_path"`
}

// LDAPAuthConfig configures LDAP authentication
type LDAPAuthConfig struct {
	Enabled   bool   `yaml:"enabled"`
	MountPath string `yaml:"mount_path"`
}

// AppRoleAuthConfig configures AppRole authentication
type AppRoleAuthConfig struct {
	Enabled   bool   `yaml:"enabled"`
	MountPath string `yaml:"mount_path"`
}

// CertAuthConfig configures certificate authentication
type CertAuthConfig struct {
	Enabled           bool   `yaml:"enabled"`
	MountPath         string `yaml:"mount_path"`
	CertRole          string `yaml:"cert_role"`
	TokenRole         string `yaml:"token_role"`          // Vault token role for creating entity-bound tokens
	EntityAliasPrefix string `yaml:"entity_alias_prefix"` // Prefix for entity alias (e.g., "est-cert-")
	TokenTTL          string `yaml:"token_ttl"`           // TTL for created tokens (default: "5m")
}

// TokenAuthConfig configures token authentication
type TokenAuthConfig struct {
	Enabled bool `yaml:"enabled"`
}

// CSRValidationConfig configures CSR validation
type CSRValidationConfig struct {
	MaxSizeBytes               int      `yaml:"max_size_bytes"`
	AllowedSignatureAlgorithms []string `yaml:"allowed_signature_algorithms"`
}

// CSRAttributesConfig configures the /csrattrs endpoint (RFC 7030 Section 4.5)
type CSRAttributesConfig struct {
	Enabled    bool     `yaml:"enabled"`    // Enable /csrattrs endpoint
	Attributes []string `yaml:"attributes"` // OIDs to return (e.g., "1.2.840.113549.1.9.14")
}

// ObservabilityConfig configures monitoring and logging
type ObservabilityConfig struct {
	Metrics MetricsConfig `yaml:"metrics"`
	Logging LoggingConfig `yaml:"logging"`
	Tracing TracingConfig `yaml:"tracing"`
	Audit   AuditConfig   `yaml:"audit"`
}

// MetricsConfig configures metrics collection via OpenTelemetry
type MetricsConfig struct {
	Enabled        bool   `yaml:"enabled"`
	PrometheusPort int    `yaml:"prometheus_port"` // Port for Prometheus scraping (0 to disable)
	OTLPEndpoint   string `yaml:"otlp_endpoint"`   // OTLP endpoint for metrics export (empty to disable)
	OTLPInsecure   bool   `yaml:"otlp_insecure"`   // Allow insecure OTLP (HTTP) - not recommended for production
}

// LoggingConfig configures logging
type LoggingConfig struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // json, text
	Stdout *bool  `yaml:"stdout"` // Enable stdout logging (default: true)
	File   string `yaml:"file"`   // Optional file path for logging
}

// TracingConfig configures distributed tracing
type TracingConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"`
}

// AuditConfig configures structured audit logging
type AuditConfig struct {
	Enabled bool   `yaml:"enabled"`
	Stdout  *bool  `yaml:"stdout"` // Enable stdout audit logging (default: true)
	File    string `yaml:"file"`   // Optional file path for audit logging
}
