package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/mabunixda/est-service/pkg/backend"
)

func TestManager(t *testing.T) {
	tests := []struct {
		name               string
		config             *Config
		expectUserpassPath string
		expectCertPath     string
		expectAppRolePath  string
	}{
		{
			name:               "default mount paths",
			config:             &Config{},
			expectUserpassPath: "userpass",
			expectCertPath:     "cert",
			expectAppRolePath:  "approle",
		},
		{
			name: "custom mount paths",
			config: &Config{
				UserpassMountPath: "custom-userpass",
				CertMountPath:     "custom-cert",
				AppRoleMountPath:  "custom-approle",
			},
			expectUserpassPath: "custom-userpass",
			expectCertPath:     "custom-cert",
			expectAppRolePath:  "custom-approle",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := NewManager(nil, tt.config, nil)

			if mgr.config.UserpassMountPath != tt.expectUserpassPath {
				t.Errorf("Expected UserpassMountPath '%s', got '%s'",
					tt.expectUserpassPath, mgr.config.UserpassMountPath)
			}

			if mgr.config.CertMountPath != tt.expectCertPath {
				t.Errorf("Expected CertMountPath '%s', got '%s'",
					tt.expectCertPath, mgr.config.CertMountPath)
			}

			if mgr.config.AppRoleMountPath != tt.expectAppRolePath {
				t.Errorf("Expected AppRoleMountPath '%s', got '%s'",
					tt.expectAppRolePath, mgr.config.AppRoleMountPath)
			}

			if mgr.logger == nil {
				t.Error("Expected logger to be initialized")
			}
		})
	}
}

func TestManager_NilLogger(t *testing.T) {
	mgr := NewManager(nil, &Config{}, nil)

	if mgr.logger == nil {
		t.Error("Expected default logger to be set when nil is provided")
	}
}

func TestGetWWWAuthenticateHeaders(t *testing.T) {
	tests := []struct {
		name           string
		config         *Config
		expectedCount  int
		expectedBasic  bool
		expectedBearer bool
	}{
		{
			name: "all auth methods enabled",
			config: &Config{
				UserpassEnabled: true,
				TokenEnabled:    true,
			},
			expectedCount:  2,
			expectedBasic:  true,
			expectedBearer: true,
		},
		{
			name: "only basic auth",
			config: &Config{
				UserpassEnabled: true,
				TokenEnabled:    false,
			},
			expectedCount:  1,
			expectedBasic:  true,
			expectedBearer: false,
		},
		{
			name: "only AppRole basic auth",
			config: &Config{
				AppRoleEnabled: true,
				TokenEnabled:   false,
			},
			expectedCount:  1,
			expectedBasic:  true,
			expectedBearer: false,
		},
		{
			name: "only bearer auth",
			config: &Config{
				UserpassEnabled: false,
				TokenEnabled:    true,
			},
			expectedCount:  1,
			expectedBasic:  false,
			expectedBearer: true,
		},
		{
			name: "no auth methods",
			config: &Config{
				UserpassEnabled: false,
				TokenEnabled:    false,
			},
			expectedCount:  0,
			expectedBasic:  false,
			expectedBearer: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := NewManager(nil, tt.config, slog.Default())
			headers := mgr.GetWWWAuthenticateHeaders()

			if len(headers) != tt.expectedCount {
				t.Errorf("Expected %d headers, got %d", tt.expectedCount, len(headers))
			}

			hasBasic := false
			hasBearer := false
			for _, h := range headers {
				if h == `Basic realm="EST Service"` {
					hasBasic = true
				}
				if h == `Bearer realm="EST Service"` {
					hasBearer = true
				}
			}

			if hasBasic != tt.expectedBasic {
				t.Errorf("Expected Basic header presence: %v, got %v", tt.expectedBasic, hasBasic)
			}
			if hasBearer != tt.expectedBearer {
				t.Errorf("Expected Bearer header presence: %v, got %v", tt.expectedBearer, hasBearer)
			}
		})
	}
}

func TestAuthenticateBasic_MissingHeader(t *testing.T) {
	mgr := NewManager(nil, &Config{UserpassEnabled: true}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)

	result := mgr.authenticateBasic(context.Background(), req)

	if result.Authenticated {
		t.Error("Expected authentication to fail without Authorization header")
	}
}

func TestAuthenticateBasic_WrongAuthType(t *testing.T) {
	mgr := NewManager(nil, &Config{UserpassEnabled: true}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer some-token")

	result := mgr.authenticateBasic(context.Background(), req)

	if result.Authenticated {
		t.Error("Expected authentication to fail with Bearer token in Basic auth")
	}
}

func TestAuthenticateBasic_InvalidBase64(t *testing.T) {
	mgr := NewManager(nil, &Config{UserpassEnabled: true}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Basic not-valid-base64!!!")

	result := mgr.authenticateBasic(context.Background(), req)

	if result.Authenticated {
		t.Error("Expected authentication to fail with invalid base64")
	}
	if result.Error == nil {
		t.Error("Expected error for invalid base64")
	}
}

func TestAuthenticateBasic_InvalidFormat(t *testing.T) {
	mgr := NewManager(nil, &Config{UserpassEnabled: true}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	invalid := base64.StdEncoding.EncodeToString([]byte("username-no-password"))
	req.Header.Set("Authorization", "Basic "+invalid)

	result := mgr.authenticateBasic(context.Background(), req)

	if result.Authenticated {
		t.Error("Expected authentication to fail with invalid format")
	}
	if result.Error == nil {
		t.Error("Expected error for invalid format")
	}
}

func TestAuthenticateBasic_AppRoleSuccess(t *testing.T) {
	mock := &backend.MockBackend{
		AuthenticateAppRoleFunc: func(ctx context.Context, mount, roleID, secretID string) (string, error) {
			if mount != "approle" {
				return "", errors.New("unexpected mount")
			}
			if roleID == "role-id" && secretID == "secret-id" {
				return "approle-token", nil
			}
			return "", errors.New("invalid credentials")
		},
	}

	mgr := NewManager(mock, &Config{AppRoleEnabled: true, AppRoleMountPath: "approle"}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	creds := base64.StdEncoding.EncodeToString([]byte("role-id:secret-id"))
	req.Header.Set("Authorization", "Basic "+creds)

	result := mgr.authenticateBasic(context.Background(), req)

	if !result.Authenticated {
		t.Error("Expected authentication to succeed with AppRole")
	}
	if result.Method != "approle" {
		t.Errorf("Expected method 'approle', got '%s'", result.Method)
	}
}

func TestAuthenticateBasic_UserpassFails_AppRoleSucceeds(t *testing.T) {
	mock := &backend.MockBackend{
		AuthenticateUserpassFunc: func(ctx context.Context, mount, username, password string) (string, error) {
			return "", errors.New("userpass failed")
		},
		AuthenticateAppRoleFunc: func(ctx context.Context, mount, roleID, secretID string) (string, error) {
			return "approle-token", nil
		},
	}

	mgr := NewManager(mock, &Config{
		UserpassEnabled: true,
		AppRoleEnabled:  true,
	}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	creds := base64.StdEncoding.EncodeToString([]byte("role-id:secret-id"))
	req.Header.Set("Authorization", "Basic "+creds)

	result := mgr.authenticateBasic(context.Background(), req)

	if !result.Authenticated {
		t.Error("Expected authentication to succeed via AppRole fallback")
	}
	if result.Method != "approle" {
		t.Errorf("Expected method 'approle', got '%s'", result.Method)
	}
}

func TestAuthenticateToken_MissingHeader(t *testing.T) {
	mgr := NewManager(nil, &Config{TokenEnabled: true}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)

	result := mgr.authenticateToken(context.Background(), req)

	if result.Authenticated {
		t.Error("Expected authentication to fail without Authorization header")
	}
}

func TestAuthenticateToken_WrongAuthType(t *testing.T) {
	mgr := NewManager(nil, &Config{TokenEnabled: true}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	result := mgr.authenticateToken(context.Background(), req)

	if result.Authenticated {
		t.Error("Expected authentication to fail with Basic auth in token authentication")
	}
}

func TestAuthenticateToken_EmptyToken(t *testing.T) {
	mgr := NewManager(nil, &Config{TokenEnabled: true}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer ")

	result := mgr.authenticateToken(context.Background(), req)

	if result.Authenticated {
		t.Error("Expected authentication to fail with empty token")
	}
}

func TestAuthenticateCert_NoTLS(t *testing.T) {
	mgr := NewManager(nil, &Config{CertEnabled: true}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)

	result := mgr.authenticateCert(context.Background(), req)

	if result.Authenticated {
		t.Error("Expected authentication to fail without TLS")
	}
}

func TestAuthenticate_NoAuthMethodsEnabled(t *testing.T) {
	mgr := NewManager(nil, &Config{
		UserpassEnabled: false,
		TokenEnabled:    false,
		CertEnabled:     false,
	}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer some-token")

	result := mgr.Authenticate(context.Background(), req)

	if result.Authenticated {
		t.Error("Expected authentication to fail when no methods are enabled")
	}
	if result.Error == nil {
		t.Error("Expected error message")
	}
	if result.Error.Error() != "no valid authentication method found" {
		t.Errorf("Expected specific error message, got: %v", result.Error)
	}
}

func TestAuthenticate_NoCredentialsProvided(t *testing.T) {
	mgr := NewManager(nil, &Config{
		UserpassEnabled: true,
		TokenEnabled:    true,
	}, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)

	result := mgr.Authenticate(context.Background(), req)

	if result.Authenticated {
		t.Error("Expected authentication to fail without credentials")
	}
}

func TestConfig_Defaults(t *testing.T) {
	config := &Config{}
	mgr := NewManager(nil, config, nil)

	if mgr.config.UserpassMountPath != "userpass" {
		t.Errorf("Expected default userpass mount path 'userpass', got '%s'", mgr.config.UserpassMountPath)
	}

	if mgr.config.CertMountPath != "cert" {
		t.Errorf("Expected default cert mount path 'cert', got '%s'", mgr.config.CertMountPath)
	}
}

func TestResult_Structure(t *testing.T) {
	result := &Result{
		Authenticated: true,
		Token:         "test-token",
		Method:        "bearer",
		Identity:      "test-user",
		Error:         nil,
	}

	if !result.Authenticated {
		t.Error("Expected Authenticated to be true")
	}
	if result.Token != "test-token" {
		t.Errorf("Expected token 'test-token', got '%s'", result.Token)
	}
	if result.Method != "bearer" {
		t.Errorf("Expected method 'bearer', got '%s'", result.Method)
	}
	if result.Identity != "test-user" {
		t.Errorf("Expected identity 'test-user', got '%s'", result.Identity)
	}
	if result.Error != nil {
		t.Errorf("Expected no error, got %v", result.Error)
	}
}
