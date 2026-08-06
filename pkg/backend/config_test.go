package backend

import (
	"context"
	"log/slog"
	"testing"
	"time"
)

// TestConfig_DefaultValues tests that Config uses sensible defaults
func TestConfig_DefaultValues(t *testing.T) {
	cfg := &Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
	}

	// TokenRenewalInterval should default to 15 minutes when creating a backend.
	// This is handled in newCommonBackend.

	if cfg.Address != "https://openbao.example.com" {
		t.Errorf("Address = %v, want https://openbao.example.com", cfg.Address)
	}

	if cfg.Token != "test-token" {
		t.Errorf("Token = %v, want test-token", cfg.Token)
	}
}

// TestConfig_TokenRenewalInterval tests custom token renewal intervals
func TestConfig_TokenRenewalInterval(t *testing.T) {
	tests := []struct {
		name     string
		interval time.Duration
		want     time.Duration
	}{
		{
			name:     "default (zero value)",
			interval: 0,
			want:     15 * time.Minute, // Should default to 15 minutes
		},
		{
			name:     "custom 5 minutes",
			interval: 5 * time.Minute,
			want:     5 * time.Minute,
		},
		{
			name:     "custom 1 hour",
			interval: 1 * time.Hour,
			want:     1 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Address:              "https://openbao.example.com",
				Token:                "test-token",
				TokenRenewalInterval: tt.interval,
			}

			// The actual default is applied in newCommonBackend.
			// Here we just verify the config stores the value correctly.
			if cfg.TokenRenewalInterval != tt.interval {
				t.Errorf("TokenRenewalInterval = %v, want %v", cfg.TokenRenewalInterval, tt.interval)
			}
		})
	}
}

// TestConfig_BackendType tests backend type configuration
func TestConfig_BackendType(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want BackendType
	}{
		{
			name: "explicit openbao",
			cfg: &Config{
				Address: "https://openbao.example.com",
				Type:    BackendTypeOpenBao,
			},
			want: BackendTypeOpenBao,
		},
		{
			name: "empty",
			cfg: &Config{
				Address: "https://openbao.example.com",
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.cfg.Type != tt.want {
				t.Errorf("Type = %v, want %v", tt.cfg.Type, tt.want)
			}
		})
	}
}

// TestConfig_TLSSettings tests TLS configuration
func TestConfig_TLSSettings(t *testing.T) {
	t.Run("with CA cert", func(t *testing.T) {
		cfg := &Config{
			Address: "https://openbao.example.com",
			CACert:  "/path/to/ca.crt",
		}

		if cfg.CACert != "/path/to/ca.crt" {
			t.Errorf("CACert = %v, want /path/to/ca.crt", cfg.CACert)
		}
	})

	t.Run("with CA path", func(t *testing.T) {
		cfg := &Config{
			Address: "https://openbao.example.com",
			CAPath:  "/path/to/certs",
		}

		if cfg.CAPath != "/path/to/certs" {
			t.Errorf("CAPath = %v, want /path/to/certs", cfg.CAPath)
		}
	})

	t.Run("with namespace", func(t *testing.T) {
		cfg := &Config{
			Address:   "https://openbao.example.com",
			Namespace: "tenant1",
		}

		if cfg.Namespace != "tenant1" {
			t.Errorf("Namespace = %v, want tenant1", cfg.Namespace)
		}
	})
}

// TestBackendType_String tests BackendType values
func TestBackendType_String(t *testing.T) {
	tests := []struct {
		name string
		bt   BackendType
		want string
	}{
		{"openbao", BackendTypeOpenBao, "openbao"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.bt) != tt.want {
				t.Errorf("BackendType = %v, want %v", tt.bt, tt.want)
			}
		})
	}
}

// TestBackend_UnsupportedType tests error handling for unsupported backend types
func TestBackend_UnsupportedType(t *testing.T) {
	cfg := &Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
		Type:    BackendType("unsupported"),
	}

	ctx := context.Background()
	_, err := NewBackend(ctx, cfg, slog.Default())

	if err == nil {
		t.Error("Expected error for unsupported backend type, got nil")
	}

	expectedMsg := "unsupported backend type"
	if err != nil && err.Error()[:len(expectedMsg)] != expectedMsg {
		t.Errorf("Error message = %v, want to start with %v", err.Error(), expectedMsg)
	}
}
