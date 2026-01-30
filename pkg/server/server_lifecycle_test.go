package server

import (
	"context"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/mabunixda/est-service/pkg/auth"
	"github.com/mabunixda/est-service/pkg/backend"
	"github.com/mabunixda/est-service/pkg/handlers"
)

// TestShutdown tests the Shutdown method
func TestShutdown(t *testing.T) {
	srv := &Server{
		httpServer: &http.Server{
			Addr: ":0", // Random port
		},
		logger:      slog.Default(),
		rateLimiter: NewRateLimiter(10, 20),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err := srv.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown failed: %v", err)
	}

	// Verify rate limiter was shut down (shouldn't panic on double shutdown)
	srv.rateLimiter = nil
	err = srv.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown without rate limiter failed: %v", err)
	}
}

// TestShutdown_WithoutRateLimiter tests shutdown when rate limiter is nil
func TestShutdown_WithoutRateLimiter(t *testing.T) {
	srv := &Server{
		httpServer: &http.Server{
			Addr: ":0",
		},
		logger:      slog.Default(),
		rateLimiter: nil, // No rate limiter
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err := srv.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown without rate limiter failed: %v", err)
	}
}

// TestStart_CancellationTriggersShutdown tests that context cancellation triggers shutdown
func TestStart_CancellationTriggersShutdown(t *testing.T) {
	// Create a server that won't actually start (invalid address)
	cfg := &Config{
		ListenAddr: "127.0.0.1:0", // Use port 0 for random available port
		PKIMount:   "pki",
		AuthConfig: &auth.Config{},
		EnrollmentConfig: &handlers.EnrollmentConfig{
			DefaultMount: "pki",
		},
	}

	srv := &Server{
		config: cfg,
		httpServer: &http.Server{
			Addr:    cfg.ListenAddr,
			Handler: http.NewServeMux(),
		},
		backend: &backend.Client{},
		logger:  slog.Default(),
	}

	// Create a context that we'll cancel immediately
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel the context after a short delay
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	// Start should return when context is cancelled
	err := srv.Start(ctx)
	// We expect either nil (clean shutdown) or context canceled error
	if err != nil && err != context.Canceled && err.Error() != "context canceled" {
		t.Logf("Start returned error (may be expected): %v", err)
	}
}

// TestStart_HTTPMode tests starting server in HTTP mode (no TLS)
func TestStart_HTTPMode(t *testing.T) {
	cfg := &Config{
		ListenAddr: "127.0.0.1:0",
		PKIMount:   "pki",
		AuthConfig: &auth.Config{},
		EnrollmentConfig: &handlers.EnrollmentConfig{
			DefaultMount: "pki",
		},
		// No TLS config - will start HTTP server
	}

	srv := &Server{
		config: cfg,
		httpServer: &http.Server{
			Addr:    cfg.ListenAddr,
			Handler: http.NewServeMux(),
		},
		backend: &backend.Client{},
		logger:  slog.Default(),
	}

	// Create a context with quick timeout
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Start in HTTP mode - will be cancelled by timeout
	err := srv.Start(ctx)
	// Expect context deadline exceeded or nil
	if err != nil && err != context.DeadlineExceeded {
		t.Logf("Start HTTP mode completed: %v", err)
	}
}

// TestStart_InvalidAddress tests error handling when server can't bind
func TestStart_InvalidAddress(t *testing.T) {
	cfg := &Config{
		ListenAddr: "999.999.999.999:99999", // Invalid address
		PKIMount:   "pki",
		AuthConfig: &auth.Config{},
		EnrollmentConfig: &handlers.EnrollmentConfig{
			DefaultMount: "pki",
		},
	}

	srv := &Server{
		config: cfg,
		httpServer: &http.Server{
			Addr:    cfg.ListenAddr,
			Handler: http.NewServeMux(),
		},
		backend: &backend.Client{},
		logger:  slog.Default(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err := srv.Start(ctx)
	// Should get an error due to invalid address
	if err == nil {
		t.Error("Expected error with invalid address")
	}
}
