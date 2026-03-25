package server

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mabunixda/est-service/pkg/auth"
	"github.com/openbao/openbao/api/v2"
)

func TestAuthMiddleware(t *testing.T) {
	mockBE := &mockBackend{}
	backendClient := newMockBackendClient(mockBE)
	logger := slog.Default()

	authCfg := &auth.Config{
		TokenEnabled: true,
	}
	authMgr := auth.NewManager(backendClient, authCfg, logger)

	cfg := &Config{
		AuthConfig: authCfg,
	}

	s := &Server{
		config:  cfg,
		logger:  logger,
		authMgr: authMgr,
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	t.Run("unauthenticated", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		s.authMiddleware(nextHandler).ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized, got %d", rec.Code)
		}
		if rec.Header().Get("WWW-Authenticate") != "Bearer realm=\"EST Service\"" {
			t.Errorf("expected Bearer realm, got %s", rec.Header().Get("WWW-Authenticate"))
		}
	})

	t.Run("authenticated", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		rec := httptest.NewRecorder()

		// the mock backend needs to be configured to return valid token
		// However, auth.Manager token auth uses ValidateToken on the backend
		mockBE.healthFunc = nil // just reset

		s.authMiddleware(nextHandler).ServeHTTP(rec, req)

		// With our mockBackend returning true for ValidateToken, this should succeed.
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rec.Code)
		}
	})
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	s := &Server{}
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	t.Run("http standard path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		s.securityHeadersMiddleware(nextHandler).ServeHTTP(rec, req)

		headers := map[string]string{
			"X-Content-Type-Options":  "nosniff",
			"X-Frame-Options":         "DENY",
			"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
			"Server":                  "EST-Service",
		}

		for k, expected := range headers {
			if got := rec.Header().Get(k); got != expected {
				t.Errorf("Header %s: expected %q, got %q", k, expected, got)
			}
		}

		if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
			t.Errorf("expected no HSTS on HTTP, got %q", got)
		}
	})

	t.Run("https est path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/est/cacerts", nil)
		req.TLS = &tls.ConnectionState{} // mock HTTPS
		rec := httptest.NewRecorder()

		s.securityHeadersMiddleware(nextHandler).ServeHTTP(rec, req)

		headers := map[string]string{
			"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
			"Cache-Control":             "no-store, no-cache, must-revalidate, private",
			"Pragma":                    "no-cache",
			"Expires":                   "0",
		}

		for k, expected := range headers {
			if got := rec.Header().Get(k); got != expected {
				t.Errorf("Header %s: expected %q, got %q", k, expected, got)
			}
		}
	})
}

func TestDeepHealthHandler(t *testing.T) {
	mockBE := &mockBackend{}
	backendClient := newMockBackendClient(mockBE)
	logger := slog.Default()

	s := &Server{
		backend:    backendClient,
		logger:     logger,
		httpServer: &http.Server{},
	}

	t.Run("healthy", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health/deep", nil)
		rec := httptest.NewRecorder()

		s.deepHealthHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rec.Code)
		}
	})

	t.Run("sealed backend", func(t *testing.T) {
		mockBE.healthFunc = func(ctx context.Context) (*api.HealthResponse, error) {
			return &api.HealthResponse{Initialized: true, Sealed: true, Version: "test"}, nil
		}

		req := httptest.NewRequest(http.MethodGet, "/health/deep", nil)
		rec := httptest.NewRecorder()

		s.deepHealthHandler(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("expected 503 Service Unavailable, got %d", rec.Code)
		}
	})

	t.Run("uninitialized backend", func(t *testing.T) {
		mockBE.healthFunc = func(ctx context.Context) (*api.HealthResponse, error) {
			return &api.HealthResponse{Initialized: false, Sealed: false, Version: "test"}, nil
		}

		req := httptest.NewRequest(http.MethodGet, "/health/deep", nil)
		rec := httptest.NewRecorder()

		s.deepHealthHandler(rec, req)

		// Still 200 OK for uninitialized, but degraded in body
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rec.Code)
		}
	})

	t.Run("backend error", func(t *testing.T) {
		mockBE.healthFunc = func(ctx context.Context) (*api.HealthResponse, error) {
			return nil, errors.New("backend connection error")
		}

		req := httptest.NewRequest(http.MethodGet, "/health/deep", nil)
		rec := httptest.NewRecorder()

		s.deepHealthHandler(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("expected 503 Service Unavailable, got %d", rec.Code)
		}
	})
}

func TestHealthHandler(t *testing.T) {
	mockBE := &mockBackend{}
	backendClient := newMockBackendClient(mockBE)
	logger := slog.Default()

	s := &Server{
		backend:    backendClient,
		logger:     logger,
		httpServer: &http.Server{},
	}

	t.Run("healthy", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()

		s.healthHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rec.Code)
		}
	})

	t.Run("sealed backend", func(t *testing.T) {
		mockBE.healthFunc = func(ctx context.Context) (*api.HealthResponse, error) {
			return &api.HealthResponse{Initialized: true, Sealed: true, Version: "test"}, nil
		}

		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()

		s.healthHandler(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("expected 503 Service Unavailable, got %d", rec.Code)
		}
	})

	t.Run("uninitialized backend", func(t *testing.T) {
		mockBE.healthFunc = func(ctx context.Context) (*api.HealthResponse, error) {
			return &api.HealthResponse{Initialized: false, Sealed: false, Version: "test"}, nil
		}

		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()

		s.healthHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rec.Code)
		}
	})

	t.Run("backend error", func(t *testing.T) {
		mockBE.healthFunc = func(ctx context.Context) (*api.HealthResponse, error) {
			return nil, errors.New("backend connection error")
		}

		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()

		s.healthHandler(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("expected 503 Service Unavailable, got %d", rec.Code)
		}
	})
}
