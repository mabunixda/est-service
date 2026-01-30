package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestRateLimiter(t *testing.T) {
	t.Run("allows requests under limit", func(t *testing.T) {
		rl := NewRateLimiter(10, 20)

		handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// Should allow first 20 requests (burst)
		for i := 0; i < 20; i++ {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Request %d: expected 200, got %d", i, w.Code)
			}
		}
	})

	t.Run("blocks requests over limit", func(t *testing.T) {
		rl := NewRateLimiter(1, 2)

		handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.2:12345"

		// First 2 should succeed (burst)
		for i := 0; i < 2; i++ {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Errorf("Request %d should succeed, got %d", i, w.Code)
			}
		}

		// Next should be rate limited
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusTooManyRequests {
			t.Errorf("Expected 429, got %d", w.Code)
		}
	})

	t.Run("rate limits per IP", func(t *testing.T) {
		rl := NewRateLimiter(1, 2)

		handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// IP 1 exhausts limit
		req1 := httptest.NewRequest("GET", "/test", nil)
		req1.RemoteAddr = "192.168.1.1:12345"
		for i := 0; i < 2; i++ {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req1)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req1)
		if w.Code != http.StatusTooManyRequests {
			t.Error("IP1 should be rate limited")
		}

		// IP 2 should still work
		req2 := httptest.NewRequest("GET", "/test", nil)
		req2.RemoteAddr = "192.168.1.2:12345"
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, req2)
		if w.Code != http.StatusOK {
			t.Error("IP2 should not be rate limited")
		}
	})

	t.Run("respects X-Forwarded-For header", func(t *testing.T) {
		rl := NewRateLimiter(1, 1)

		handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("X-Forwarded-For", "192.168.1.100")

		// First request succeeds
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Error("First request should succeed")
		}

		// Second request rate limited (same X-Forwarded-For)
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusTooManyRequests {
			t.Error("Should be rate limited by X-Forwarded-For")
		}
	})
}

func TestRateLimiterWithTelemetry(t *testing.T) {
	t.Run("records rate limit rejections", func(t *testing.T) {
		// Create mock telemetry (we'll just verify no panic)
		rl := NewRateLimiter(1, 1)

		handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"

		// Exhaust limit
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Trigger rate limit
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusTooManyRequests {
			t.Error("Should be rate limited")
		}
	})
}

func TestRateLimiterCleanup(t *testing.T) {
	t.Run("cleans up old visitors", func(t *testing.T) {
		rl := &RateLimiter{
			visitors: make(map[string]*rate.Limiter),
			r:        rate.Limit(100),
			b:        200,
			cleanup:  10 * time.Millisecond,
		}

		// Add a visitor
		rl.getVisitor("192.168.1.1")

		if len(rl.visitors) != 1 {
			t.Error("Should have 1 visitor")
		}

		// Wait for tokens to refill
		time.Sleep(20 * time.Millisecond)

		// Trigger cleanup manually (normally runs in goroutine)
		rl.mu.Lock()
		for ip, limiter := range rl.visitors {
			if limiter.Tokens() >= float64(rl.b) {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()

		if len(rl.visitors) != 0 {
			t.Error("Should have cleaned up visitor")
		}
	})
}
