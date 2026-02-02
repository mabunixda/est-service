package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter implements per-IP rate limiting using token bucket algorithm
type RateLimiter struct {
	visitors         map[string]*rate.Limiter
	mu               sync.RWMutex
	r                rate.Limit
	b                int
	cleanup          time.Duration
	telemetry        *Telemetry
	ctx              context.Context
	cancel           context.CancelFunc
	trustedProxyNets []*net.IPNet
}

// NewRateLimiter creates a new rate limiter
// requestsPerSecond: allowed requests per second per IP
// burst: maximum burst size
func NewRateLimiter(requestsPerSecond int, burst int) *RateLimiter {
	return NewRateLimiterWithTelemetry(requestsPerSecond, burst, nil)
}

// NewRateLimiterWithTelemetry creates a new rate limiter with telemetry
func NewRateLimiterWithTelemetry(requestsPerSecond int, burst int, telemetry *Telemetry) *RateLimiter {
	ctx, cancel := context.WithCancel(context.Background())

	rl := &RateLimiter{
		visitors:         make(map[string]*rate.Limiter),
		r:                rate.Limit(requestsPerSecond),
		b:                burst,
		cleanup:          5 * time.Minute,
		telemetry:        telemetry,
		ctx:              ctx,
		cancel:           cancel,
		trustedProxyNets: nil,
	}

	// Cleanup old visitors periodically
	go rl.cleanupVisitors()

	return rl
}

// SetTrustedProxyCIDRs configures which proxy IPs are allowed to supply X-Forwarded-For
func (rl *RateLimiter) SetTrustedProxyCIDRs(cidrs []string) error {
	if len(cidrs) == 0 {
		rl.trustedProxyNets = nil
		return nil
	}

	trusted := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			return fmt.Errorf("invalid trusted proxy CIDR %q: %w", cidr, err)
		}
		trusted = append(trusted, network)
	}

	rl.trustedProxyNets = trusted
	return nil
}

// getVisitor returns rate limiter for a specific IP
func (rl *RateLimiter) getVisitor(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.visitors[ip]
	if !exists {
		limiter = rate.NewLimiter(rl.r, rl.b)
		rl.visitors[ip] = limiter
	}

	return limiter
}

// cleanupVisitors removes stale visitor entries
// It runs until the context is cancelled (on shutdown)
func (rl *RateLimiter) cleanupVisitors() {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()

	for {
		select {
		case <-rl.ctx.Done():
			// Context cancelled, stop cleanup goroutine
			return
		case <-ticker.C:
			rl.mu.Lock()
			for ip, limiter := range rl.visitors {
				// Remove if no tokens have been consumed recently
				if limiter.Tokens() >= float64(rl.b) {
					delete(rl.visitors, ip)
				}
			}
			rl.mu.Unlock()
		}
	}
}

// Shutdown stops the cleanup goroutine gracefully
func (rl *RateLimiter) Shutdown() {
	if rl.cancel != nil {
		rl.cancel()
	}
}

// getClientIP extracts the client IP address from the request
// It handles X-Forwarded-For header properly to prevent spoofing
func (rl *RateLimiter) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (from proxies)
	// Only use the first IP in the chain (closest to client)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" && rl.isTrustedProxy(r.RemoteAddr) {
		// Take first IP from comma-separated list
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Fallback to RemoteAddr (strip port)
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If SplitHostPort fails, return as-is (might be just IP without port)
		return r.RemoteAddr
	}
	return ip
}

func (rl *RateLimiter) isTrustedProxy(remoteAddr string) bool {
	if len(rl.trustedProxyNets) == 0 {
		return false
	}

	ipStr, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ipStr = remoteAddr
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, network := range rl.trustedProxyNets {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// Middleware returns an HTTP middleware for rate limiting
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get client IP with proper handling
		ip := rl.getClientIP(r)

		limiter := rl.getVisitor(ip)
		if !limiter.Allow() {
			if rl.telemetry != nil {
				rl.telemetry.RecordRateLimitReject(r.Context(), ip)
			}
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}
