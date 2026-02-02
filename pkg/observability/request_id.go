package observability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

// RequestIDHeader is the canonical header used for request correlation.
const RequestIDHeader = "X-Request-ID"

type requestIDKey struct{}

// WithRequestID attaches a request ID to the context.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, requestID)
}

// RequestIDFromContext retrieves a request ID from context, if present.
func RequestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if val, ok := ctx.Value(requestIDKey{}).(string); ok {
		return val
	}
	return ""
}

// NewRequestID generates a random, URL-safe request ID.
func NewRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}
