package backend

import (
	"context"
	"log/slog"
)

// openBaoBackend implements the Backend interface for OpenBao
// It embeds commonBackend which contains all the shared implementation logic
type openBaoBackend struct {
	*commonBackend
}

// newOpenBaoBackend creates a new OpenBao backend implementation
func newOpenBaoBackend(ctx context.Context, cfg *Config, logger *slog.Logger) (Backend, error) {
	common, err := newCommonBackend(ctx, cfg, logger)
	if err != nil {
		return nil, err
	}

	return &openBaoBackend{
		commonBackend: common,
	}, nil
}

// Type returns the backend type
func (b *openBaoBackend) Type() BackendType {
	return BackendTypeOpenBao
}

// CloneWithToken creates a new backend instance with a different token
// This enables per-request token usage for proper audit trails and policy enforcement
func (b *openBaoBackend) CloneWithToken(ctx context.Context, token string) (Backend, error) {
	clonedCommon, err := b.cloneWithToken(ctx, token)
	if err != nil {
		return nil, err
	}

	return &openBaoBackend{
		commonBackend: clonedCommon,
	}, nil
}
