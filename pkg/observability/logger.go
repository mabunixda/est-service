package observability

import (
	"fmt"
	"io"
	"log/slog"
	"os"
)

// Config holds observability configuration
type Config struct {
	LogLevel  string
	LogFormat string
	Stdout    bool
	File      string
}

// AuditConfig holds audit logger configuration
type AuditConfig struct {
	Enabled bool
	Stdout  bool
	File    string
}

// SetupLogger configures the global logger
func SetupLogger(cfg *Config) (*slog.Logger, error) {
	var level slog.Level

	if cfg == nil {
		return nil, fmt.Errorf("logger config is nil")
	}
	if cfg.LogFormat == "" {
		cfg.LogFormat = "text"
	}

	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	writer, err := buildLogWriter(cfg.Stdout, cfg.File, 0o640)
	if err != nil {
		return nil, err
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	if cfg.LogFormat == "json" {
		handler = slog.NewJSONHandler(writer, opts)
	} else {
		handler = slog.NewTextHandler(writer, opts)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)

	return logger, nil
}

// SetupAuditLogger creates a structured audit logger (JSON) if enabled
func SetupAuditLogger(cfg *AuditConfig) (*slog.Logger, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}

	writer, err := buildLogWriter(cfg.Stdout, cfg.File, 0o600)
	if err != nil {
		return nil, err
	}

	// Always use JSON for audit events
	handler := slog.NewJSONHandler(writer, opts)

	return slog.New(handler), nil
}

func buildLogWriter(stdout bool, filePath string, perm os.FileMode) (io.Writer, error) {
	if !stdout && filePath == "" {
		return nil, fmt.Errorf("no log outputs configured")
	}

	writers := make([]io.Writer, 0, 2)
	if stdout {
		writers = append(writers, os.Stdout)
	}
	if filePath != "" {
		file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, perm)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file %q: %w", filePath, err)
		}
		writers = append(writers, file)
	}

	if len(writers) == 1 {
		return writers[0], nil
	}

	return io.MultiWriter(writers...), nil
}
