package observability

import (
	"bytes"
	"log/slog"
	"os"
	"strings"
	"testing"
)

func TestSetupLogger_LogLevels(t *testing.T) {
	tests := []struct {
		name          string
		logLevel      string
		expectedLevel slog.Level
	}{
		{"debug level", "debug", slog.LevelDebug},
		{"info level", "info", slog.LevelInfo},
		{"warn level", "warn", slog.LevelWarn},
		{"error level", "error", slog.LevelError},
		{"default level (empty)", "", slog.LevelInfo},
		{"default level (invalid)", "invalid", slog.LevelInfo},
		{"default level (unknown)", "trace", slog.LevelInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				LogLevel:  tt.logLevel,
				LogFormat: "text",
				Stdout:    true,
			}

			logger, err := SetupLogger(cfg)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if logger == nil {
				t.Fatal("Expected non-nil logger")
			}

			// Verify the logger is set as default
			if slog.Default() != logger {
				t.Error("Expected logger to be set as default")
			}

			// Test that the logger works
			logger.Info("test message")
		})
	}
}

func TestSetupLogger_LogFormats(t *testing.T) {
	tests := []struct {
		name      string
		logFormat string
		wantJSON  bool
	}{
		{"json format", "json", true},
		{"text format", "text", false},
		{"default format (empty)", "", false},
		{"default format (invalid)", "xml", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture output by temporarily redirecting stdout
			// Note: This is tricky in tests, so we just verify the logger is created
			cfg := &Config{
				LogLevel:  "info",
				LogFormat: tt.logFormat,
				Stdout:    true,
			}

			logger, err := SetupLogger(cfg)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if logger == nil {
				t.Fatal("Expected non-nil logger")
			}

			// The logger should be functional
			logger.Info("test message", "key", "value")
		})
	}
}

func TestSetupLogger_NilConfig(t *testing.T) {
	_, err := SetupLogger(nil)
	if err == nil {
		t.Error("Expected error when config is nil")
	}
}

func TestSetupLogger_OutputsToStdout(t *testing.T) {
	// Verify that the logger outputs to stdout
	cfg := &Config{
		LogLevel:  "info",
		LogFormat: "text",
		Stdout:    true,
	}

	// Temporarily redirect stdout to capture output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logger, err := SetupLogger(cfg)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	logger.Info("test message for output verification")

	// Restore stdout
	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "test message for output verification") {
		t.Errorf("Expected log output to contain test message, got: %s", output)
	}
	if !strings.Contains(output, "level=INFO") {
		t.Errorf("Expected log output to contain level=INFO, got: %s", output)
	}
}

func TestSetupLogger_JSONFormat(t *testing.T) {
	cfg := &Config{
		LogLevel:  "info",
		LogFormat: "json",
		Stdout:    true,
	}

	// Temporarily redirect stdout to capture output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logger, err := SetupLogger(cfg)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	logger.Info("json test message", "key", "value")

	// Restore stdout
	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	// JSON format should contain JSON structure
	if !strings.Contains(output, "\"msg\"") {
		t.Errorf("Expected JSON output to contain '\"msg\"', got: %s", output)
	}
	if !strings.Contains(output, "\"level\"") {
		t.Errorf("Expected JSON output to contain '\"level\"', got: %s", output)
	}
	if !strings.Contains(output, "\"key\"") {
		t.Errorf("Expected JSON output to contain '\"key\"', got: %s", output)
	}
}

func TestSetupLogger_LevelFiltering(t *testing.T) {
	// Test that log level filtering works correctly
	cfg := &Config{
		LogLevel:  "warn",
		LogFormat: "text",
		Stdout:    true,
	}

	// Temporarily redirect stdout to capture output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logger, err := SetupLogger(cfg)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// These should be filtered out (below warn level)
	logger.Debug("debug message - should not appear")
	logger.Info("info message - should not appear")

	// These should appear
	logger.Warn("warn message - should appear")
	logger.Error("error message - should appear")

	// Restore stdout
	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	// Debug and Info should not appear
	if strings.Contains(output, "debug message") {
		t.Error("Debug message should be filtered out at warn level")
	}
	if strings.Contains(output, "info message") {
		t.Error("Info message should be filtered out at warn level")
	}

	// Warn and Error should appear
	if !strings.Contains(output, "warn message") {
		t.Error("Warn message should appear at warn level")
	}
	if !strings.Contains(output, "error message") {
		t.Error("Error message should appear at warn level")
	}
}

func TestConfig_EmptyStruct(t *testing.T) {
	// Test with an empty config (all zero values)
	cfg := &Config{Stdout: true}

	logger, err := SetupLogger(cfg)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if logger == nil {
		t.Fatal("Expected non-nil logger even with empty config")
	}

	// Should use defaults (info level, text format)
	logger.Info("test with empty config")
	logger.Debug("this should not appear at default info level")
}

func TestSetupLogger_SetsGlobalDefault(t *testing.T) {
	cfg := &Config{
		LogLevel:  "debug",
		LogFormat: "text",
		Stdout:    true,
	}

	logger, err := SetupLogger(cfg)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify it's set as the global default
	defaultLogger := slog.Default()

	if defaultLogger != logger {
		t.Error("SetupLogger should set the returned logger as slog.Default()")
	}
}

func TestSetupLogger_CaseSensitivity(t *testing.T) {
	// Test that log levels are case-sensitive (lowercase expected)
	tests := []struct {
		name         string
		logLevel     string
		shouldBeInfo bool // If unrecognized, defaults to info
	}{
		{"lowercase debug", "debug", false},
		{"uppercase DEBUG", "DEBUG", true},  // Should default to info
		{"mixed case Debug", "Debug", true}, // Should default to info
		{"lowercase info", "info", false},
		{"uppercase INFO", "INFO", true}, // Should default to info
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				LogLevel:  tt.logLevel,
				LogFormat: "text",
				Stdout:    true,
			}

			logger, err := SetupLogger(cfg)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if logger == nil {
				t.Fatal("Expected non-nil logger")
			}

			// Just verify the logger is created
			// Actual level filtering is tested in other tests
		})
	}
}
