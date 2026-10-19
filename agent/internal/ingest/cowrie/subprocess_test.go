package cowrie

import (
	"context"
	"testing"
	"time"
)

func TestSubprocessConfigValidation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Test that NewSubprocess validates required fields (empty strings)
	cfg := SubprocessConfig{
		BinPath:    "python3",
		ConfigPath: "/nonexistent/cowrie.cfg",
		LogPath:    "/tmp/cowrie.json",
		WorkDir:    "",
		Attr:       nil,
	}

	_, err := NewSubprocess(context.Background(), cfg)
	if err == nil {
		t.Error("expected error for empty workdir")
	}

	// Test with empty config path
	cfg.WorkDir = "/tmp"
	cfg.ConfigPath = ""
	_, err = NewSubprocess(ctx, cfg)
	if err == nil {
		t.Error("expected error for empty config path")
	}

	// Test with empty log path
	cfg.ConfigPath = "/tmp/cowrie.cfg"
	cfg.LogPath = ""
	_, err = NewSubprocess(ctx, cfg)
	if err == nil {
		t.Error("expected error for empty log path")
	}
}

func TestSubprocessConfigDefaults(t *testing.T) {
	if DefaultBinPath != "python3" {
		t.Errorf("DefaultBinPath = %q, want python3", DefaultBinPath)
	}
}

func TestDefaultConfigTemplate(t *testing.T) {
	if DefaultConfigTemplate == "" {
		t.Fatal("DefaultConfigTemplate should not be empty")
	}
	// Check that template contains required sections
	if !contains(DefaultConfigTemplate, "[ssh]") {
		t.Error("template missing [ssh] section")
	}
	if !contains(DefaultConfigTemplate, "[telnet]") {
		t.Error("template missing [telnet] section")
	}
	if !contains(DefaultConfigTemplate, "[output_jsonlog]") {
		t.Error("template missing [output_jsonlog] section")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || contains(s[1:], substr)))
}
