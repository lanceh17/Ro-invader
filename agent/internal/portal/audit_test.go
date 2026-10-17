package portal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readEntries(t *testing.T, path string) []AuditEntry {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	var out []AuditEntry
	for i, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var e AuditEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("audit line %d is not valid JSON: %v", i, err)
		}
		out = append(out, e)
	}
	return out
}

// TestAuditRecordAppendsJSONL: one self-describing line per record, and the
// timestamp is stamped for callers that do not set one (all of them).
func TestAuditRecordAppendsJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	clk := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	a := NewAudit(path, func() time.Time { return clk })

	if err := a.Record(AuditEntry{Action: "sinkhole", MAC: "aa:bb:cc:dd:ee:01", Query: "bad.example", Score: 72.7, Tier: "quarantined", Corroborated: true, DistinctKinds: 2}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := a.Record(AuditEntry{Action: "release", MAC: "aa:bb:cc:dd:ee:01", By: "portal"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries := readEntries(t, path)
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	first, second := entries[0], entries[1]
	if !first.Time.Equal(clk) || !second.Time.Equal(clk) {
		t.Errorf("times = %v / %v, want %v", first.Time, second.Time, clk)
	}
	if first.Action != "sinkhole" || first.Query != "bad.example" || first.Score != 72.7 || first.Tier != "quarantined" || !first.Corroborated || first.DistinctKinds != 2 {
		t.Errorf("sinkhole entry = %+v, fields not preserved", first)
	}
	if second.Action != "release" || second.By != "portal" {
		t.Errorf("release entry = %+v, fields not preserved", second)
	}
}

// TestAuditLazilyCreatesFile: runs that never contain anything must leave no
// artifacts behind — observing a network should not litter it.
func TestAuditLazilyCreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a := NewAudit(path, nil)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("audit file exists before any record (err=%v)", err)
	}
	if err := a.Record(AuditEntry{Action: "sinkhole"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("audit file missing after record: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	// Reuse after Close reopens the file rather than failing silently.
	if err := a.Record(AuditEntry{Action: "release"}); err != nil {
		t.Fatalf("Record after Close: %v", err)
	}
	_ = a.Close()
	if got := len(readEntries(t, path)); got != 2 {
		t.Errorf("got %d entries, want 2", got)
	}
}

func TestAuditNilReceiverIsInert(t *testing.T) {
	var a *Audit
	if err := a.Record(AuditEntry{Action: "sinkhole"}); err == nil {
		t.Error("nil audit accepted a record")
	}
	if err := a.Close(); err != nil {
		t.Errorf("nil Close: %v", err)
	}
}
