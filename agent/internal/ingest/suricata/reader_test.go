package suricata

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

// TestTailDoesNotLoseRecordsSplitAcrossTicks is the regression test for the
// specific data-loss mode Tail is prone to: a record the writer is still
// appending when the tail ticks must not be consumed as a malformed fragment
// and then skipped. Losing it silently would look exactly like "no threats
// found".
func TestTailDoesNotLoseRecordsSplitAcrossTicks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")

	// Write the first half of a record with no trailing newline.
	half := `{"timestamp":"2026-10-17T12:05:00.000000+0000","event_type":"tls","src_ip":"192.168.1.44","src_port":50000,"dest_ip":"3.170.12.33","dest_port":443,"proto":"TCP","tls":{"sni":"`
	if err := os.WriteFile(path, []byte(half), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan core.NormalizedEvent, 16)
	errCh := make(chan error, 1)
	go func() {
		errCh <- Tail(ctx, path, testAttr(), out, 10*time.Millisecond)
	}()

	// Give Tail a tick or two to observe the partial record and (correctly)
	// decline to consume it.
	time.Sleep(60 * time.Millisecond)

	// Complete the record. If Tail had already consumed the first half, the
	// remainder would be read from the middle of the JSON and dropped.
	rest := `cdn-lfs.huggingface.co"}}` + "\n"
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(rest); err != nil {
		t.Fatal(err)
	}
	f.Close()

	select {
	case ev := <-out:
		if ev.Kind != core.EventTLS {
			t.Errorf("Kind = %q, want %q", ev.Kind, core.EventTLS)
		}
		if ev.SNI != "cdn-lfs.huggingface.co" {
			t.Errorf("SNI = %q, want the value written after the split", ev.SNI)
		}
	case err := <-errCh:
		t.Fatalf("Tail exited early: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("record split across two ticks was lost")
	}

	cancel()
	<-errCh
}

// TestTailEmitsCompleteRecords verifies the ordinary path: records present
// when Tail starts, and records appended later, are both delivered.
func TestTailEmitsCompleteRecords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")

	if err := os.WriteFile(path, []byte(sampleTLS+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan core.NormalizedEvent, 16)
	errCh := make(chan error, 1)
	go func() {
		errCh <- Tail(ctx, path, testAttr(), out, 10*time.Millisecond)
	}()

	select {
	case ev := <-out:
		if ev.SNI != "cdn-lfs.huggingface.co" {
			t.Errorf("SNI = %q, want cdn-lfs.huggingface.co", ev.SNI)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("existing record was not emitted")
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(sampleDNSQuery + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	select {
	case ev := <-out:
		if ev.QueryName != "ollama.com" {
			t.Errorf("QueryName = %q, want ollama.com", ev.QueryName)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("appended record was not emitted")
	}

	cancel()
	<-errCh
}

// TestTailSurvivesTruncation covers Suricata's rotation: the file shrinks
// underneath the tail, which must be detected rather than causing the tail to
// block forever at the stale offset while new telemetry piles up unseen.
func TestTailSurvivesTruncation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")

	if err := os.WriteFile(path, []byte(sampleTLS+"\n"+sampleDNSQuery+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan core.NormalizedEvent, 16)
	errCh := make(chan error, 1)
	go func() {
		errCh <- Tail(ctx, path, testAttr(), out, 10*time.Millisecond)
	}()

	// Drain the two records already present.
	drained := 0
	for drained < 2 {
		select {
		case <-out:
			drained++
		case <-time.After(2 * time.Second):
			t.Fatalf("drained %d of 2 initial records", drained)
		}
	}

	// Truncate in place and write a new record, as a rotate-in-place would.
	if err := os.WriteFile(path, []byte(sampleSSHAuth+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	select {
	case ev := <-out:
		if ev.Kind != core.EventSSHAuth {
			t.Errorf("after truncation Kind = %q, want %q", ev.Kind, core.EventSSHAuth)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tail blocked at the stale offset after truncation")
	}

	cancel()
	<-errCh
}
