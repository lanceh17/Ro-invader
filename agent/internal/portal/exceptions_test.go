package portal

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func mustMAC(t *testing.T) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC("aa:bb:cc:dd:ee:01")
	if err != nil {
		t.Fatalf("ParseMAC: %v", err)
	}
	return mac
}

// fixedClock is a mutable clock so tests can cross an expiry boundary.
type fixedClock struct{ t time.Time }

func (c *fixedClock) now() time.Time          { return c.t }
func (c *fixedClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// TestExceptionsMemoryRoundTrip: release, then prove the device is contained
// again the moment the clock passes the expiry — with no one acting on it.
func TestExceptionsMemoryRoundTrip(t *testing.T) {
	clk := &fixedClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	e, err := NewExceptions("", clk.now)
	if err != nil {
		t.Fatalf("NewExceptions: %v", err)
	}
	mac := mustMAC(t)

	if _, ok := e.Active(mac); ok {
		t.Fatal("fresh store reports an active release")
	}
	exc, err := e.Release(mac, "portal", time.Hour)
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if exc.By != "portal" || !exc.ExpiresAt.Equal(clk.t.Add(time.Hour)) {
		t.Fatalf("release = %+v, want by=portal, expiry now+1h", exc)
	}
	if _, ok := e.Active(mac); !ok {
		t.Fatal("release not active immediately after granting")
	}

	clk.advance(59 * time.Minute)
	if _, ok := e.Active(mac); !ok {
		t.Fatal("release expired before its ttl")
	}
	clk.advance(2 * time.Minute)
	if _, ok := e.Active(mac); ok {
		t.Fatal("expired release still active; time-boxing is not enforced")
	}
}

// TestExceptionsPersistAndReload: a release written at runtime survives the
// restart, because re-containing a device the operator freed (or freeing one
// they contained) from a lost state file is a trust-breaking surprise.
func TestExceptionsPersistAndReload(t *testing.T) {
	clk := &fixedClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	path := filepath.Join(t.TempDir(), "state.json")
	e1, err := NewExceptions(path, clk.now)
	if err != nil {
		t.Fatalf("NewExceptions: %v", err)
	}
	mac := mustMAC(t)
	if _, err := e1.Release(mac, "portal", time.Hour); err != nil {
		t.Fatalf("Release: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("state file not written: %v", err)
	}
	var stored []Exception
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatalf("state file is not valid JSON: %v", err)
	}
	if len(stored) != 1 || stored[0].MAC != mac.String() {
		t.Fatalf("state file contents = %+v, want one entry for %s", stored, mac)
	}

	e2, err := NewExceptions(path, clk.now)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, ok := e2.Active(mac); !ok {
		t.Fatal("release lost across reload")
	}
}

func TestExceptionsExpiredEntriesPrunedOnLoad(t *testing.T) {
	clk := &fixedClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	path := filepath.Join(t.TempDir(), "state.json")
	raw, _ := json.Marshal([]Exception{{
		MAC: "aa:bb:cc:dd:ee:01", ExpiresAt: clk.t.Add(-time.Minute), By: "old",
	}})
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	e, err := NewExceptions(path, clk.now)
	if err != nil {
		t.Fatalf("NewExceptions: %v", err)
	}
	if _, ok := e.Active(mustMAC(t)); ok {
		t.Fatal("expired release survived the load")
	}
}

// TestExceptionsMalformedStateIsAnError: a state file we cannot parse must
// stop the daemon, not be skipped — skipping it would re-contain every
// released device while the operator believes they are free.
func TestExceptionsMalformedStateIsAnError(t *testing.T) {
	dir := t.TempDir()

	badJSON := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badJSON, []byte("{not json"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := NewExceptions(badJSON, nil); err == nil {
		t.Error("corrupt state file accepted")
	}

	badMAC := filepath.Join(dir, "badmac.json")
	raw, _ := json.Marshal([]Exception{{MAC: "not-a-mac", ExpiresAt: time.Now().Add(time.Hour)}})
	if err := os.WriteFile(badMAC, raw, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := NewExceptions(badMAC, nil); err == nil {
		t.Error("state file with invalid mac accepted")
	}
}

// TestExceptionsReleasePersistFailureRollsBack: if the release cannot be
// written, the in-memory copy must not claim otherwise — the operator would
// see "released" now and a re-contained device after the next restart.
func TestExceptionsReleasePersistFailureRollsBack(t *testing.T) {
	clk := &fixedClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	// A directory where the state file belongs makes the rename fail.
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	e := &Exceptions{path: path, now: clk.now, items: map[string]Exception{}}
	mac := mustMAC(t)

	if _, err := e.Release(mac, "portal", time.Hour); err == nil {
		t.Fatal("Release succeeded despite unwritable state")
	}
	if _, ok := e.Active(mac); ok {
		t.Fatal("failed release left the device active in memory")
	}
}

func TestExceptionsNilReceiverIsInert(t *testing.T) {
	var e *Exceptions
	if _, ok := e.Active(mustMAC(t)); ok {
		t.Error("nil store reported an active release")
	}
	if _, err := e.Release(mustMAC(t), "portal", time.Hour); err == nil {
		t.Error("nil store accepted a release")
	}
}
