package portal

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Exception is a time-boxed release of one device from quarantine.
//
// It is deliberately temporary. A release is an operator saying "I have looked
// at this and I accept it for now", not a verdict that the evidence was wrong;
// the signals that produced the quarantine keep decaying on their normal
// half-life, and when the exception expires the engine's tier applies again by
// itself. An exception that never expired would be a permanent bypass an
// operator could forget, which is exactly the kind of state SAFETY.md forbids.
type Exception struct {
	// MAC is the canonical string form of the released device, stored as a
	// string rather than net.HardwareAddr because that type marshals as raw
	// bytes and the file is meant to be read by a human inspecting state.
	MAC        string    `json:"mac"`
	ReleasedAt time.Time `json:"released_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	// By records who released it, so the audit trail answers "who let this
	// device back on?" without consulting logs elsewhere.
	By string `json:"by"`
}

// Exceptions is the persisted set of active releases.
//
// All methods are safe for concurrent use: the DNS path reads it on every
// query while the portal writes it on a release.
type Exceptions struct {
	mu    sync.Mutex
	path  string // empty means memory-only; nothing persists
	now   func() time.Time
	items map[string]Exception
}

// NewExceptions returns a store backed by path, loading what is already there.
//
// An empty path keeps everything in memory, which is what tests and
// short-lived runs use. An existing file with malformed content is an error
// rather than something to ignore: silently discarding releases would
// re-contain devices the operator already freed, and silently discarding a
// corrupt file's replacement would erase them.
func NewExceptions(path string, now func() time.Time) (*Exceptions, error) {
	if now == nil {
		now = time.Now
	}
	e := &Exceptions{path: path, now: now, items: map[string]Exception{}}
	if path == "" {
		return e, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return e, nil
		}
		return nil, fmt.Errorf("portal: reading releases %s: %w", path, err)
	}
	var stored []Exception
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, fmt.Errorf("portal: parsing releases %s: %w", path, err)
	}
	for _, exc := range stored {
		if _, err := net.ParseMAC(exc.MAC); err != nil {
			return nil, fmt.Errorf("portal: releases %s has invalid mac %q", path, exc.MAC)
		}
		if exc.ExpiresAt.After(e.now()) {
			e.items[exc.MAC] = exc
		}
	}
	return e, nil
}

// Active reports whether mac currently holds an unexpired release.
//
// Expired entries return false but are not deleted here: this is the hot path
// the DNS resolver walks on every query, and mutation happens only on load and
// release, where the write is already going to disk.
func (e *Exceptions) Active(mac net.HardwareAddr) (Exception, bool) {
	if e == nil {
		return Exception{}, false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	exc, ok := e.items[mac.String()]
	if !ok || !exc.ExpiresAt.After(e.now()) {
		return Exception{}, false
	}
	return exc, true
}

// Release records a release for mac lasting ttl, attributed to by, and
// persists it.
//
// If persistence fails the entry is rolled back and the error returned: a
// release that exists only in this process's memory would silently evaporate
// at the next restart and re-contain the device while the operator believes
// it was freed. Failing loudly is the safe behavior.
func (e *Exceptions) Release(mac net.HardwareAddr, by string, ttl time.Duration) (Exception, error) {
	if e == nil {
		return Exception{}, fmt.Errorf("portal: no release store configured")
	}
	if ttl <= 0 {
		return Exception{}, fmt.Errorf("portal: release ttl must be positive")
	}
	key := mac.String()
	now := e.now()
	exc := Exception{
		MAC:        key,
		ReleasedAt: now,
		ExpiresAt:  now.Add(ttl),
		By:         by,
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	prev, had := e.items[key]
	e.items[key] = exc
	e.pruneExpiredLocked()
	if err := e.saveLocked(); err != nil {
		if had {
			e.items[key] = prev
		} else {
			delete(e.items, key)
		}
		return Exception{}, err
	}
	return exc, nil
}

// pruneExpiredLocked drops entries whose time has passed. Callers hold e.mu.
func (e *Exceptions) pruneExpiredLocked() {
	now := e.now()
	for k, exc := range e.items {
		if !exc.ExpiresAt.After(now) {
			delete(e.items, k)
		}
	}
}

// saveLocked writes the store atomically: a temp file in the same directory,
// then a rename over the destination. A crash mid-write leaves either the old
// file or the new one, never a truncated state file that would parse to no
// releases and re-contain every freed device on the next start.
func (e *Exceptions) saveLocked() error {
	if e.path == "" {
		return nil
	}
	all := make([]Exception, 0, len(e.items))
	for _, exc := range e.items {
		all = append(all, exc)
	}
	raw, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return fmt.Errorf("portal: encoding releases: %w", err)
	}
	dir := filepath.Dir(e.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("portal: creating release state dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".releases-*.json")
	if err != nil {
		return fmt.Errorf("portal: writing release state: %w", err)
	}
	tmpName := tmp.Name()
	_, werr := tmp.Write(append(raw, '\n'))
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		os.Remove(tmpName)
		if werr != nil {
			return fmt.Errorf("portal: writing release state: %w", werr)
		}
		return fmt.Errorf("portal: writing release state: %w", cerr)
	}
	if err := os.Rename(tmpName, e.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("portal: committing release state: %w", err)
	}
	return nil
}
