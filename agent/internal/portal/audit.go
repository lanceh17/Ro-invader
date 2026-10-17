package portal

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// AuditEntry is one line of the action audit log: what happened to a device,
// why, and who did it.
//
// The log answers the two questions an incident review asks first: "what did
// the agent do to my network, and when?" and "who released this device, and
// on what grounds?" ARCHITECTURE.md requires the log to exist for every
// containment decision; SAFETY.md's reversibility guarantee implies the same
// record for every release, otherwise release and containment are unaccounted
// leverage.
type AuditEntry struct {
	Time time.Time `json:"time"`
	// Action is "sinkhole" for a containment decision applied at the DNS
	// layer, or "release" for an operator-authorized exception.
	Action string `json:"action"`

	// Device attribution. MAC/IPs/Vendor/Class may be empty when the event
	// could not be attributed, which is itself worth recording rather than
	// dropping.
	MAC    string   `json:"mac,omitempty"`
	IPs    []string `json:"ips,omitempty"`
	Vendor string   `json:"vendor,omitempty"`
	Class  string   `json:"class,omitempty"`

	// Assessment state at decision time (sinkhole) or at release time.
	// Score is never omitted for attributed entries: a containment decision
	// with no score behind it is unauditable.
	Score         float64  `json:"score"`
	Tier          string   `json:"tier,omitempty"`
	Corroborated  bool     `json:"corroborated"`
	DistinctKinds int      `json:"distinct_kinds,omitempty"`
	Reasons       []string `json:"reasons,omitempty"`

	// Query is the name that triggered a sinkhole.
	Query string `json:"query,omitempty"`

	// By and Expires describe a release: who granted it and when it lapses.
	By      string     `json:"by,omitempty"`
	Expires *time.Time `json:"expires_at,omitempty"`
}

// Audit appends entries as JSON Lines: one self-describing object per line,
// no schema evolution problem, trivially greppable and machine-readable.
//
// Safe for concurrent use — the DNS query path records sinkholes while the
// portal handler records releases.
type Audit struct {
	mu   sync.Mutex
	path string // may be empty only if constructed with a writer (tests)
	now  func() time.Time
	f    *os.File
}

// NewAudit returns a log that appends to path, creating it on first record.
//
// The file is opened lazily so that runs which never contain anything (such
// as -observe demonstrations) leave no artifacts behind.
func NewAudit(path string, now func() time.Time) *Audit {
	if now == nil {
		now = time.Now
	}
	return &Audit{path: path, now: now}
}

// Record appends one entry, stamping Time when the caller left it zero.
//
// Each entry is written and fsynced as a unit. The volumes here are
// human-scale (one line per contained query and per release), and an audit
// line lost to a crash is exactly the line a review would need.
func (a *Audit) Record(e AuditEntry) error {
	if a == nil {
		return fmt.Errorf("portal: no audit log configured")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if e.Time.IsZero() {
		e.Time = a.now()
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("portal: encoding audit entry: %w", err)
	}
	if a.f == nil {
		if a.path == "" {
			return fmt.Errorf("portal: no audit log configured")
		}
		f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("portal: opening audit log: %w", err)
		}
		a.f = f
	}
	if _, err := a.f.Write(append(raw, '\n')); err != nil {
		return fmt.Errorf("portal: writing audit log: %w", err)
	}
	if err := a.f.Sync(); err != nil {
		return fmt.Errorf("portal: syncing audit log: %w", err)
	}
	return nil
}

// Close flushes and closes the underlying file, if one was opened.
func (a *Audit) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		return nil
	}
	err := a.f.Close()
	a.f = nil
	if err != nil {
		return fmt.Errorf("portal: closing audit log: %w", err)
	}
	return nil
}
