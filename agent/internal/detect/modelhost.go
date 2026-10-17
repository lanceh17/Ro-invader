// Package detect holds pure-function signal matchers.
//
// Every detector here obeys the same three rules, because they are what make
// this package testable with no Suricata, no router, and no hardware:
//
//  1. Evaluate accepts a core.NormalizedEvent and returns signals. Nothing else.
//  2. No I/O, no clock reads, no global mutable state.
//  3. Detectors are device-agnostic. They report what they observed; the risk
//     engine applies device-class weighting, because only the risk engine
//     holds the Device.
package detect

import (
	"strings"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

// DefaultModelHostSuffixes are the destinations a weight-based replicator
// pulls its own weights from. A request to any of these from a device that
// has no business running models is anomalous regardless of transfer size,
// which makes this far more sensitive than a volume threshold.
//
// This is configuration, not code. Extend it from feed data rather than
// editing this slice, and treat any list here as a starting point that will
// rot as hosting providers change.
var DefaultModelHostSuffixes = []string{
	"huggingface.co",
	"cdn-lfs.huggingface.co",
	"hf.co",
	"ollama.com",
	"registry.ollama.ai",
	"raw.githubusercontent.com", // model weights are frequently hosted here
}

// ModelHostDetector implements signal R2: a model-hosting domain contacted by
// a device whose class makes that contact surprising.
//
// It is a [core.SignalReplicationRequired] signal. A weight-based replicator
// cannot replicate without obtaining weights from somewhere, and that
// somewhere is almost always one of these endpoints.
type ModelHostDetector struct {
	suffixes []string
}

// NewModelHostDetector returns a detector matching the given suffixes, or
// DefaultModelHostSuffixes when none are supplied.
func NewModelHostDetector(suffixes []string) *ModelHostDetector {
	if len(suffixes) == 0 {
		suffixes = DefaultModelHostSuffixes
	}
	out := make([]string, 0, len(suffixes))
	for _, s := range suffixes {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		// Strip a leading wildcard so callers can write "cdn-lfs.*" without
		// the matcher having to special-case it.
		s = strings.TrimPrefix(s, "*.")
		out = append(out, s)
	}
	return &ModelHostDetector{suffixes: out}
}

// Kind identifies this detector's signal.
func (d *ModelHostDetector) Kind() core.SignalKind { return core.SignalModelHostOnIoT }

// Evaluate reports a signal when the event's SNI or DNS question name falls
// in a configured model-host category.
//
// The signal carries base weight and confidence only. Device-class weighting
// is applied later by the risk engine, which is the component that knows
// whether the originator was a workstation (expected) or a security camera
// (extremely not).
func (d *ModelHostDetector) Evaluate(e core.NormalizedEvent) []core.Signal {
	// We need to attribute this to a device. An event with no LAN-side MAC
	// tells us that something talked to a model host, but not that it was
	// one of ours, which is the whole point of the signal.
	if len(e.DeviceMAC) == 0 {
		return nil
	}

	host := firstNonEmpty(e.SNI, e.QueryName)
	if host == "" {
		return nil
	}
	if !d.matches(host) {
		return nil
	}

	return []core.Signal{{
		Kind:      core.SignalModelHostOnIoT,
		Class:     core.SignalReplicationRequired,
		DeviceMAC: e.DeviceMAC,
		// Base weight is deliberately modest on its own. On a workstation
		// this is nothing; on an appliance it is the strongest single signal
		// in the set. That distinction belongs to the risk engine.
		Weight:     20,
		Confidence: 0.6,
		Reason:     "device contacted a model-hosting endpoint (" + host + ")",
		Evidence: map[string]any{
			"host":       host,
			"event_kind": string(e.Kind),
			"sni":        e.SNI,
			"query":      e.QueryName,
		},
	}}
}

// matches performs a suffix match, so that "cdn-lfs.huggingface.co" matches
// the configured "huggingface.co" without requiring every subdomain to be
// enumerated.
func (d *ModelHostDetector) matches(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, s := range d.suffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
