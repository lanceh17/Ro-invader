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
	"fmt"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

// DefaultWeightTransferThreshold is the bytes-toserver threshold for R1.
// A flow exceeding this to a model-hosting endpoint is the weight-moving
// sequence itself. At 500 MB it is above the noise floor of most LAN traffic
// and below the multi-GB weights a replicator must move.
const DefaultWeightTransferThreshold = 500 << 20 // 500 MiB

// WeightTransferDetector implements signal R1: a large flow to a model host.
//
// It is a [core.SignalReplicationRequired] signal. A replicator must move its
// weights to every new host, and that transfer is the one artifact that is
// hard to avoid producing regardless of how the adversary packages the worm.
type WeightTransferDetector struct {
	threshold int64
	suffixes  []string
}

// NewWeightTransferDetector returns a detector firing on large transfers to
// model-hosting endpoints.
//
// A zero threshold falls back to DefaultWeightTransferThreshold; a nil
// suffixes falls back to DefaultModelHostSuffixes.
func NewWeightTransferDetector(suffixes []string) *WeightTransferDetector {
	w := DefaultWeightTransferThreshold
	if suffixes == nil {
		suffixes = DefaultModelHostSuffixes
	}
	out := make([]string, 0, len(suffixes))
	for _, s := range suffixes {
		s = cleanSuffix(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return &WeightTransferDetector{threshold: int64(w), suffixes: out}
}

// Kind identifies this detector's signal.
func (d *WeightTransferDetector) Kind() core.SignalKind { return core.SignalWeightTransfer }

// Evaluate reports a signal when a large flow targets a known model host.
//
// The flow event must carry bytes_toserver; a flow without it cannot be scored
// and is silently dropped.
func (d *WeightTransferDetector) Evaluate(e core.NormalizedEvent) []core.Signal {
	if e.Kind != core.EventFlow {
		return nil
	}
	if e.Bytes <= d.threshold {
		return nil
	}
	if len(e.DeviceMAC) == 0 {
		return nil
	}
	host := firstNonEmpty(e.SNI, e.QueryName)
	if host == "" {
		return nil
	}
	if !suffixMatch(host, d.suffixes) {
		return nil
	}

	return []core.Signal{{
		Kind:       core.SignalWeightTransfer,
		Class:      core.SignalReplicationRequired,
		DeviceMAC:  e.DeviceMAC,
		Weight:     35,
		Confidence: 0.7,
		Reason:     "large transfer to model host (" + formatBytes(e.Bytes) + " bytes to " + host + ")",
		Evidence: map[string]any{
			"host":        host,
			"bytes":       e.Bytes,
			"bytes_human": formatBytes(e.Bytes),
			"threshold":   d.threshold,
		},
	}}
}

func suffixMatch(host string, suffixes []string) bool {
	host = cleanHost(host)
	for _, s := range suffixes {
		if host == s || hasSuffix(host, s) {
			return true
		}
	}
	return false
}

// evaluate is the per-signal decision for weight-transfer. It is deliberately
// exported as Evaluate; we also surface evaluate here so the per-kind decision
// is easy to test in isolation.
func (d *WeightTransferDetector) evaluate(e core.NormalizedEvent) []core.Signal {
	return d.Evaluate(e)
}

func hasSuffix(host, suffix string) bool {
	return len(host) > len(suffix) && host[len(host)-len(suffix)-1] == '.' && host[len(host)-len(suffix):] == suffix
}

func cleanHost(host string) string {
	host = host[:len(host)]
	for len(host) > 0 && host[len(host)-1] == '.' {
		host = host[:len(host)-1]
	}
	return host
}

func cleanSuffix(s string) string {
	s = s[:len(s)]
	for len(s) > 0 && s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	return s
}

func formatBytes(b int64) string {
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	}
	if b < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	}
	if b < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	}
	return fmt.Sprintf("%.1f GB", float64(b)/(1024*1024*1024))
}
