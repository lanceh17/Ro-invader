package detect

import (
	"fmt"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

// DefaultScanBurstThreshold is the number of distinct connections in a burst
// window that triggers R5. A device opening this many connections in a short
// window is scanning, not using the network normally.
const DefaultScanBurstThreshold = 20

// DefaultScanBurstWindow is the time window for counting connections.
// A burst is counted within this duration; connections outside it don't count.
const DefaultScanBurstWindow = 30 * time.Second

// BurstDetector implements signal R5: a port-scan burst from a LAN host.
//
// This is a [core.SignalPoCArtifact] signal. Scanning is a common reconnaissance
// step for any attacker, not specific to AI worms, but it's a strong indicator
// of compromise when seen from an IoT device that has no business scanning.
type BurstDetector struct {
	threshold int
	window    time.Duration
}

// NewBurstDetector returns a detector firing on scan bursts.
//
// A zero threshold falls back to DefaultScanBurstThreshold; a zero window
// falls back to DefaultScanBurstWindow.
func NewBurstDetector(threshold int, window time.Duration) *BurstDetector {
	t := DefaultScanBurstThreshold
	if threshold > 0 {
		t = threshold
	}
	w := DefaultScanBurstWindow
	if window > 0 {
		w = window
	}
	return &BurstDetector{threshold: t, window: w}
}

// Kind identifies this detector's signal.
func (d *BurstDetector) Kind() core.SignalKind { return core.SignalBurst }

// Evaluate reports a signal when a device opens many connections in a short window.
//
// This is a simplified implementation. A full implementation would track per-device
// connection counts over time. For now, we flag when a single flow event shows
// evidence of scanning (many connections to different ports).
//
// In production, this would aggregate across multiple events using the detector's
// state, similar to DNSDriftDetector.
func (d *BurstDetector) Evaluate(e core.NormalizedEvent) []core.Signal {
	if len(e.DeviceMAC) == 0 {
		return nil
	}

	// Check for scan-like patterns in the event
	// A flow with many packets to different ports suggests scanning
	if e.Kind == core.EventFlow && e.Duration > 0 {
		// Estimate connections from packet count (rough heuristic)
		// In production, Suricata's eve.json would provide connection counts
		packets := int(e.Bytes / 1000) // rough estimate
		if packets >= d.threshold {
			return []core.Signal{{
				Kind:       core.SignalBurst,
				Class:      core.SignalPoCArtifact,
				DeviceMAC:  e.DeviceMAC,
				Weight:     12,
				Confidence: 0.4,
				Reason:     "possible port scan burst (" + fmtPortCount(packets) + " connections in " + d.window.String() + ")",
				Evidence: map[string]any{
					"bytes":     e.Bytes,
					"duration":  e.Duration.String(),
					"threshold": d.threshold,
				},
			}}
		}
	}

	return nil
}

var _ = time.Second // keep import

var _ = fmtPortCount // keep import

func fmtPortCount(n int) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	if n < 1000*1000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	return fmt.Sprintf("%.1fM", float64(n)/(1000*1000))
}

// ShouldSuppressDeviceClass is the stable hook the rest of the tree calls. The
// concrete decision for this kind is suppressedForClass; the public API stays
// at ShouldSuppressDeviceClass so a caller does not depend on the per-kind
// helper.
func (d *BurstDetector) ShouldSuppressDeviceClass(cls core.DeviceClass) bool {
	return d.suppressed(cls)
}

// suppressed reports whether a signal whose class matters should be suppressed
// for the given device class. Workstations, servers, and mobile hosts commonly
// scan for real (admin workstations, monitoring servers); cameras, IoT, and
// appliances should never.
func (d *BurstDetector) suppressed(cls core.DeviceClass) bool {
	switch cls {
	case core.ClassWorkstation, core.ClassServer, core.ClassMobile:
		return true
	default:
		return false
	}
}
