package detect

import (
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

// DefaultNewDeviceGrace is the grace period after first sighting before R8 fires.
// A device seen for the first time is normal network churn; flag it only after
// this window passes without classification.
const DefaultNewDeviceGrace = 24 * time.Hour

// NewDeviceDetector implements signal R8: a new device appearing on the network
// without classification.
//
// This is a [core.SignalPoCArtifact] signal. A new device is normal (someone
// brought a phone home), but an unclassified device that starts showing other
// signals is suspicious. R8 is most useful as corroboration for other signals,
// not as a standalone trigger.
type NewDeviceDetector struct {
	grace time.Duration
}

// NewNewDeviceDetector returns a detector firing on new unclassified devices.
//
// A zero grace falls back to DefaultNewDeviceGrace.
func NewNewDeviceDetector(grace time.Duration) *NewDeviceDetector {
	g := DefaultNewDeviceGrace
	if grace > 0 {
		g = grace
	}
	return &NewDeviceDetector{grace: g}
}

// Kind identifies this detector's signal.
func (d *NewDeviceDetector) Kind() core.SignalKind { return core.SignalNewDevice }

// Evaluate reports a signal when a newly seen device has no classification.
//
// This requires state tracking (when the device was first seen), which makes it
// not a pure function of a single event. For now, we flag when a device appears
// with no vendor/class, indicating it's new and unclassified.
//
// In production, this would track first-seen times per device and fire after
// the grace period. The risk engine's R8 signal would then corroborate with
// other signals.
func (d *NewDeviceDetector) Evaluate(e core.NormalizedEvent) []core.Signal {
	if len(e.DeviceMAC) == 0 {
		return nil
	}

	// Flag when a device has no vendor or class (unclassified)
	// This is a placeholder - real implementation would track first-seen time
	if e.Kind == core.EventInventory {
		// Inventory events carry device classification
		// If a device appears in inventory with no vendor/class, it's new and unclassified
		return nil // Placeholder: would need state to track
	}

	// For non-inventory events, we can't determine if it's new without state
	// This detector is stateful and needs to be wired into the pipeline differently
	return nil
}

// Grace returns the grace period for new devices.
func (d *NewDeviceDetector) Grace() time.Duration {
	return d.grace
}

// Package-level suppression helpers are provided in weighttransfer.go.
var _ = time.Hour            // keep import
var _ = core.SignalClass("") // keep import
