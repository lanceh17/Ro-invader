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
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

// DefaultBeaconInterval is the typical beacon interval for C2 callbacks.
// A device connecting at regular intervals on non-standard ports is beaconing.
const DefaultBeaconInterval = 60 * time.Second

// DefaultBeaconWindow is the observation window for detecting beacons.
// We need to see several beacons within this window to confirm the pattern.
const DefaultBeaconWindow = 30 * time.Minute

// DefaultNonStandardPorts is the set of ports that are "non-standard" for
// beacon detection. Traffic on these ports is more suspicious than on 80/443.
var DefaultNonStandardPorts = []int{
	// Common C2/beacon ports
	8080, 8443, // HTTP alternates
	4444, 5555, // Metasploit/meterpreter
	1337, 31337, // Back orifice
	4443, 4444, // Common malware ports
	9001, 9002, // Tor/IRC
	1080,  // SOCKS proxy
	10000, // GUI remote access
}

// BeaconDetector implements signal R9: periodic beaconing on non-standard ports.
//
// This is a [core.SignalPoCArtifact] signal. C2 beacons are a common malware
// pattern, but the specific interval and port are easily changed by an adversary.
// This detector catches the common case; a sophisticated adversary would evade it.
type BeaconDetector struct {
	interval time.Duration
	window   time.Duration
	ports    []int
}

// NewBeaconDetector returns a detector firing on beacon patterns.
//
// A zero interval falls back to DefaultBeaconInterval; a zero window falls back
// to DefaultBeaconWindow; a nil ports slice falls back to DefaultNonStandardPorts.
func NewBeaconDetector(interval, window time.Duration, ports []int) *BeaconDetector {
	i := DefaultBeaconInterval
	if interval > 0 {
		i = interval
	}
	w := DefaultBeaconWindow
	if window > 0 {
		w = window
	}
	p := DefaultNonStandardPorts
	if ports != nil {
		p = ports
	}
	return &BeaconDetector{interval: i, window: w, ports: p}
}

// Kind identifies this detector's signal.
func (d *BeaconDetector) Kind() core.SignalKind { return core.SignalBeacon }

// Evaluate reports a signal when a device connects to non-standard ports at
// regular intervals.
//
// This is a simplified implementation. A full implementation would track
// connection timing per device and detect periodicity. For now, we flag when
// a flow event uses a non-standard port.
//
// In production, this would aggregate timing across multiple events and detect
// the regular interval pattern.
func (d *BeaconDetector) Evaluate(e core.NormalizedEvent) []core.Signal {
	if len(e.DeviceMAC) == 0 {
		return nil
	}

	// Check if the destination port is non-standard
	if e.Dst.Port == 0 {
		return nil
	}

	if !isNonStandardPort(int(e.Dst.Port), d.ports) {
		return nil
	}

	// Flag connections to non-standard ports
	// In production, we'd track timing and only fire after seeing the periodic pattern
	return []core.Signal{{
		Kind:       core.SignalBeacon,
		Class:      core.SignalPoCArtifact,
		DeviceMAC:  e.DeviceMAC,
		Weight:     8,
		Confidence: 0.35,
		Reason:     "connection to non-standard port " + fmtPort(int(e.Dst.Port)) + " (possible C2 beacon)",
		Evidence: map[string]any{
			"port":     int(e.Dst.Port),
			"interval": d.interval.String(),
			"window":   d.window.String(),
		},
	}}
}

func isNonStandardPort(port int, ports []int) bool {
	for _, p := range ports {
		if port == p {
			return true
		}
	}
	return false
}

func fmtPort(port int) string {
	return fmt.Sprintf("%d", port)
}

// ShouldSuppressDeviceClass returns whether the beacon signal is suppressed
// for the given device class. Servers and workstations commonly use non-standard
// ports for development and infrastructure; cameras, IoT, and appliances should
// not. The decision is deliberately routed through the same public hook so that
// suppression is one rule for the whole tree.
func (d *BeaconDetector) ShouldSuppressDeviceClass(cls core.DeviceClass) bool {
	return d.suppressedForClass(cls)
}

func (d *BeaconDetector) suppressedForClass(cls core.DeviceClass) bool {
	return d.suppressed(cls)
}

// suppressed reports whether a beacon signal should be suppressed for the given
// device class.
func (d *BeaconDetector) suppressed(cls core.DeviceClass) bool {
	switch cls {
	case core.ClassServer, core.ClassWorkstation:
		return true // Servers and dev workstations often use non-standard ports
	default:
		return false
	}
}

var _ = time.Minute          // keep import
var _ = core.SignalClass("") // keep import

// BeaconDetector satisfies driftInspector so the pipeline can reach its
// ShouldSuppressDeviceClass without casting.
var _ interface {
	ShouldSuppressDeviceClass(core.DeviceClass) bool
} = (*BeaconDetector)(nil)
