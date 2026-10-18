package detect

import (
	"net/netip"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

// DefaultEastWestThreshold is the bytes threshold for R4 east-west detection.
// Sustained peer-to-peer volume between LAN devices is the signature of a
// distributed inference swarm. At 100 MB it catches bulk transfers without
// flagging normal discovery traffic.
const DefaultEastWestThreshold = 100 << 20 // 100 MiB

// DefaultEastWestPeers is the set of private prefixes that count as "east-west".
// Traffic between these ranges stays on the LAN and is the surface a worm
// propagates across.
var DefaultEastWestPeers = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
}

// EastWestVolumeDetector implements signal R4: sustained east-west peer volume.
//
// This is a [core.SignalReplicationRequired] signal. A replicator coordinating
// distributed inference across multiple hosts must exchange data East-West, and
// that volume is hard to disguise as normal LAN traffic.
type EastWestVolumeDetector struct {
	threshold int64
	peers     []netip.Prefix
}

// NewEastWestVolumeDetector returns a detector firing on large east-west flows.
//
// A zero threshold falls back to DefaultEastWestThreshold; a nil peers slice
// falls back to DefaultEastWestPeers.
func NewEastWestVolumeDetector(peers []string) *EastWestVolumeDetector {
	out := make([]netip.Prefix, 0, len(peers))
	for _, p := range peers {
		if p != "" {
			if prefix, err := netip.ParsePrefix(p); err == nil {
				out = append(out, prefix)
			}
		}
	}
	if len(out) == 0 {
		// Fall back to defaults
		for _, p := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
			if prefix, err := netip.ParsePrefix(p); err == nil {
				out = append(out, prefix)
			}
		}
	}
	return &EastWestVolumeDetector{threshold: 100 << 20, peers: out}
}

// Kind identifies this detector's signal.
func (d *EastWestVolumeDetector) Kind() core.SignalKind { return core.SignalEastWestVolume }

// Evaluate reports a signal when a large flow is between two private addresses.
//
// Both src and dst must be in the configured peer ranges for this to fire.
func (d *EastWestVolumeDetector) Evaluate(e core.NormalizedEvent) []core.Signal {
	if e.Kind != core.EventFlow {
		return nil
	}
	if e.Bytes <= 100<<20 {
		return nil
	}
	if len(e.DeviceMAC) == 0 {
		return nil
	}

	// Check if both src and dst are in the configured peer ranges
	srcPrivate := isInPeerRanges(e.Src.IP, d.peers)
	dstPrivate := isInPeerRanges(e.Dst.IP, d.peers)

	if !srcPrivate || !dstPrivate {
		return nil
	}

	return []core.Signal{{
		Kind:       core.SignalEastWestVolume,
		Class:      core.SignalReplicationRequired,
		DeviceMAC:  e.DeviceMAC,
		Weight:     25,
		Confidence: 0.6,
		Reason:     "sustained east-west volume (" + formatBytes(e.Bytes) + " bytes between LAN hosts)",
		Evidence: map[string]any{
			"src":         e.Src.IP.String(),
			"dst":         e.Dst.IP.String(),
			"bytes":       e.Bytes,
			"bytes_human": formatBytes(e.Bytes),
		},
	}}
}

// isInPeerRanges checks if an IP is within any of the configured peer ranges.
func isInPeerRanges(ip netip.Addr, peers []netip.Prefix) bool {
	for _, p := range peers {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

var _ = core.SignalKind("") // keep import

// firstNonEmpty is provided here for symmetry with the other detectors even
// though EastWestVolume never uses a name-based host match.
var _ = firstNonEmpty("", "") // keep import
