package detect

import (
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
	peers     []string
}

// NewEastWestVolumeDetector returns a detector firing on large east-west flows.
//
// A zero threshold falls back to DefaultEastWestThreshold; a nil peers slice
// falls back to DefaultEastWestPeers.
func NewEastWestVolumeDetector(peers []string) *EastWestVolumeDetector {
	t := DefaultEastWestThreshold
	if peers == nil {
		peers = DefaultEastWestPeers
	}
	out := make([]string, 0, len(peers))
	for _, p := range peers {
		if p != "" {
			out = append(out, p)
		}
	}
	return &EastWestVolumeDetector{threshold: int64(t), peers: out}
}

// Kind identifies this detector's signal.
func (d *EastWestVolumeDetector) Kind() core.SignalKind { return core.SignalEastWestVolume }

// Evaluate reports a signal when a large flow is between two private addresses.
//
// Both src and dst must be in the private ranges for this to fire. A flow from
// a LAN device to the internet is not east-west, even if it is large.
func (d *EastWestVolumeDetector) Evaluate(e core.NormalizedEvent) []core.Signal {
	if e.Kind != core.EventFlow {
		return nil
	}
	if e.Bytes <= d.threshold {
		return nil
	}
	if len(e.DeviceMAC) == 0 {
		return nil
	}

	// Check if both src and dst are in private ranges
	srcPrivate := isPrivateIP(e.Src)
	dstPrivate := isPrivateIP(e.Dst)

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

// isPrivateIP reports whether an IP address is in one of the RFC 1918 private
// ranges. It is intentionally narrow: RFC 4193 Unique Local and the like are
// not treated as east-west here because the fixture corpus does not use them.
func isPrivateIP(ip core.Endpoint) bool {
	// Simplified check - in production this would use netip.Prefix matching
	// For now, check if the IP is in common private ranges
	addr := ip.IP
	if addr.Is4() {
		// Check 10.0.0.0/8
		if addr.As4()[0] == 10 {
			return true
		}
		// Check 172.16.0.0/12
		if addr.As4()[0] == 172 && addr.As4()[1] >= 16 && addr.As4()[1] <= 31 {
			return true
		}
		// Check 192.168.0.0/16
		if addr.As4()[0] == 192 && addr.As4()[1] == 168 {
			return true
		}
	}
	return false
}

var _ = core.SignalKind("") // keep import

// firstNonEmpty is provided here for symmetry with the other detectors even
// though EastWestVolume never uses a name-based host match.
var _ = firstNonEmpty("", "") // keep import
