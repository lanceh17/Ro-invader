// Package act defines the interface through which the system affects network
// state, and the adapters that implement it against real routers.
//
// Note what is absent from this interface: there is no verb that transmits to
// a managed device. That is not an oversight. R0-Invader is passive by
// architecture, and enforcing it in the interface shape means a future
// contribution cannot quietly add probing without also changing this file and
// confronting the safety commitment in SAFETY.md.
package act

import (
	"context"
	"net/netip"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

// Actuator pushes containment and blocking state to a router.
//
// Adapters must be idempotent: calling Quarantine twice for the same device
// must leave the same end state as calling it once, with no duplicated rules
// and no traffic gap during a redundant apply.
type Actuator interface {
	// Name identifies the backend for logging and health reporting.
	Name() string

	// Authoritative declares that this host's resolver is authoritative for
	// the device, so that walled-garden restriction and remediation
	// notification share one mechanism.
	Authoritative(ctx context.Context, d core.Device) error

	// Quarantine applies the given policy to the device. The policy's
	// BlockPeers and RestrictEgress fields determine the effect; passing
	// PolicyMonitor is a no-op that must nonetheless succeed.
	Quarantine(ctx context.Context, d core.Device, p core.Policy) error

	// Release removes all containment and returns the device to full access.
	// It must always succeed for a previously quarantined device: a security
	// tool that can lock a device out with no route to recovery is worse than
	// no tool.
	Release(ctx context.Context, d core.Device) error

	// BlockNet blocks a prefix for the given duration. The `until` field
	// makes expiry part of the contract rather than a background cleanup
	// concern, so that a crashed control plane leaves no permanent block.
	BlockNet(ctx context.Context, n netip.Prefix, until time.Time) error

	// BlockDomain sinkholes a domain for the given duration.
	BlockDomain(ctx context.Context, d string, until time.Time) error

	// Health reports whether the actuator can currently reach its router and
	// read back the rules it believes it owns. A failing Health must block
	// new containment actions rather than queueing them silently.
	Health(ctx context.Context) error
}

// Supported lists the actuator backends compiled into this build.
func Supported() []string {
	return []string{"openwrt", "vyos", "opnsense"}
}
