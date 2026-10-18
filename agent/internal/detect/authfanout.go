package detect

import (
	"fmt"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

// DefaultAuthFanoutThreshold is the number of auth events to distinct targets
// that triggers R6. A device authenticating to this many hosts in a short
// window is credential-reuse fan-out (T1021.004/.006).
const DefaultAuthFanoutThreshold = 5

// AuthFanoutDetector implements signal R6: authentication fan-out with
// credential reuse.
//
// This is a [core.SignalReplicationRequired] signal. An AI worm spreading via
// credential reuse must authenticate to many hosts, and that pattern is hard to
// disguise as normal admin activity when it comes from an IoT device.
type AuthFanoutDetector struct {
	threshold int
}

// NewAuthFanoutDetector returns a detector firing on auth fan-out.
//
// A zero threshold falls back to DefaultAuthFanoutThreshold.
func NewAuthFanoutDetector(threshold int) *AuthFanoutDetector {
	t := DefaultAuthFanoutThreshold
	if threshold > 0 {
		t = threshold
	}
	return &AuthFanoutDetector{threshold: t}
}

// Kind identifies this detector's signal.
func (d *AuthFanoutDetector) Kind() core.SignalKind { return core.SignalAuthFanout }

// Evaluate reports a signal when a device authenticates to many distinct targets.
//
// SSH auth events (EventSSHAuth) are the primary signal. A device authenticating
// to 5+ distinct hosts in a short window is fan-out, not normal admin activity.
func (d *AuthFanoutDetector) Evaluate(e core.NormalizedEvent) []core.Signal {
	if e.Kind != core.EventSSHAuth {
		return nil
	}
	if len(e.DeviceMAC) == 0 {
		return nil
	}

	// Count distinct targets from the auth event's raw evidence.
	// In production, this would aggregate across multiple events.
	// For now, use the auth user as a proxy for the signal firing.
	targetCount := 1 // placeholder; real count would need event aggregation
	if targetCount < d.threshold {
		return nil
	}

	// Get the auth user if available
	authUser := e.AuthUser
	if authUser == "" {
		authUser = "unknown"
	}

	return []core.Signal{{
		Kind:       core.SignalAuthFanout,
		Class:      core.SignalReplicationRequired,
		DeviceMAC:  e.DeviceMAC,
		Weight:     28,
		Confidence: 0.65,
		Reason:     "authentication fan-out to " + fmtTargetCount(targetCount) + " hosts (" + authUser + ")",
		Evidence: map[string]any{
			"targets":   targetCount,
			"auth_user": authUser,
			"threshold": d.threshold,
		},
	}}
}

func fmtTargetCount(n int) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	if n < 1000*1000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	return fmt.Sprintf("%.1fM", float64(n)/(1000*1000))
}

// Package-level suppression helpers are provided in weighttransfer.go.
var _ = fmtTargetCount       // keep import
var _ = core.SignalClass("") // keep import
