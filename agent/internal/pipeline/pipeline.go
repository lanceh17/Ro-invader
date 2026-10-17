// Package pipeline connects the ingest paths to the risk engine.
//
// Before this package existed, the connection lived inline in the CLI's analyze
// command: read events, attribute them, run detectors, observe the engine. That
// loop is the single place the whole system has side effects, and it was about
// to be written a second time for the DNS resolver. Centralizing it means the
// Suricata path and the resolver path are not merely similar but identical, and
// that a change to attribution or observation is one edit.
//
// The pipeline owns three things and nothing else:
//
//  1. Attribution — turning a source IP into a device MAC, because a signal
//     that cannot name a device cannot be acted on.
//  2. Detection — running the detector set over the attributed event.
//  3. Observation — feeding the resulting signals into the risk engine.
//
// It does not score, does not decide, and does not contain. Those belong to the
// risk engine and the actuator, which keep the boundary SAFETY.md draws: this
// package observes, others act.
package pipeline

import (
	"net"
	"net/netip"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
	"github.com/lanceh17/Ro-invader/agent/internal/detect"
	"github.com/lanceh17/Ro-invader/agent/internal/risk"
)

// Attributor resolves a source IP to the device that owns it.
//
// It is declared here rather than imported from the Suricata package so this
// package depends only on the shape, not on a specific ingest path. The
// inventory satisfies it structurally, so no adapter is needed.
type Attributor interface {
	MACFor(ip netip.Addr) (net.HardwareAddr, bool)
}

// MapAttributor is the trivial implementation: a static IP-to-MAC table. It
// exists so a caller with a table in hand — a test, or a wiring that loaded a
// static inventory — can pass it directly without declaring a type.
type MapAttributor map[netip.Addr]net.HardwareAddr

// MACFor implements Attributor.
func (m MapAttributor) MACFor(ip netip.Addr) (net.HardwareAddr, bool) {
	mac, ok := m[ip.Unmap()]
	return mac, ok
}

// Pipeline is the observe-side connective tissue: events in, signals recorded.
// It is safe for concurrent use, because the risk engine it writes to is.
type Pipeline struct {
	attr      Attributor
	detectors []core.Detector
	engine    *risk.Engine
}

// New builds a Pipeline.
//
// A nil engine falls back to a default-constructed one, a nil attributor is
// permitted and yields unattributable events (which every detector drops, so
// the honest consequence — no signals — is what happens), and an empty detector
// set falls back to detect.All(). The fallbacks exist so that the common case
// needs no arguments and the failure mode of forgetting to pass detectors is an
// empty pipeline rather than one that silently ignores everything.
func New(attr Attributor, engine *risk.Engine, detectors ...core.Detector) *Pipeline {
	if engine == nil {
		engine = risk.New()
	}
	if len(detectors) == 0 {
		detectors = detect.All()
	}
	return &Pipeline{attr: attr, detectors: detectors, engine: engine}
}

// Engine exposes the risk engine this pipeline feeds, so a caller can assess
// devices after ingesting events.
func (p *Pipeline) Engine() *risk.Engine { return p.engine }

// Detectors returns the detector set in use, for reporting.
func (p *Pipeline) Detectors() []core.Detector { return p.detectors }

// Ingest attributes an event, runs every detector over it, and records the
// resulting signals in the risk engine. It returns the signals that fired.
//
// Attribution is applied only when the event arrives unattributed. Events from
// the Suricata path are already attributed during normalization, and re-running
// attribution would be wasted work; more importantly it would risk overwriting
// a correct MAC with an empty lookup result. Letting the pre-attributed value
// stand is what lets both ingest paths flow through the same method.
func (p *Pipeline) Ingest(ev core.NormalizedEvent) []core.Signal {
	if len(ev.DeviceMAC) == 0 && p.attr != nil && ev.Src.IP.IsValid() {
		if mac, ok := p.attr.MACFor(ev.Src.IP); ok {
			ev.DeviceMAC = mac
		}
	}

	var fired []core.Signal
	for _, d := range p.detectors {
		for _, s := range d.Evaluate(ev) {
			p.engine.Observe(s, ev.Time)
			fired = append(fired, s)
		}
	}
	return fired
}

// IngestAll is Ingest over a slice, returning every signal that fired. It
// exists so batch paths (the analyze command) do not reimplement the loop.
func (p *Pipeline) IngestAll(events []core.NormalizedEvent) []core.Signal {
	var fired []core.Signal
	for _, ev := range events {
		fired = append(fired, p.Ingest(ev)...)
	}
	return fired
}
