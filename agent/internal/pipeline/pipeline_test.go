package pipeline

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
	"github.com/lanceh17/Ro-invader/agent/internal/detect"
	"github.com/lanceh17/Ro-invader/agent/internal/risk"
)

var (
	srcIP   = netip.MustParseAddr("192.168.1.77")
	srcMAC  = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x77}
	testMap = MapAttributor{srcIP: srcMAC}
)

// event is an unattributed DNS query from srcIP, as the resolver produces it.
func event(name string, at time.Time) core.NormalizedEvent {
	return core.NormalizedEvent{
		Time:      at,
		Kind:      core.EventDNSQuery,
		Src:       core.Endpoint{IP: srcIP},
		QueryName: name,
	}
}

func TestIngestAttributesAndFires(t *testing.T) {
	p := New(testMap, nil, detect.NewModelHostDetector(nil))

	now := time.Now()
	fired := p.Ingest(event("cdn-lfs.huggingface.co", now))
	if len(fired) != 1 {
		t.Fatalf("fired %d signals, want 1", len(fired))
	}
	if fired[0].DeviceMAC.String() != srcMAC.String() {
		t.Errorf("signal attributed to %v, want %v", fired[0].DeviceMAC, srcMAC)
	}
	// The signal must reach the engine, not merely be returned.
	dev := core.Device{MAC: srcMAC, Class: core.ClassCamera}
	if a := p.Engine().Evaluate(dev, now); a.Score <= 0 {
		t.Errorf("engine score = %v after ingest; the signal did not reach it", a.Score)
	}
}

func TestIngestUnknownSourceYieldsNoSignal(t *testing.T) {
	// An IP the inventory does not know cannot be attributed, so no detector
	// can name a device, so nothing fires. This is the honest consequence of
	// a missing inventory rather than an error to swallow.
	p := New(testMap, nil, detect.NewModelHostDetector(nil))
	ev := event("cdn-lfs.huggingface.co", time.Now())
	ev.Src.IP = netip.MustParseAddr("192.168.1.200")

	if fired := p.Ingest(ev); len(fired) != 0 {
		t.Errorf("an unattributable event fired %d signals; want 0", len(fired))
	}
}

func TestIngestPreservesExistingAttribution(t *testing.T) {
	// Suricata events arrive already attributed. Re-attributing could only
	// overwrite a correct MAC with an empty lookup, so the existing value must
	// stand. The map deliberately lacks srcIP to prove the MAC is not recomputed.
	otherMAC := net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	p := New(testMap, nil, detect.NewModelHostDetector(nil))

	ev := event("cdn-lfs.huggingface.co", time.Now())
	ev.DeviceMAC = otherMAC

	fired := p.Ingest(ev)
	if len(fired) != 1 {
		t.Fatalf("fired %d signals, want 1", len(fired))
	}
	if fired[0].DeviceMAC.String() != otherMAC.String() {
		t.Errorf("pre-attributed MAC was overwritten to %v, want %v", fired[0].DeviceMAC, otherMAC)
	}
}

func TestIngestNilAttributorYieldsNothing(t *testing.T) {
	p := New(nil, nil, detect.NewModelHostDetector(nil))
	if fired := p.Ingest(event("cdn-lfs.huggingface.co", time.Now())); len(fired) != 0 {
		t.Errorf("nil attributor fired %d signals; want 0", len(fired))
	}
}

func TestNewDefaultsEngineAndDetectors(t *testing.T) {
	// A bare New must be usable: default engine, default detector set.
	p := New(testMap, nil)
	if p.Engine() == nil {
		t.Fatal("New gave a nil engine")
	}
	if len(p.Detectors()) == 0 {
		t.Fatal("New gave no detectors; a pipeline with no detectors observes nothing")
	}
	if fired := p.Ingest(event("cdn-lfs.huggingface.co", time.Now())); len(fired) == 0 {
		t.Error("the default set did not fire on a model-host query")
	}
}

// TestIngestDrivesTheRiskEngineEndToEnd is the whole point of this package: a
// DNS query from the resolver, attributed and scored, producing a device
// assessment — the sensing-to-decision path with no Suricata involved.
func TestIngestDrivesTheRiskEngineEndToEnd(t *testing.T) {
	now := time.Now()
	// A low baseline so a single first contact suffices to exercise R7.
	p := New(testMap, risk.New(), detect.NewDNSDriftDetector(1, nil))

	// Prime the detector's baseline for this device, then make first contact.
	p.Ingest(event("ordinary.example", now))
	fired := p.Ingest(event("cdn-lfs.huggingface.co", now))
	if len(fired) != 1 {
		t.Fatalf("R7 did not fire; got %d signals", len(fired))
	}
	if fired[0].Kind != core.SignalDNSDrift {
		t.Errorf("Kind = %v, want SignalDNSDrift", fired[0].Kind)
	}

	dev := core.Device{MAC: srcMAC, Class: core.ClassCamera}
	a := p.Engine().Evaluate(dev, now)
	if a.Score <= 0 {
		t.Fatalf("assessment score = %v, want > 0", a.Score)
	}
	if a.DistinctKinds != 1 {
		t.Errorf("DistinctKinds = %d, want 1", a.DistinctKinds)
	}
	// R7 alone must never escalate, per DETECTION.md's corroboration table.
	if a.Tier != core.ContainmentMonitor {
		t.Errorf("Tier = %v, want monitor; R7 alone must not act", a.Tier)
	}
}

func TestIngestAllBatches(t *testing.T) {
	p := New(testMap, nil, detect.NewModelHostDetector(nil))
	now := time.Now()
	events := []core.NormalizedEvent{
		event("cdn-lfs.huggingface.co", now),
		event("registry.ollama.ai", now),
		event("ordinary.example", now),
	}
	fired := p.IngestAll(events)
	if len(fired) != 2 {
		t.Errorf("IngestAll fired %d signals, want 2 (third is ordinary)", len(fired))
	}
}
