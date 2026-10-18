package detect

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

func TestBurstDetector_FiresOnHighPacketCount(t *testing.T) {
	d := NewBurstDetector(20, 30*time.Second)

	e := baseFlowEvent()
	// Bytes / 1000 = packets estimate
	// 200 MiB / 1000 = ~200,000 packets >> 20 threshold
	e.Bytes = 200 << 20

	got := d.Evaluate(e)
	if len(got) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(got))
	}
	sig := got[0]
	if sig.Kind != core.SignalBurst {
		t.Errorf("Kind = %q, want %q", sig.Kind, core.SignalBurst)
	}
	if sig.Class != core.SignalPoCArtifact {
		t.Errorf("Class = %q, want %q", sig.Class, core.SignalPoCArtifact)
	}
	if sig.Reason == "" {
		t.Error("Reason must be non-empty")
	}
}

func TestBurstDetector_RejectsLowPacketCount(t *testing.T) {
	d := NewBurstDetector(20, 30*time.Second)

	e := baseFlowEvent()
	// Small transfer = low packet count
	e.Bytes = 1000 // ~1 packet

	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("low packet count should not fire, got %d signals", len(got))
	}
}

func TestBurstDetector_RequiresFlowEvent(t *testing.T) {
	d := NewBurstDetector(20, 30*time.Second)

	e := core.NormalizedEvent{
		Kind:      core.EventTLS,
		DeviceMAC: mac("aa:bb:cc:dd:ee:ff"),
		Bytes:     200 << 20,
		Duration:  10 * time.Second,
	}

	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("non-flow events should not fire, got %d signals", len(got))
	}
}

func TestBurstDetector_RequiresDeviceMAC(t *testing.T) {
	d := NewBurstDetector(20, 30*time.Second)

	e := core.NormalizedEvent{
		Kind:      core.EventFlow,
		Bytes:     200 << 20,
		Duration:  10 * time.Second,
		DeviceMAC: nil,
	}

	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("unattributable event should not fire, got %d signals", len(got))
	}
}

func TestBurstDetector_ZeroThresholdUsesDefault(t *testing.T) {
	d := NewBurstDetector(0, 0)

	if d.threshold != 20 {
		t.Errorf("threshold = %d, want 20 (default)", d.threshold)
	}
	if d.window != 30*time.Second {
		t.Errorf("window = %v, want 30s (default)", d.window)
	}
}

func TestBurstDetector_CustomThresholdAndWindow(t *testing.T) {
	d := NewBurstDetector(10, 10*time.Second)

	if d.threshold != 10 {
		t.Errorf("threshold = %d, want 10", d.threshold)
	}
	if d.window != 10*time.Second {
		t.Errorf("window = %v, want 10s", d.window)
	}
}

func TestBurstDetector_SignalKind(t *testing.T) {
	d := NewBurstDetector(20, 30*time.Second)

	if d.Kind() != core.SignalBurst {
		t.Errorf("Kind = %v, want SignalBurst", d.Kind())
	}
}

func TestBurstDetector_SignalClassIsPoCArtifact(t *testing.T) {
	d := NewBurstDetector(20, 30*time.Second)

	e := core.NormalizedEvent{
		Kind:      core.EventFlow,
		DeviceMAC: mac("aa:bb:cc:dd:ee:ff"),
		Bytes:     200 << 20,
		Duration:  10 * time.Second,
		Dst: core.Endpoint{
			IP:   netip.MustParseAddr("192.168.1.50"),
			Port: 8080,
		},
	}

	got := d.Evaluate(e)
	if len(got) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(got))
	}
	if got[0].Class != core.SignalPoCArtifact {
		t.Errorf("Class = %v, want SignalPoCArtifact", got[0].Class)
	}
}

func TestBurstDetector_IsPure(t *testing.T) {
	d := NewBurstDetector(20, 30*time.Second)

	e := core.NormalizedEvent{
		Kind:      core.EventFlow,
		DeviceMAC: mac("aa:bb:cc:dd:ee:ff"),
		Src:       core.Endpoint{IP: netip.MustParseAddr("192.168.1.44"), Port: 49152},
		Dst:       core.Endpoint{IP: netip.MustParseAddr("192.168.1.50"), Port: 8080},
		Bytes:     200 << 20,
		Duration:  10 * time.Second,
	}

	a := d.Evaluate(e)
	b := d.Evaluate(e)

	if len(a) != len(b) {
		t.Fatalf("non-deterministic: %d then %d signals", len(a), len(b))
	}
}

func TestBurstDetector_SuppressionForWorkstation(t *testing.T) {
	d := NewBurstDetector(20, 30*time.Second)

	// Workstations, servers, mobile should be suppressed
	if !d.ShouldSuppressDeviceClass(core.ClassWorkstation) {
		t.Error("Workstation should be suppressed")
	}
	if !d.ShouldSuppressDeviceClass(core.ClassServer) {
		t.Error("Server should be suppressed")
	}
	if !d.ShouldSuppressDeviceClass(core.ClassMobile) {
		t.Error("Mobile should be suppressed")
	}

	// IoT, camera, appliance should NOT be suppressed
	if d.ShouldSuppressDeviceClass(core.ClassIoT) {
		t.Error("IoT should not be suppressed")
	}
	if d.ShouldSuppressDeviceClass(core.ClassCamera) {
		t.Error("Camera should not be suppressed")
	}
	if d.ShouldSuppressDeviceClass(core.ClassAppliance) {
		t.Error("Appliance should not be suppressed")
	}
}

func TestBurstDetector_SignalClassIsPoCArtifactInSignal(t *testing.T) {
	d := NewBurstDetector(20, 30*time.Second)

	e := core.NormalizedEvent{
		Kind:      core.EventFlow,
		DeviceMAC: mac("aa:bb:cc:dd:ee:ff"),
		Bytes:     200 << 20,
		Duration:  10 * time.Second,
		Dst: core.Endpoint{
			IP:   netip.MustParseAddr("192.168.1.50"),
			Port: 8080,
		},
	}

	got := d.Evaluate(e)
	if len(got) == 0 {
		t.Fatal("expected signal to fire for test")
	}
	if got[0].Class != core.SignalPoCArtifact {
		t.Errorf("signal class = %v, want SignalPoCArtifact", got[0].Class)
	}
}
