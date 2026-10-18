package detect

import (
	"testing"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

func TestBeaconDetector_FiresOnNonStandardPort(t *testing.T) {
	d := NewBeaconDetector(0, 0, nil)

	e := baseFlowEvent()
	e.Dst.Port = 8080 // Non-standard port

	got := d.Evaluate(e)
	if len(got) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(got))
	}
	sig := got[0]
	if sig.Kind != core.SignalBeacon {
		t.Errorf("Kind = %q, want %q", sig.Kind, core.SignalBeacon)
	}
	if sig.Class != core.SignalPoCArtifact {
		t.Errorf("Class = %q, want %q", sig.Class, core.SignalPoCArtifact)
	}
	if sig.Reason == "" {
		t.Error("Reason must be non-empty")
	}
}

func TestBeaconDetector_RejectsStandardPorts(t *testing.T) {
	d := NewBeaconDetector(0, 0, nil)

	e := baseFlowEvent()
	e.Dst.Port = 80 // Standard HTTP

	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("standard port 80 should not fire, got %d signals", len(got))
	}

	e.Dst.Port = 443 // Standard HTTPS
	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("standard port 443 should not fire, got %d signals", len(got))
	}
}

func TestBeaconDetector_ZeroPortDoesNotFire(t *testing.T) {
	d := NewBeaconDetector(0, 0, nil)

	e := baseFlowEvent()
	e.Dst.Port = 0

	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("port 0 should not fire, got %d signals", len(got))
	}
}

func TestBeaconDetector_ZeroIntervalWindowUseDefaults(t *testing.T) {
	d := NewBeaconDetector(0, 0, nil)

	if d.interval != DefaultBeaconInterval {
		t.Errorf("interval = %v, want default %v", d.interval, DefaultBeaconInterval)
	}
	if d.window != DefaultBeaconWindow {
		t.Errorf("window = %v, want default %v", d.window, DefaultBeaconWindow)
	}
	if d.ports == nil {
		t.Error("ports should not be nil after constructor")
	}
}

func TestBeaconDetector_CustomPorts(t *testing.T) {
	d := NewBeaconDetector(0, 0, []int{9999})

	e := baseFlowEvent()
	e.Dst.Port = 9999

	if got := d.Evaluate(e); len(got) != 1 {
		t.Errorf("custom port should fire, got %d signals", len(got))
	}

	e.Dst.Port = 8080 // Not in custom list
	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("port not in custom list should not fire, got %d signals", len(got))
	}
}

func TestBeaconDetector_NilPortsUsesDefaults(t *testing.T) {
	d := NewBeaconDetector(0, 0, nil)

	e := baseFlowEvent()
	e.Dst.Port = 8080 // Default non-standard port

	if got := d.Evaluate(e); len(got) != 1 {
		t.Errorf("default non-standard port should fire, got %d signals", len(got))
	}
}

func TestBeaconDetector_RequiresDeviceMAC(t *testing.T) {
	d := NewBeaconDetector(0, 0, nil)

	e := baseFlowEvent()
	e.DeviceMAC = nil
	e.Dst.Port = 8080

	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("unattributable event should not fire, got %d signals", len(got))
	}
}

func TestBeaconDetector_SignalKind(t *testing.T) {
	d := NewBeaconDetector(0, 0, nil)

	if d.Kind() != core.SignalBeacon {
		t.Errorf("Kind = %v, want SignalBeacon", d.Kind())
	}
}

func TestBeaconDetector_SignalClassIsPoCArtifact(t *testing.T) {
	d := NewBeaconDetector(0, 0, nil)

	e := baseFlowEvent()
	e.Dst.Port = 8080

	got := d.Evaluate(e)
	if len(got) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(got))
	}
	if got[0].Class != core.SignalPoCArtifact {
		t.Errorf("Class = %v, want SignalPoCArtifact", got[0].Class)
	}
}

func TestBeaconDetector_SuppressionForWorkstation(t *testing.T) {
	d := NewBeaconDetector(0, 0, nil)

	// Workstations, servers should be suppressed
	if !d.ShouldSuppressDeviceClass(core.ClassWorkstation) {
		t.Error("Workstation should be suppressed")
	}
	if !d.ShouldSuppressDeviceClass(core.ClassServer) {
		t.Error("Server should be suppressed")
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

func TestBeaconDetector_IsPure(t *testing.T) {
	d := NewBeaconDetector(0, 0, nil)

	e := baseFlowEvent()
	e.Dst.Port = 8080

	a := d.Evaluate(e)
	b := d.Evaluate(e)

	if len(a) != len(b) {
		t.Fatalf("non-deterministic: %d then %d signals", len(a), len(b))
	}
	if len(a) > 0 && a[0].Reason != b[0].Reason {
		t.Errorf("non-deterministic reason: %q then %q", a[0].Reason, b[0].Reason)
	}
}

func TestBeaconDetector_NonStandardPortsList(t *testing.T) {
	d := NewBeaconDetector(0, 0, nil)

	// Test some default non-standard ports
	testPorts := []int{8080, 8443, 4444, 5555, 1337, 31337, 4443, 9001, 9002, 1080, 10000}

	for _, port := range testPorts {
		e := baseFlowEvent()
		e.Dst.Port = uint16(port)

		if got := d.Evaluate(e); len(got) != 1 {
			t.Errorf("port %d should fire, got %d signals", port, len(got))
		}
	}

	// Standard ports should not fire
	standardPorts := []int{80, 443, 22, 53, 25, 110, 143, 993, 995}
	for _, port := range standardPorts {
		e := baseFlowEvent()
		e.Dst.Port = uint16(port)

		if got := d.Evaluate(e); len(got) != 0 {
			t.Errorf("standard port %d should not fire, got %d signals", port, len(got))
		}
	}
}

func TestBeaconDetector_IsPureDetector(t *testing.T) {
	d := NewBeaconDetector(0, 0, nil)

	e := baseFlowEvent()
	e.Dst.Port = 8080

	a := d.Evaluate(e)
	b := d.Evaluate(e)

	if len(a) != len(b) {
		t.Fatalf("non-deterministic: %d then %d signals", len(a), len(b))
	}
}
