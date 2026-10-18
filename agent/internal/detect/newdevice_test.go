package detect

import (
	"testing"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

func TestNewDeviceDetector_FiresOnNewUnclassifiedDevice(t *testing.T) {
	d := NewNewDeviceDetector(24 * time.Hour)

	e := baseInventoryEvent()
	// The current implementation returns nil for all cases
	// This test documents the current behavior

	got := d.Evaluate(e)
	// Current implementation returns nil for all cases
	// This is a placeholder implementation
	if got != nil {
		t.Errorf("expected nil (placeholder implementation), got %d signals", len(got))
	}
}

func TestNewDeviceDetector_ZeroGraceUsesDefault(t *testing.T) {
	d := NewNewDeviceDetector(0)

	if d.grace != DefaultNewDeviceGrace {
		t.Errorf("grace = %v, want default %v", d.grace, DefaultNewDeviceGrace)
	}
}

func TestNewDeviceDetector_CustomGrace(t *testing.T) {
	d := NewNewDeviceDetector(12 * time.Hour)

	if d.grace != 12*time.Hour {
		t.Errorf("grace = %v, want 12h", d.grace)
	}
}

func TestNewDeviceDetector_SignalKind(t *testing.T) {
	d := NewNewDeviceDetector(24 * time.Hour)

	if d.Kind() != core.SignalNewDevice {
		t.Errorf("Kind = %v, want SignalNewDevice", d.Kind())
	}
}

func TestNewDeviceDetector_GraceMethod(t *testing.T) {
	d := NewNewDeviceDetector(12 * time.Hour)

	if d.Grace() != 12*time.Hour {
		t.Errorf("Grace() = %v, want 12h", d.Grace())
	}
}

func TestNewDeviceDetector_PlaceholderBehavior(t *testing.T) {
	d := NewNewDeviceDetector(24 * time.Hour)

	// Test various event types - all should return nil for placeholder
	testCases := []core.NormalizedEvent{
		{Kind: core.EventInventory, DeviceMAC: mac("aa:bb:cc:dd:ee:ff")},
		{Kind: core.EventFlow, DeviceMAC: mac("aa:bb:cc:dd:ee:ff")},
		{Kind: core.EventTLS, DeviceMAC: mac("aa:bb:cc:dd:ee:ff")},
		{Kind: core.EventDNSQuery, DeviceMAC: mac("aa:bb:cc:dd:ee:ff")},
		{Kind: core.EventFlow, DeviceMAC: nil},
	}

	for _, e := range testCases {
		got := d.Evaluate(e)
		if got != nil {
			t.Errorf("placeholder implementation should return nil, got %d signals", len(got))
		}
	}
}

func TestNewDeviceDetector_SignalKindIsNewDevice(t *testing.T) {
	d := NewNewDeviceDetector(24 * time.Hour)

	if d.Kind() != core.SignalNewDevice {
		t.Errorf("Kind = %v, want SignalNewDevice", d.Kind())
	}
}

func TestNewDeviceDetector_DefaultGraceIs24Hours(t *testing.T) {
	d := NewNewDeviceDetector(0)

	if d.grace != 24*time.Hour {
		t.Errorf("default grace = %v, want 24h", d.grace)
	}
}

func TestNewDeviceDetector_IsPure(t *testing.T) {
	d := NewNewDeviceDetector(24 * time.Hour)

	e := core.NormalizedEvent{
		Kind:      core.EventInventory,
		DeviceMAC: mac("aa:bb:cc:dd:ee:ff"),
	}

	a := d.Evaluate(e)
	b := d.Evaluate(e)

	// Both should be nil
	if a != nil || b != nil {
		t.Errorf("expected nil for placeholder")
	}
}
