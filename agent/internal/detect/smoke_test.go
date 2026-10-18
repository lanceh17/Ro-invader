package detect

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
	"github.com/lanceh17/Ro-invader/agent/internal/ingest/suricata"
	"github.com/lanceh17/Ro-invader/agent/internal/inventory"
)

// TestSmokeTestDetectorsOnFixtures verifies that the default detector set fires
// signals when given sample EVE events from the fixture corpus.
// This exercises the detector logic directly with fixture data.
func TestSmokeTestDetectorsOnFixtures(t *testing.T) {
	// Resolve fixtures path relative to the project root
	projectRoot := filepath.Join("..", "..", "..")
	invPath := filepath.Join(projectRoot, "tests", "fixtures", "inventory.json")
	sampleJSONPath := filepath.Join(projectRoot, "tests", "fixtures", "eve", "sample.json")

	// Load the sample inventory for device attribution
	inv, err := inventory.Load(invPath)
	if err != nil {
		t.Fatalf("failed to load inventory from %s: %v", invPath, err)
	}

	// Read the sample EVE events
	sampleJSON, err := os.ReadFile(sampleJSONPath)
	if err != nil {
		t.Fatalf("failed to read EVE events from %s: %v", sampleJSONPath, err)
	}

	// Build an attributor MapAttributor from the inventory
	attr := suricata.MapAttributor{
		netip.MustParseAddr("192.168.1.44"): invMACFor2Values(inv, "192.168.1.44"),
		netip.MustParseAddr("192.168.1.50"): invMACFor2Values(inv, "192.168.1.50"),
		netip.MustParseAddr("192.168.1.60"): invMACFor2Values(inv, "192.168.1.60"),
	}

	// Use the suricata reader to parse the events
	events, err := suricata.ReadAll(strings.NewReader(string(sampleJSON)), attr)
	if err != nil {
		t.Fatalf("failed to read EVE events: %v", err)
	}

	t.Logf("Events normalized: %d", len(events))

	// Run all detectors on all events
	fired := EvalAll(events)

	t.Logf("Signals fired: %d from %d detectors", len(fired), len(All()))

	// Verify that at least some signals fired (smoke test)
	if len(fired) == 0 {
		t.Fatal("expected at least one signal to fire, but none fired")
	}

	// Show what signals fired and from which detectors
	signalKinds := make(map[core.SignalKind]int)
	for _, s := range fired {
		signalKinds[s.Kind]++
	}
	t.Logf("Signal kind counts: %v", signalKinds)

	// Verify we have signals from at least 1 detector kind
	kinds := make(map[core.SignalKind]bool)
	for _, s := range fired {
		kinds[s.Kind] = true
	}
	t.Logf("Signal kinds fired: %v", kinds)

	// Verify specific expected signals based on the fixture content:
	// - model-host contact (huggingface.co, ollama.ai)
	foundModelHost := false
	for _, s := range fired {
		if s.Kind == core.SignalModelHostOnIoT {
			foundModelHost = true
		}
	}

	if !foundModelHost {
		t.Error("expected SignalModelHostOnIoT to fire (model-host contact in fixtures)")
	}

	// Show all signal details
	t.Logf("All fired signals:")
	for i, s := range fired {
		t.Logf("  Signal %d: Kind=%s Reason=%s Device=%s", i+1, s.Kind, s.Reason[:40], s.DeviceMAC)
	}

	// Verify the model-host signals are attributed to known devices
	for _, s := range fired {
		if s.Kind == core.SignalModelHostOnIoT {
			// Verify the signal is attributed to a known device (not empty MAC)
			if len(s.DeviceMAC) == 0 {
				t.Error("expected DeviceMAC to be set for model-host signal")
			} else {
				t.Logf("Signal %s attributed to device %s", s.Kind, s.DeviceMAC)
			}
		}
	}
}

// invMACFor2Values calls inv.MACFor and returns the MAC address (first return value).
// MACFor returns (mac HardwareAddr, ok bool), we just need the mac.
func invMACFor2Values(inv *inventory.Inventory, ip string) net.HardwareAddr {
	mac, _ := inv.MACFor(netip.MustParseAddr(ip))
	return mac
}
