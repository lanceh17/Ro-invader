package main

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
	"github.com/lanceh17/Ro-invader/agent/internal/inventory"
	"github.com/lanceh17/Ro-invader/agent/internal/risk"
)

const testDeviceIP = "192.168.1.50"

func testInventory(t *testing.T) *inventory.Inventory {
	t.Helper()
	inv, err := inventory.Parse([]byte(`[
		{"mac":"aa:bb:cc:dd:ee:01","ips":["192.168.1.50"],"class":"camera"}
	]`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return inv
}

func testMAC(t *testing.T) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC("aa:bb:cc:dd:ee:01")
	if err != nil {
		t.Fatalf("ParseMAC: %v", err)
	}
	return mac
}

func mkSignal(kind core.SignalKind, cls core.SignalClass, w, c float64) core.Signal {
	return core.Signal{Kind: kind, Class: cls, Weight: w, Confidence: c}
}

// TestQuarantineFuncUnknownIPIsNotContained: a source the inventory does not
// know cannot be assessed, so it must never be contained. Containing an
// unknown device would be acting on a guess.
func TestQuarantineFuncUnknownIPIsNotContained(t *testing.T) {
	inv := testInventory(t)
	qf := quarantineFunc(inv, risk.New())
	if qf(netip.MustParseAddr("192.168.1.99")) {
		t.Error("an unknown IP was contained")
	}
}

func TestQuarantineFuncNilInputsAreNotContained(t *testing.T) {
	inv := testInventory(t)
	qf := quarantineFunc(nil, risk.New())
	if qf(netip.MustParseAddr(testDeviceIP)) {
		t.Error("nil inventory must not contain")
	}
	qf = quarantineFunc(inv, nil)
	if qf(netip.MustParseAddr(testDeviceIP)) {
		t.Error("nil engine must not contain")
	}
}

// TestQuarantineFuncContainsCorroboratedDevice is the positive case: a device
// past the quarantine threshold with corroboration is contained.
func TestQuarantineFuncContainsCorroboratedDevice(t *testing.T) {
	inv := testInventory(t)
	mac := testMAC(t)
	eng := risk.New()
	now := time.Now()

	// Two distinct kinds, enough weight for a camera (class 1.5) to clear the
	// quarantine threshold of 60.
	for i := 0; i < 3; i++ {
		eng.Observe(withMAC(mkSignal(core.SignalModelHostOnIoT, core.SignalReplicationRequired, 20, 0.6), mac), now)
		eng.Observe(withMAC(mkSignal(core.SignalDNSDrift, core.SignalReplicationRequired, 25, 0.5), mac), now)
	}

	// Sanity: the fixture must actually be quarantined, or the test would
	// pass vacuously if quarantineFunc always returned false.
	dev, _ := inv.Get(mac)
	if tier := eng.Evaluate(dev, now).Tier; tier != core.ContainmentQuarantined {
		t.Fatalf("fixture device tier = %v, want quarantined", tier)
	}

	qf := quarantineFunc(inv, eng)
	if !qf(netip.MustParseAddr(testDeviceIP)) {
		t.Error("a corroborated, over-threshold device was not contained")
	}
}

// TestQuarantineFuncSingleKindNeverContains is the central safety property:
// one signal kind, however large the score, never reaches an action. This is
// what stops a single false positive from sinkholing a device.
func TestQuarantineFuncSingleKindNeverContains(t *testing.T) {
	inv := testInventory(t)
	mac := testMAC(t)
	eng := risk.New()
	now := time.Now()

	// A single kind, repeated until the score is far past 60.
	for i := 0; i < 20; i++ {
		eng.Observe(withMAC(mkSignal(core.SignalModelHostOnIoT, core.SignalReplicationRequired, 20, 0.6), mac), now)
	}

	dev, _ := inv.Get(mac)
	a := eng.Evaluate(dev, now)
	if a.Score <= risk.DefaultConfig().QuarantineThreshold {
		t.Fatalf("fixture score = %v, want above the quarantine threshold", a.Score)
	}
	if a.DistinctKinds != 1 {
		t.Fatalf("DistinctKinds = %d, want 1", a.DistinctKinds)
	}

	qf := quarantineFunc(inv, eng)
	if qf(netip.MustParseAddr(testDeviceIP)) {
		t.Error("a single signal kind was contained despite a high score; corroboration must gate containment")
	}
}

func withMAC(s core.Signal, mac net.HardwareAddr) core.Signal {
	s.DeviceMAC = mac
	return s
}
