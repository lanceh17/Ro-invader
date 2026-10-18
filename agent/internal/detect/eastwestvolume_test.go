package detect

import (
	"net/netip"
	"testing"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

func TestEastWestVolumeDetector_FiresOnLargeEastWestFlow(t *testing.T) {
	d := NewEastWestVolumeDetector(nil)

	e := baseFlowEvent()
	e.Src.IP = netip.MustParseAddr("192.168.1.44")
	e.Dst.IP = netip.MustParseAddr("192.168.1.50")
	e.Bytes = 200 << 20 // 200 MiB

	got := d.Evaluate(e)
	if len(got) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(got))
	}
	sig := got[0]
	if sig.Kind != core.SignalEastWestVolume {
		t.Errorf("Kind = %q, want %q", sig.Kind, core.SignalEastWestVolume)
	}
	if sig.Class != core.SignalReplicationRequired {
		t.Errorf("Class = %q, want %q", sig.Class, core.SignalReplicationRequired)
	}
	if sig.Reason == "" {
		t.Error("Reason must be non-empty")
	}
	if sig.DeviceMAC.String() != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("DeviceMAC = %v, want aa:bb:cc:dd:ee:ff", sig.DeviceMAC)
	}
}

func TestEastWestVolumeDetector_RejectsSmallTransfers(t *testing.T) {
	d := NewEastWestVolumeDetector(nil)

	e := baseFlowEvent()
	e.Src.IP = netip.MustParseAddr("192.168.1.44")
	e.Dst.IP = netip.MustParseAddr("192.168.1.50")
	e.Bytes = 50 << 20 // 50 MiB, below 100 MiB threshold

	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("small transfer should not fire, got %d signals", len(got))
	}
}

func TestEastWestVolumeDetector_RejectsInternetTraffic(t *testing.T) {
	d := NewEastWestVolumeDetector(nil)

	e := baseFlowEvent()
	e.Src.IP = netip.MustParseAddr("192.168.1.44")
	e.Dst.IP = netip.MustParseAddr("8.8.8.8") // Internet
	e.Bytes = 200 << 20

	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("internet traffic should not fire, got %d signals", len(got))
	}
}

func TestEastWestVolumeDetector_RejectsMixedTraffic(t *testing.T) {
	d := NewEastWestVolumeDetector(nil)

	e := baseFlowEvent()
	e.Src.IP = netip.MustParseAddr("192.168.1.44") // Private
	e.Dst.IP = netip.MustParseAddr("8.8.8.8")      // Public
	e.Bytes = 200 << 20

	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("mixed private/public should not fire, got %d signals", len(got))
	}
}

func TestEastWestVolumeDetector_RequiresBothPrivate(t *testing.T) {
	d := NewEastWestVolumeDetector(nil)

	// Both public
	e := baseFlowEvent()
	e.Src.IP = netip.MustParseAddr("8.8.8.8")
	e.Dst.IP = netip.MustParseAddr("1.1.1.1")
	e.Bytes = 200 << 20

	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("both public should not fire, got %d signals", len(got))
	}
}

func TestEastWestVolumeDetector_PrivateRanges(t *testing.T) {
	d := NewEastWestVolumeDetector(nil)

	testCases := []struct {
		src, dst string
		wantFire bool
	}{
		{"10.0.0.1", "10.0.0.2", true},
		{"172.16.0.1", "172.16.0.2", true},
		{"172.31.255.255", "172.16.0.1", true},
		{"192.168.1.1", "192.168.1.2", true},
		{"10.0.0.1", "8.8.8.8", false},
		{"8.8.8.8", "192.168.1.1", false},
	}

	for _, tc := range testCases {
		e := baseFlowEvent()
		e.Src.IP = netip.MustParseAddr(tc.src)
		e.Dst.IP = netip.MustParseAddr(tc.dst)
		e.Bytes = 200 << 20

		got := d.Evaluate(e)
		fired := len(got) > 0
		if fired != tc.wantFire {
			t.Errorf("src=%s dst=%s: want fire=%v, got fire=%v", tc.src, tc.dst, tc.wantFire, fired)
		}
	}
}

func TestEastWestVolumeDetector_RejectsNonFlowEvents(t *testing.T) {
	d := NewEastWestVolumeDetector(nil)

	e := baseFlowEvent()
	e.Kind = core.EventTLS
	e.Bytes = 200 << 20

	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("non-flow events should not fire, got %d signals", len(got))
	}
}

func TestEastWestVolumeDetector_RequiresDeviceMAC(t *testing.T) {
	d := NewEastWestVolumeDetector(nil)

	e := baseFlowEvent()
	e.DeviceMAC = nil

	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("unattributable event should not fire, got %d signals", len(got))
	}
}

func TestEastWestVolumeDetector_IsPure(t *testing.T) {
	d := NewEastWestVolumeDetector(nil)

	e := baseFlowEvent()
	e.Src.IP = netip.MustParseAddr("192.168.1.44")
	e.Dst.IP = netip.MustParseAddr("192.168.1.50")
	e.Bytes = 200 << 20

	a := d.Evaluate(e)
	b := d.Evaluate(e)

	if len(a) != len(b) {
		t.Fatalf("non-deterministic: %d then %d signals", len(a), len(b))
	}
	if len(a) > 0 && a[0].Reason != b[0].Reason {
		t.Errorf("non-deterministic reason: %q then %q", a[0].Reason, b[0].Reason)
	}
	if e.Bytes != 200<<20 {
		t.Error("Evaluate mutated the event")
	}
}

func TestEastWestVolumeDetector_CustomPeers(t *testing.T) {
	d := NewEastWestVolumeDetector([]string{"10.0.0.0/8"})

	e := baseFlowEvent()
	e.Src.IP = netip.MustParseAddr("192.168.1.44")
	e.Dst.IP = netip.MustParseAddr("192.168.1.50")
	e.Bytes = 200 << 20

	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("custom peers should restrict, got %d signals", len(got))
	}

	e.Src.IP = netip.MustParseAddr("10.0.0.1")
	e.Dst.IP = netip.MustParseAddr("10.0.0.2")
	if got := d.Evaluate(e); len(got) != 1 {
		t.Errorf("custom peer should fire, got %d", len(got))
	}
}

func TestEastWestVolumeDetector_IsPureDetector(t *testing.T) {
	d := NewEastWestVolumeDetector(nil)

	e := baseFlowEvent()
	e.Src.IP = netip.MustParseAddr("192.168.1.44")
	e.Dst.IP = netip.MustParseAddr("192.168.1.50")
	e.Bytes = 200 << 20

	a := d.Evaluate(e)
	b := d.Evaluate(e)

	if len(a) != len(b) {
		t.Fatalf("non-deterministic: %d then %d signals", len(a), len(b))
	}
	if len(a) > 0 && a[0].Reason != b[0].Reason {
		t.Errorf("non-deterministic reason: %q then %q", a[0].Reason, b[0].Reason)
	}
	if e.Bytes != 200<<20 {
		t.Error("Evaluate mutated the event")
	}
}
