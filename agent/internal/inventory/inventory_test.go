package inventory

import (
	"net"
	"net/netip"
	"testing"
)

func TestParseBareArray(t *testing.T) {
	raw := []byte(`[
		{"mac":"aa:bb:cc:dd:ee:01","ips":["192.168.1.44"],"class":"camera","vendor":"Hikvision"},
		{"mac":"aa:bb:cc:dd:ee:02","ips":["192.168.1.50"],"class":"workstation"}
	]`)

	inv, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if inv.Len() != 2 {
		t.Fatalf("Len = %d, want 2", inv.Len())
	}

	dev, ok := inv.Get(mustMAC(t, "aa:bb:cc:dd:ee:01"))
	if !ok {
		t.Fatal("Get did not find ee:01")
	}
	if dev.Class != "camera" {
		t.Errorf("Class = %q, want camera", dev.Class)
	}
	if dev.Vendor != "Hikvision" {
		t.Errorf("Vendor = %q, want Hikvision", dev.Vendor)
	}
}

func TestParseWrappedObject(t *testing.T) {
	raw := []byte(`{"devices":[{"mac":"aa:bb:cc:dd:ee:01","ips":["192.168.1.44"]}]}`)

	inv, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if inv.Len() != 1 {
		t.Fatalf("Len = %d, want 1", inv.Len())
	}
}

func TestMACForResolvesAndCopies(t *testing.T) {
	raw := []byte(`[{"mac":"aa:bb:cc:dd:ee:01","ips":["192.168.1.44","fe80::1"]}]`)
	inv, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	mac, ok := inv.MACFor(netip.MustParseAddr("192.168.1.44"))
	if !ok {
		t.Fatal("MACFor did not resolve 192.168.1.44")
	}
	if mac.String() != "aa:bb:cc:dd:ee:01" {
		t.Errorf("MACFor = %v", mac)
	}

	// The result must be a copy. A caller mutating it must not corrupt the
	// table, or one stray write reattributes every subsequent event.
	mac[0] = 0xff
	again, _ := inv.MACFor(netip.MustParseAddr("192.168.1.44"))
	if again.String() != "aa:bb:cc:dd:ee:01" {
		t.Error("MACFor returned a reference into the table, not a copy")
	}

	// An unknown address resolves to not-ok rather than a zero MAC, which a
	// caller would mistake for a real identity.
	if _, ok := inv.MACFor(netip.MustParseAddr("10.0.0.99")); ok {
		t.Error("MACFor resolved an unknown address")
	}
}

// TestUnmapKeepsIPv4MappedWorking guards the dual-stack case: an address
// arriving in IPv6 form must still resolve to the IPv4-registered device.
func TestUnmapKeepsIPv4MappedWorking(t *testing.T) {
	raw := []byte(`[{"mac":"aa:bb:cc:dd:ee:01","ips":["192.168.1.44"]}]`)
	inv, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	v4Mapped := netip.MustParseAddr("::ffff:192.168.1.44")
	if _, ok := inv.MACFor(v4Mapped); !ok {
		t.Error("an IPv4-mapped address must resolve to the same device")
	}
}

func TestDefaultClassIsUnknown(t *testing.T) {
	raw := []byte(`[{"mac":"aa:bb:cc:dd:ee:01","ips":["192.168.1.44"]}]`)
	inv, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	dev, _ := inv.Get(mustMAC(t, "aa:bb:cc:dd:ee:01"))
	if dev.Class != "unknown" {
		t.Errorf("Class = %q, want unknown when unset", dev.Class)
	}
}

func TestInvalidMACRejected(t *testing.T) {
	if _, err := Parse([]byte(`[{"mac":"not-a-mac","ips":["192.168.1.44"]}]`)); err == nil {
		t.Error("an invalid MAC must be rejected, not silently accepted")
	}
}

func TestInvalidIPRejected(t *testing.T) {
	if _, err := Parse([]byte(`[{"mac":"aa:bb:cc:dd:ee:01","ips":["999.1.1.1"]}]`)); err == nil {
		t.Error("an invalid IP must be rejected")
	}
}

func TestEmptyInputYieldsEmptyInventory(t *testing.T) {
	inv, err := Parse([]byte("   "))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if inv.Len() != 0 {
		t.Errorf("Len = %d, want 0", inv.Len())
	}
}

// TestDuplicateIPKeepsFirstOwner documents the collision policy: a stale lease
// pointing two MACs at one address must not silently reattribute the device
// mid-flight. First wins.
func TestDuplicateIPKeepsFirstOwner(t *testing.T) {
	raw := []byte(`[
		{"mac":"aa:bb:cc:dd:ee:01","ips":["192.168.1.44"]},
		{"mac":"aa:bb:cc:dd:ee:02","ips":["192.168.1.44"]}
	]`)
	inv, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	mac, _ := inv.MACFor(netip.MustParseAddr("192.168.1.44"))
	if mac.String() != "aa:bb:cc:dd:ee:01" {
		t.Errorf("MACFor = %v, want the first owner ee:01", mac)
	}
}

func mustMAC(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	m, err := net.ParseMAC(s)
	if err != nil {
		t.Fatalf("bad test MAC %q: %v", s, err)
	}
	return m
}
