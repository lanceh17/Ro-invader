package router

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
	"github.com/lanceh17/Ro-invader/agent/internal/ingest/suricata"
)

// staticSource is a Source that returns a fixed lease list, optionally
// failing.
//
// It stands in for a router so the Client's merge, retention and attribution
// logic can be tested with no vendor wire format in the way. Testing those
// rules through a real vendor mock would make every change to a VyOS table's
// column count look like a regression in the Client, and vice versa.
type staticSource struct {
	name   string
	leases []Lease
	err    error
	// errAfter serves leases for the first errAfter calls and fails every
	// call after that, which is how "the router went away" is modelled
	// without a second mock.
	errAfter int
	calls    int
}

func (s *staticSource) Name() string { return s.name }

func (s *staticSource) Leases(context.Context) ([]Lease, error) {
	s.calls++
	if s.errAfter > 0 {
		if s.calls > s.errAfter {
			return nil, s.err
		}
		return s.leases, nil
	}
	if s.err != nil {
		return nil, s.err
	}
	return s.leases, nil
}

func mustMAC(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	mac, ok := NormalizeMAC(s)
	if !ok {
		t.Fatalf("NormalizeMAC(%q) failed", s)
	}
	return mac
}

func newTestClient(t *testing.T, sources ...Source) *Client {
	t.Helper()
	c, err := New(Config{BaseURL: "http://192.168.1.1", Sources: sources})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// TestNormalizeMAC covers the three spellings routers publish. The whole
// table is keyed on one canonical form, so a spelling that normalizes
// differently does not merely look untidy — it turns one device into two
// entries and splits its own traffic across two identities.
func TestNormalizeMAC(t *testing.T) {
	tests := []struct {
		name string
		in   string
		ok   bool
	}{
		{"colon form", "aa:bb:cc:dd:ee:ff", true},
		{"uppercase colon form", "AA:BB:CC:DD:EE:FF", true},
		{"dash form", "AA-BB-CC-DD-EE-FF", true},
		{"bare hex, OpenWrt's spelling", "aabbccddeeff", true},
		{"uppercase bare hex", "AABBCCDDEEFF", true},
		{"surrounding whitespace", "  aa:bb:cc:dd:ee:ff \n", true},
		{"empty", "", false},
		{"not hex", "zz:bb:cc:dd:ee:ff", false},
		{"short bare hex", "aabbccddee", false},
		{"long bare hex", "aabbccddeeff11", false},
		{"truncated colon form", "aa:bb:cc:dd:ee", false},
		{"EUI-64 is refused, not truncated", "aa:bb:cc:dd:ee:ff:00:11", false},
		{"prose", "the device with no mac", false},
	}
	want := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := NormalizeMAC(tt.in)
			if ok != tt.ok {
				t.Fatalf("NormalizeMAC(%q) ok = %v, want %v", tt.in, ok, tt.ok)
			}
			if !ok {
				return
			}
			if got.String() != want.String() {
				t.Errorf("NormalizeMAC(%q) = %s, want %s", tt.in, got, want)
			}
		})
	}
}

// TestNewLeaseRejectsUnusableRows pins the per-row contract every vendor
// parser depends on: one bad row is skipped, never fatal. If this returned
// an error instead of a false, a single torn line in a dnsmasq lease file
// would take the whole network's inventory with it.
func TestNewLeaseRejectsUnusableRows(t *testing.T) {
	if _, ok := newLease("not-a-mac", "192.168.1.5", ""); ok {
		t.Error("newLease accepted an unparseable MAC")
	}
	if _, ok := newLease("aabbccddeeff", "not-an-ip", ""); ok {
		t.Error("newLease accepted an unparseable address")
	}
	if _, ok := newLease("", "192.168.1.5", ""); ok {
		t.Error("newLease accepted a row with no MAC at all")
	}

	l, ok := newLease("aabbccddeeff", "192.168.1.5", "*")
	if !ok {
		t.Fatal("newLease rejected a valid row")
	}
	// dnsmasq writes "*" where a device announced no hostname. Carrying it
	// through would put a literal asterisk in front of the operator.
	if l.Hostname != "" {
		t.Errorf("Hostname = %q, want empty for the %q placeholder", l.Hostname, "*")
	}
	if l.MAC.String() != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("MAC = %s, want aa:bb:cc:dd:ee:ff", l.MAC)
	}
}

func TestNewRequiresBaseURL(t *testing.T) {
	_, err := New(Config{})
	if err == nil {
		t.Fatal("New must reject an empty BaseURL")
	}
	if !strings.Contains(err.Error(), "BaseURL") {
		t.Errorf("error %q does not name the BaseURL field", err)
	}
}

// TestNewDefaultsToOpenWrtSource guards the convenience path: a deployment
// with one router on stock OpenWrt should configure BaseURL, Username and
// Password and nothing else. Without the default there is a second way to
// spell "no sources", and it is the way that silently polls nothing.
func TestNewDefaultsToOpenWrtSource(t *testing.T) {
	c, err := New(Config{BaseURL: "http://192.168.1.1/", Username: "root", Password: "pw"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(c.sources) != 1 {
		t.Fatalf("got %d sources, want the OpenWrt default", len(c.sources))
	}
	if c.sources[0].Name() != "openwrt" {
		t.Errorf("default source = %q, want openwrt", c.sources[0].Name())
	}

	src := c.sources[0].(*openWrtSource)
	if src.rpc.base != "http://192.168.1.1" {
		t.Errorf("base = %q, want the trailing slash stripped", src.rpc.base)
	}
	// The transport must be filled in even though none was supplied, or the
	// first poll panics on a nil Doer.
	if src.cfg.Transport == nil {
		t.Error("New did not install a default transport")
	}
}

// TestNewWithoutSourcesOrUsernameFails covers the ambiguous configuration:
// no sources and no credentials to build the default from. It must be an
// error rather than a Client that polls nothing and reports success.
func TestNewWithoutSourcesOrUsernameFails(t *testing.T) {
	_, err := New(Config{BaseURL: "http://192.168.1.1"})
	if err == nil {
		t.Fatal("New must reject a config with neither Sources nor Username")
	}
	if !strings.Contains(err.Error(), "Username") {
		t.Errorf("error %q does not name the Username field", err)
	}
}

func TestVendorConstructorsNameTheMissingCredential(t *testing.T) {
	base := Config{BaseURL: "http://fw.example"}

	if _, err := NewVyOS(base); err == nil || !strings.Contains(err.Error(), vyosAPIKeyEnv) {
		t.Errorf("NewVyOS error = %v, want it to name %s", err, vyosAPIKeyEnv)
	}
	if _, err := NewOPNsense(base); err == nil || !strings.Contains(err.Error(), opnSenseKeyEnv) {
		t.Errorf("NewOPNsense error = %v, want it to name %s", err, opnSenseKeyEnv)
	}

	withKey := base
	withKey.Token = "key"
	if _, err := NewOPNsense(withKey); err == nil || !strings.Contains(err.Error(), opnSenseSecretEnv) {
		t.Errorf("NewOPNsense error = %v, want it to name %s", err, opnSenseSecretEnv)
	}

	if _, err := NewVyOS(Config{BaseURL: "http://fw.example", Token: "k"}); err != nil {
		t.Errorf("NewVyOS with a key: %v", err)
	}
	if _, err := NewOPNsense(Config{BaseURL: "http://fw.example", Token: "k", Password: "s"}); err != nil {
		t.Errorf("NewOPNsense with a key and secret: %v", err)
	}
}

// TestPollAccumulatesAcrossSources is the reason the Client exists as a
// separate layer: a single MAC holding an IPv4 lease and an IPv6 lease must
// come back as one device with two addresses, not as two devices.
func TestPollAccumulatesAcrossSources(t *testing.T) {
	v4 := staticSource{name: "v4", leases: []Lease{
		{MAC: mustMAC(t, "aa:bb:cc:dd:ee:01"), IP: netip.MustParseAddr("192.168.1.30"), Hostname: "nas"},
	}}
	v6 := staticSource{name: "v6", leases: []Lease{
		{MAC: mustMAC(t, "AA-BB-CC-DD-EE-01"), IP: netip.MustParseAddr("fd00::30"), Hostname: "nas"},
	}}
	c := newTestClient(t, &v4, &v6)

	if err := c.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	if c.Len() != 1 {
		t.Fatalf("Len = %d, want 1: the dash and colon spellings are the same device", c.Len())
	}
	devs := c.Devices()
	if len(devs) != 1 {
		t.Fatalf("Devices() = %d entries, want 1", len(devs))
	}
	if len(devs[0].IPs) != 2 {
		t.Errorf("device holds %d addresses, want both leases", len(devs[0].IPs))
	}
	if devs[0].Class != core.ClassUnknown {
		t.Errorf("Class = %q, want unknown: a router knows addresses, not people", devs[0].Class)
	}
	if devs[0].FirstSeen.IsZero() || devs[0].LastSeen.IsZero() {
		t.Error("device carries no observation timestamps")
	}
	if len(devs[0].Notes) != 1 || devs[0].Notes[0] != "hostname: nas" {
		t.Errorf("Notes = %v, want the announced hostname recorded once", devs[0].Notes)
	}
}

// TestPollDropsDuplicateBindings covers a lease reported by two sources for
// the same address — normal when a DHCP lease and an ARP entry describe the
// same host. Two entries would double-count the device in every report.
func TestPollDropsDuplicateBindings(t *testing.T) {
	l := Lease{MAC: mustMAC(t, "aa:bb:cc:dd:ee:02"), IP: netip.MustParseAddr("192.168.1.31")}
	c := newTestClient(t, &staticSource{name: "a", leases: []Lease{l}}, &staticSource{name: "b", leases: []Lease{l}})

	if err := c.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if c.Len() != 1 {
		t.Errorf("Len = %d, want 1", c.Len())
	}
	if len(c.Devices()[0].IPs) != 1 {
		t.Errorf("device holds %d addresses, want 1", len(c.Devices()[0].IPs))
	}
}

// TestPollKeepsLeasesWhenASourceFails is the retention rule, and it is the
// most consequential behaviour in the package. Deleting on absence would mean
// one router reboot empties the device table, and every detector downstream
// treats an unattributable event as nothing to see — so the failure would be
// silent and would look exactly like a quiet network.
func TestPollKeepsLeasesWhenASourceFails(t *testing.T) {
	failing := staticSource{
		name:     "flaky",
		leases:   []Lease{{MAC: mustMAC(t, "aa:bb:cc:dd:ee:03"), IP: netip.MustParseAddr("192.168.1.40")}},
		err:      errors.New("connection refused"),
		errAfter: 1,
	}
	steady := staticSource{name: "steady", leases: []Lease{
		{MAC: mustMAC(t, "aa:bb:cc:dd:ee:04"), IP: netip.MustParseAddr("192.168.1.41")},
	}}
	c := newTestClient(t, &failing, &steady)
	ctx := context.Background()

	if err := c.Poll(ctx); err != nil {
		t.Fatalf("first Poll: %v", err)
	}
	if c.Len() != 2 {
		t.Fatalf("after first poll Len = %d, want 2", c.Len())
	}

	// The flaky router is now down. Poll must report the failure — silence
	// would hide an outage — without discarding anything already learned.
	err := c.Poll(ctx)
	if err == nil {
		t.Fatal("Poll must report the failing source")
	}
	if !strings.Contains(err.Error(), "flaky") {
		t.Errorf("error %q does not name the source that failed", err)
	}

	if c.Len() != 2 {
		t.Errorf("Len = %d after a source failure, want the 2 devices retained", c.Len())
	}
	if _, ok := c.MACFor(netip.MustParseAddr("192.168.1.40")); !ok {
		t.Error("a lease from the failed source was erased; attribution is now blind for that device")
	}
	// The healthy source still contributes.
	if _, ok := c.MACFor(netip.MustParseAddr("192.168.1.41")); !ok {
		t.Error("the healthy source's lease is missing")
	}
}

// TestPollMovesBindingWhenAnAddressIsReassigned covers the DHCP lease moving
// between devices, which is the normal case that the opposite rule would
// break: holding the older binding would attribute the new device's traffic
// to the old one forever, and misattribution here means quarantining the
// wrong device.
func TestPollMovesBindingWhenAnAddressIsReassigned(t *testing.T) {
	src := staticSource{name: "router", leases: []Lease{
		{MAC: mustMAC(t, "aa:bb:cc:dd:ee:05"), IP: netip.MustParseAddr("192.168.1.50")},
	}}
	c := newTestClient(t, &src)

	if err := c.Poll(context.Background()); err != nil {
		t.Fatalf("first Poll: %v", err)
	}

	src.leases = []Lease{{MAC: mustMAC(t, "aa:bb:cc:dd:ee:06"), IP: netip.MustParseAddr("192.168.1.50")}}
	if err := c.Poll(context.Background()); err != nil {
		t.Fatalf("second Poll: %v", err)
	}

	mac, ok := c.MACFor(netip.MustParseAddr("192.168.1.50"))
	if !ok {
		t.Fatal("address became unresolvable after the lease moved")
	}
	if mac.String() != "aa:bb:cc:dd:ee:06" {
		t.Errorf("MACFor = %s, want the new leaseholder aa:bb:cc:dd:ee:06", mac)
	}
}

func TestMACForResolvesAndCopies(t *testing.T) {
	c := newTestClient(t, &staticSource{name: "router", leases: []Lease{
		{MAC: mustMAC(t, "aa:bb:cc:dd:ee:07"), IP: netip.MustParseAddr("192.168.1.60")},
	}})
	if err := c.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	mac, ok := c.MACFor(netip.MustParseAddr("192.168.1.60"))
	if !ok {
		t.Fatal("MACFor did not resolve a known address")
	}

	// The returned slice must be a copy. The table is rebuilt on every poll,
	// so a caller that sorted or truncated the slice it was handed would
	// corrupt attribution for every other event already in flight.
	mac[0] = 0xff
	again, _ := c.MACFor(netip.MustParseAddr("192.168.1.60"))
	if again.String() != "aa:bb:cc:dd:ee:07" {
		t.Errorf("MACFor returned the live table: caller mutation leaked in (%s)", again)
	}

	// An IPv4-mapped IPv6 spelling of the same address must resolve, because
	// that is how it can arrive from a parser.
	if _, ok := c.MACFor(netip.MustParseAddr("::ffff:192.168.1.60")); !ok {
		t.Error("MACFor did not normalize an IPv4-mapped address")
	}
}

func TestMACForUnknownAddressIsFalse(t *testing.T) {
	c := newTestClient(t, &staticSource{name: "router"})
	if _, ok := c.MACFor(netip.MustParseAddr("192.168.1.99")); ok {
		t.Error("MACFor resolved an address no router has reported")
	}
}

// TestClientSatisfiesSuricataAttributor makes the package's purpose a test
// rather than a claim: the ingest layer must accept this Client wherever it
// accepts any other attributor, or the whole live-inventory design is
// decorative.
func TestClientSatisfiesSuricataAttributor(t *testing.T) {
	c := newTestClient(t, &staticSource{name: "router", leases: []Lease{
		{MAC: mustMAC(t, "aa:bb:cc:dd:ee:08"), IP: netip.MustParseAddr("192.168.1.70")},
	}})
	if err := c.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	var attr suricata.Attributor = c
	mac, ok := attr.MACFor(netip.MustParseAddr("192.168.1.70"))
	if !ok || mac.String() != "aa:bb:cc:dd:ee:08" {
		t.Errorf("Attributor lookup = (%s, %v), want the lease MAC", mac, ok)
	}
}

// TestPollConcurrentWithMACFor exercises the lock. The ingest loop calls
// MACFor from the hot path for every event while the poll loop rebuilds the
// table behind it, so without a real lock this is a data race and, with
// luck, a concurrent map read/write that takes the whole process down. Run
// under -race, this is the test that would catch it.
func TestPollConcurrentWithMACFor(t *testing.T) {
	leases := []Lease{
		{MAC: mustMAC(t, "aa:bb:cc:dd:ee:09"), IP: netip.MustParseAddr("192.168.1.80")},
		{MAC: mustMAC(t, "aa:bb:cc:dd:ee:0a"), IP: netip.MustParseAddr("192.168.1.81")},
	}
	c := newTestClient(t, &staticSource{name: "router", leases: leases})
	addr := netip.MustParseAddr("192.168.1.80")

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				c.MACFor(addr)
				c.Len()
				c.Devices()
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := c.Poll(context.Background()); err != nil {
				t.Errorf("Poll: %v", err)
				return
			}
		}
	}()

	// Let the poll loop run long enough to overlap the readers.
	for i := 0; i < 200; i++ {
		if err := c.Poll(context.Background()); err != nil {
			t.Fatalf("Poll: %v", err)
		}
	}
	close(stop)
	wg.Wait()

	if _, ok := c.MACFor(addr); !ok {
		t.Error("the table lost its entry under concurrent access")
	}
}

// TestDoRequestRejectsNonSuccessStatus covers the shared transport guard.
// The error must carry the status text rather than a bare code, because
// "401 Unauthorized" tells an operator to go and fix a credential and "401"
// tells them only that a number they have already seen came back.
func TestDoRequestRejectsNonSuccessStatus(t *testing.T) {
	for _, code := range []int{401, 403, 500, 503} {
		do := doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: code,
				Status:     http.StatusText(code),
				Body:       http.NoBody,
			}, nil
		})
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://x", nil)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		if _, err := doRequest(do, req); err == nil {
			t.Errorf("status %d was accepted", code)
		} else if !strings.Contains(err.Error(), http.StatusText(code)) {
			t.Errorf("error %q does not name the status", err)
		}
	}
}

// doerFunc adapts a function to the Doer interface.
type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }
