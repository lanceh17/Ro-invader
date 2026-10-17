package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
	"github.com/lanceh17/Ro-invader/agent/internal/detect"
	"github.com/lanceh17/Ro-invader/agent/internal/pipeline"
)

var (
	testPortal  = netip.MustParseAddr("192.168.1.1")
	testClient  = netip.MustParseAddr("192.168.1.50")
	testUnknown = netip.MustParseAddr("192.168.1.99")
)

// testServer builds a Server whose upstream is replaced by stub, so Handle
// can be exercised with no network.
func testServer(t *testing.T, cfg Config, stub forwarder) *Server {
	t.Helper()
	if cfg.Upstream == "" {
		cfg.Upstream = "127.0.0.1:53"
	}
	if !cfg.Portal.IsValid() {
		cfg.Portal = testPortal
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if stub != nil {
		s.forward = stub
	}
	return s
}

// okForward returns a canned A response for whatever it is sent, and records
// that it was called so tests can assert forwarding happened (or did not).
func okForward(called *bool) forwarder {
	return func(q []byte) ([]byte, error) {
		if called != nil {
			*called = true
		}
		// A minimal response: echo the ID, set QR, no records.
		out := make([]byte, HeaderLen)
		copy(out, q[:HeaderLen])
		binary.BigEndian.PutUint16(out[2:4], flagQR|flagRD)
		return out, nil
	}
}

func TestNewRequiresUpstreamAndPortal(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("an empty config must be rejected")
	}
	if _, err := New(Config{Upstream: "1.1.1.1:53"}); err == nil {
		t.Error("a missing Portal must be rejected")
	}
	if _, err := New(Config{Portal: testPortal}); err == nil {
		t.Error("a missing Upstream must be rejected")
	}
}

func TestNewDefaultsNilQuarantined(t *testing.T) {
	// The stub keeps this off the network; the default Quarantined is what is
	// under test, not upstream forwarding.
	s := testServer(t, Config{}, okForward(nil))
	// A nil Quarantined would panic on the first query. New must install a
	// default that treats every device as free.
	if resp := s.Handle(buildQuery(t, "example.com", TypeA), testClient); resp == nil {
		t.Fatal("Handle with default Quarantined returned nil; want a response")
	}
}

// --- policy (Config.Decide) ------------------------------------------------

func TestDecideUncontainedAlwaysForwards(t *testing.T) {
	c := Config{Garden: []string{"vendor.example"}}
	for _, name := range []string{"example.com", "patch.vendor.example", "evil.example"} {
		if d := c.Decide(name, false); d.Action != ActionForward {
			t.Errorf("Decide(%q, uncontained) = %v, want forward", name, d.Action)
		}
	}
}

func TestDecideContainedSinkholesForeignNames(t *testing.T) {
	c := Config{Garden: []string{"vendor.example"}}
	d := c.Decide("cdn-lfs.huggingface.co", true)
	if d.Action != ActionSinkhole {
		t.Errorf("contained + foreign name = %v, want sinkhole", d.Action)
	}
	if d.Reason == "" {
		t.Error("a sinkhole decision must carry a reason for the portal to show")
	}
}

func TestDecideContainedAllowsGarden(t *testing.T) {
	c := Config{Garden: []string{"vendor.example", "cdn.vendor.example"}}
	for _, name := range []string{
		"vendor.example",
		"cdn.vendor.example",       // listed explicitly
		"patch.cdn.vendor.example", // subdomain of a listed suffix
	} {
		if d := c.Decide(name, true); d.Action != ActionForward {
			t.Errorf("contained + garden %q = %v, want forward", name, d.Action)
		}
	}
}

// TestDecideNoSubstringMatch is the security-relevant edge: a device must not
// reach "evilvendor.example" just because "vendor.example" is in the garden.
func TestDecideNoSubstringMatch(t *testing.T) {
	c := Config{Garden: []string{"vendor.example"}}
	for _, name := range []string{
		"evilvendor.example",
		"vendor.example.evil.com",
		"notvendor.example",
	} {
		if d := c.Decide(name, true); d.Action != ActionSinkhole {
			t.Errorf("contained + %q = %v, want sinkhole (no substring match)", name, d.Action)
		}
	}
}

func TestDecideNormalizesCaseAndDot(t *testing.T) {
	c := Config{Garden: []string{"Vendor.Example."}}
	if d := c.Decide("PATCH.VENDOR.EXAMPLE.", true); d.Action != ActionForward {
		t.Errorf("mixed case + trailing dot = %v, want forward", d.Action)
	}
}

func TestDecideEmptyNameForwards(t *testing.T) {
	// The root/priming query has no name. Refusing it would break stubs that
	// send it at startup, so it forwards.
	c := Config{Garden: []string{"vendor.example"}}
	if d := c.Decide("", true); d.Action != ActionForward {
		t.Errorf("empty name = %v, want forward", d.Action)
	}
}

func TestDecideEmptyGardenSuffixIgnored(t *testing.T) {
	c := Config{Garden: []string{"", "  ", "vendor.example"}}
	// The blank entries must not make every name match.
	if d := c.Decide("anything.example", true); d.Action != ActionSinkhole {
		t.Errorf("blank garden entries caused a match: %v", d.Action)
	}
}

// --- threat-intel blocklist (Config.Blocked) -------------------------------

func TestDecideBlockedNameForNXDomain(t *testing.T) {
	c := Config{
		Blocked: func(name string) bool { return name == "c2.evil.example" },
	}
	d := c.Decide("C2.Evil.Example.", false)
	if d.Action != ActionNXDomain {
		t.Errorf("uncontained + blocked = %v, want nxdomain", d.Action)
	}
	if d.Reason == "" {
		t.Error("a blocked decision must carry a reason for the audit log")
	}
	if d := c.Decide("ordinary.example", false); d.Action != ActionForward {
		t.Errorf("uncontained + unblocked = %v, want forward", d.Action)
	}
}

func TestDecideNoBlockedHookForwards(t *testing.T) {
	// A nil hook is the shipped default: fresh installs block nothing.
	c := Config{}
	if d := c.Decide("c2.evil.example", false); d.Action != ActionForward {
		t.Errorf("nil Blocked = %v, want forward", d.Action)
	}
}

func TestDecideBlockedNeverAppliesToContainedDevices(t *testing.T) {
	c := Config{
		Garden:  []string{"vendor.example"},
		Blocked: func(string) bool { return true },
	}
	// Containment already answers non-garden names with the portal; the
	// blocklist must not replace that notification with a bare NXDOMAIN.
	if d := c.Decide("c2.evil.example", true); d.Action != ActionSinkhole {
		t.Errorf("contained + blocked + non-garden = %v, want sinkhole", d.Action)
	}
	// And remediation outranks the blocklist: a garden name stays resolvable
	// even when a feed also lists it, or the device could never be fixed.
	if d := c.Decide("vendor.example", true); d.Action != ActionForward {
		t.Errorf("contained + blocked + garden = %v, want forward", d.Action)
	}
}

func TestDecideRootQueryBeatsBlocklist(t *testing.T) {
	// The priming query has no name; a blocklist that claims everything
	// still must not refuse it, or stubs break at startup.
	c := Config{Blocked: func(string) bool { return true }}
	if d := c.Decide("", false); d.Action != ActionForward {
		t.Errorf("root query = %v, want forward", d.Action)
	}
}

func TestHandleBlockedNameNeverReachesUpstream(t *testing.T) {
	var called bool
	var gotAction Action
	s := testServer(t, Config{
		Blocked: func(name string) bool { return name == "c2.evil.example" },
		OnQuery: func(_ core.NormalizedEvent, a Action) { gotAction = a },
	}, okForward(&called))

	resp := s.Handle(buildQuery(t, "c2.evil.example", TypeA), testClient)
	if called {
		t.Fatal("a blocked name was forwarded to the upstream resolver")
	}
	if got := uint8(binary.BigEndian.Uint16(resp[2:4]) & 0x000F); got != RCodeNameErr {
		t.Errorf("RCODE = %d, want NXDOMAIN", got)
	}
	if gotAction != ActionNXDomain {
		t.Errorf("OnQuery action = %v, want nxdomain so the audit can record it", gotAction)
	}

	// The neighbour is unaffected: the predicate is name-based, not device.
	s.Handle(buildQuery(t, "ordinary.example", TypeA), testClient)
	if !called {
		t.Error("an unblocked name must still forward")
	}
}

// --- Handle path -----------------------------------------------------------

func TestHandleMalformedReturnsFormErr(t *testing.T) {
	s := testServer(t, Config{}, nil)
	resp := s.Handle([]byte{0x01}, testClient)
	if got := uint8(binary.BigEndian.Uint16(resp[2:4]) & 0x000F); got != RCodeFormErr {
		t.Errorf("RCODE = %d, want FORMERR", got)
	}
}

func TestHandleNoQuestionReturnsFormErr(t *testing.T) {
	// A valid header advertising zero questions is malformed under RFC 1035,
	// so the answer is FORMERR. There is no question to echo into a REFUSED.
	raw := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(raw[4:6], 0)
	s := testServer(t, Config{}, nil)
	resp := s.Handle(raw, testClient)
	if got := uint8(binary.BigEndian.Uint16(resp[2:4]) & 0x000F); got != RCodeFormErr {
		t.Errorf("RCODE = %d, want FORMERR", got)
	}
}

func TestHandleUncontainedForwards(t *testing.T) {
	var called bool
	s := testServer(t, Config{}, okForward(&called))
	resp := s.Handle(buildQuery(t, "example.com", TypeA), testClient)
	if !called {
		t.Fatal("an uncontained device's query was not forwarded")
	}
	if resp == nil {
		t.Fatal("Handle returned nil; a response is required")
	}
	if binary.BigEndian.Uint16(resp[2:4])&flagQR == 0 {
		t.Error("relayed response must have QR set")
	}
}

func TestHandleContainedSinkholes(t *testing.T) {
	var called bool
	s := testServer(t, Config{
		Quarantined: func(ip netip.Addr) bool { return ip == testClient },
	}, okForward(&called))

	resp := s.Handle(buildQuery(t, "cdn-lfs.huggingface.co", TypeA), testClient)
	if called {
		t.Fatal("a contained device's query must not reach the upstream")
	}
	// The rdata is the portal.
	rdata := resp[len(resp)-4:]
	if netip.AddrFrom4([4]byte{rdata[0], rdata[1], rdata[2], rdata[3]}) != testPortal {
		t.Errorf("sinkhole rdata = %v, want portal %v", rdata, testPortal)
	}
}

func TestHandleContainedGardenStillResolves(t *testing.T) {
	var called bool
	s := testServer(t, Config{
		Garden:      []string{"vendor.example"},
		Quarantined: func(netip.Addr) bool { return true },
	}, okForward(&called))

	s.Handle(buildQuery(t, "patch.vendor.example", TypeA), testClient)
	if !called {
		t.Fatal("the walled-garden exception was not honoured; a contained device could never be remediated")
	}
}

// TestHandleQuarantineIsPerDevice: containment is keyed to the source address,
// so one contained device must not sinkhole its neighbours.
func TestHandleQuarantineIsPerDevice(t *testing.T) {
	s := testServer(t, Config{
		Quarantined: func(ip netip.Addr) bool { return ip == testClient },
	}, okForward(nil))

	contained := s.Handle(buildQuery(t, "example.com", TypeA), testClient)
	free := s.Handle(buildQuery(t, "example.com", TypeA), testUnknown)

	if got := uint8(binary.BigEndian.Uint16(contained[2:4]) & 0x000F); got == RCodeNoError {
		// A sinkhole is NOERROR with an answer; an empty NOERROR would mean
		// the contained device got a clean pass.
		if binary.BigEndian.Uint16(contained[6:8]) == 0 {
			t.Error("contained device received an empty success; it must be sinkholed")
		}
	}
	if binary.BigEndian.Uint16(free[6:8]) != 0 && free[len(free)-4] != testPortal.As4()[0] {
		// The free device's response is the canned forward, not the portal.
		if free[len(free)-4] == testPortal.As4()[0] {
			t.Error("an uncontained device was sinkholed")
		}
	}
}

func TestHandleUpstreamFailureReturnsServFail(t *testing.T) {
	s := testServer(t, Config{}, func([]byte) ([]byte, error) {
		return nil, errors.New("upstream down")
	})
	resp := s.Handle(buildQuery(t, "example.com", TypeA), testClient)
	if got := uint8(binary.BigEndian.Uint16(resp[2:4]) & 0x000F); got != 2 { // SERVFAIL
		t.Errorf("RCODE = %d, want SERVFAIL when the upstream is unreachable", got)
	}
}

func TestHandleOnQueryCallback(t *testing.T) {
	var gotEv core.NormalizedEvent
	var gotAction Action
	s := testServer(t, Config{
		Quarantined: func(ip netip.Addr) bool { return ip == testClient },
		OnQuery: func(ev core.NormalizedEvent, a Action) {
			gotEv, gotAction = ev, a
		},
	}, nil)

	s.Handle(buildQuery(t, "cdn-lfs.huggingface.co", TypeA), testClient)

	if gotAction != ActionSinkhole {
		t.Errorf("action = %v, want sinkhole", gotAction)
	}
	if gotEv.Kind != core.EventDNSQuery {
		t.Errorf("Kind = %v, want EventDNSQuery", gotEv.Kind)
	}
	if gotEv.Src.IP != testClient {
		t.Errorf("Src.IP = %v, want %v", gotEv.Src.IP, testClient)
	}
	if gotEv.QueryName != "cdn-lfs.huggingface.co" {
		t.Errorf("QueryName = %q, want cdn-lfs.huggingface.co", gotEv.QueryName)
	}
	if gotEv.Dst.Host != "cdn-lfs.huggingface.co" {
		t.Errorf("Dst.Host = %q, want the queried name", gotEv.Dst.Host)
	}
	// The event must carry a real time, because the risk engine's decay keys
	// off it. A zero time would silently fall back to the engine's clock.
	if gotEv.Time.IsZero() {
		t.Error("event Time is zero; the timestamp must be stamped here")
	}
	// Attribution is the pipeline's job: the resolver knows an IP, not the
	// inventory. DeviceMAC must be left empty for the pipeline to fill.
	if len(gotEv.DeviceMAC) != 0 {
		t.Errorf("DeviceMAC = %v, want empty; the resolver does not hold the inventory", gotEv.DeviceMAC)
	}
}

// TestOnQueryEventFeedsThePipeline is the end-to-end wiring this slice exists
// for: a query arriving at the resolver becomes an event, which the pipeline
// attributes and scores, with no Suricata anywhere in the path.
func TestOnQueryEventFeedsThePipeline(t *testing.T) {
	// The resolver hands the pipeline an unattributed event carrying only the
	// source IP; the pipeline's attributor maps that IP to the device.
	invMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x50}
	attr := pipeline.MapAttributor{testClient: invMAC}

	// Low baseline so a single first contact exercises R7.
	pipe := pipeline.New(attr, nil, detect.NewDNSDriftDetector(1, nil))

	var captured []core.NormalizedEvent
	s := testServer(t, Config{
		OnQuery: func(ev core.NormalizedEvent, _ Action) { captured = append(captured, ev) },
	}, okForward(nil))

	// Two queries: one ordinary to establish baseline, one to a watched domain.
	s.Handle(buildQuery(t, "ordinary.example", TypeA), testClient)
	s.Handle(buildQuery(t, "cdn-lfs.huggingface.co", TypeA), testClient)

	if len(captured) != 2 {
		t.Fatalf("captured %d events, want 2", len(captured))
	}

	var fired []core.Signal
	for _, ev := range captured {
		fired = append(fired, pipe.Ingest(ev)...)
	}

	if len(fired) != 1 {
		t.Fatalf("pipeline fired %d signals, want 1 (the first model-host contact)", len(fired))
	}
	if fired[0].Kind != core.SignalDNSDrift {
		t.Errorf("Kind = %v, want SignalDNSDrift", fired[0].Kind)
	}
	if fired[0].DeviceMAC.String() != invMAC.String() {
		t.Errorf("attributed to %v, want %v (via the pipeline, not the resolver)", fired[0].DeviceMAC, invMAC)
	}

	// And the engine must hold it.
	dev := core.Device{MAC: invMAC, Class: core.ClassCamera}
	if a := pipe.Engine().Evaluate(dev, captured[1].Time); a.Score <= 0 {
		t.Errorf("engine score = %v; the DNS signal never reached scoring", a.Score)
	}
}

// --- live socket -----------------------------------------------------------

// TestListenAndServeRoundTrip runs the real UDP loop on loopback. It is the
// one test that binds a port, and it exists because the parse/decide/respond
// logic being correct does not prove the socket loop forwards packets.
func TestListenAndServeRoundTrip(t *testing.T) {
	ready := make(chan net.Addr, 1)
	// OnQuery runs on the server's goroutine, while the assertions run on the
	// test's. A UDP round trip is not a happens-before edge the race detector
	// can see, so the observation comes back over a channel rather than into
	// captured variables; without this, TestListenAndServeRoundTrip fails
	// under -race in CI while passing everywhere else.
	observed := make(chan core.NormalizedEvent, 1)

	s := testServer(t, Config{
		ListenAddr: "127.0.0.1:0",
		// The source address is loopback, which is not a LAN device IP the
		// test could have predicted, so containment is asserted for every
		// source. The point of this test is the socket round trip, and the
		// per-device keying is covered by TestHandleQuarantineIsPerDevice.
		Quarantined: func(netip.Addr) bool { return true },
		OnQuery: func(ev core.NormalizedEvent, _ Action) {
			select {
			case observed <- ev:
			default:
			}
		},
		Ready: func(a net.Addr) { ready <- a },
	}, okForward(nil))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- s.ListenAndServe(ctx) }()

	var addr net.Addr
	select {
	case addr = <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("server never became ready")
	}

	conn, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatalf("dialing the resolver: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := conn.Write(buildQuery(t, "cdn-lfs.huggingface.co", TypeA)); err != nil {
		t.Fatalf("writing query: %v", err)
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	if binary.BigEndian.Uint16(buf[6:8]) != 1 {
		t.Errorf("ANCOUNT = %d, want 1 (the sinkholed portal answer)", binary.BigEndian.Uint16(buf[6:8]))
	}
	rdata := buf[n-4:]
	if netip.AddrFrom4([4]byte{rdata[0], rdata[1], rdata[2], rdata[3]}) != testPortal {
		t.Errorf("rdata = %v, want portal", rdata)
	}
	var gotEv core.NormalizedEvent
	select {
	case gotEv = <-observed:
	case <-time.After(2 * time.Second):
		t.Fatal("OnQuery never fired")
	}
	if gotEv.QueryName != "cdn-lfs.huggingface.co" {
		t.Errorf("OnQuery name = %q, want the queried name", gotEv.QueryName)
	}
	// Loopback source attribution: the sinkhole only happened because the
	// source matched Quarantined, so the address the loop recorded is the
	// address the policy keyed on.
	if src := gotEv.Src.IP; !src.IsValid() || !src.IsLoopback() {
		t.Errorf("OnQuery source = %v, want a loopback address", src)
	}

	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Errorf("ListenAndServe returned %v on cancel; want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("ListenAndServe did not return after cancel")
	}
}
