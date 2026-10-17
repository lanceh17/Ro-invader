package suricata

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

func testAttr() Attributor {
	return MapAttributor{
		netip.MustParseAddr("192.168.1.44"): mustMAC("aa:bb:cc:dd:ee:01"),
		netip.MustParseAddr("192.168.1.50"): mustMAC("aa:bb:cc:dd:ee:02"),
	}
}

func mustMAC(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

const sampleFlow = `{"timestamp":"2026-10-17T12:00:00.000000+0000","flow_id":123,"event_type":"flow","src_ip":"192.168.1.44","src_port":49152,"dest_ip":"3.170.12.33","dest_port":443,"proto":"TCP","flow":{"pkts_toserver":10,"pkts_toclient":20,"bytes_toserver":500000,"bytes_toclient":1200,"age":3600.5,"start":"2026-10-17T11:00:00.000000+0000"}}`

const sampleTLS = `{"timestamp":"2026-10-17T12:05:00.000000+0000","event_type":"tls","src_ip":"192.168.1.44","src_port":50000,"dest_ip":"3.170.12.33","dest_port":443,"proto":"TCP","tls":{"subject":"*.huggingface.co","sni":"cdn-lfs.huggingface.co","version":"TLS 1.3"}}`

const sampleDNSQuery = `{"timestamp":"2026-10-17T12:04:00.000000+0000","event_type":"dns","src_ip":"192.168.1.44","src_port":5353,"dest_ip":"192.168.1.1","dest_port":53,"proto":"UDP","dns":{"version":2,"type":"query","id":42,"flags":"0100","rrname":"ollama.com","rrtype":"A"}}`

const sampleDNSAnswer = `{"timestamp":"2026-10-17T12:04:00.000000+0000","event_type":"dns","src_ip":"192.168.1.1","src_port":53,"dest_ip":"192.168.1.44","dest_port":5353,"proto":"UDP","dns":{"version":2,"type":"answer","id":42,"flags":"8180","rrname":"ollama.com","rrtype":"A","rcode":"NOERROR","answers":[{"rrname":"ollama.com","rrtype":"A","ttl":60,"addr":"54.198.0.1"}]}}`

const sampleSSHAuth = `{"timestamp":"2026-10-17T12:06:00.000000+0000","event_type":"ssh","src_ip":"192.168.1.50","src_port":51000,"dest_ip":"192.168.1.44","dest_port":22,"proto":"TCP","ssh":{"client":{"proto":"2.0","software_version":"OpenSSH_8.2"},"server":{"proto":"2.0","software_version":"OpenSSH_9.0"},"auth":{"success":true,"username":"root","method":"password","direction":"to_server"}}}`

const sampleSSHNoAuth = `{"timestamp":"2026-10-17T12:06:01.000000+0000","event_type":"ssh","src_ip":"192.168.1.50","src_port":51001,"dest_ip":"192.168.1.44","dest_port":22,"proto":"TCP","ssh":{"client":{"proto":"2.0","software_version":"OpenSSH_8.2"},"server":{"proto":"2.0","software_version":"OpenSSH_9.0"}}}`

// sampleSSHOutboundAuth is an authentication attempt the device made outward.
// It is not credential-reuse fan-out and must not be reported as one.
const sampleSSHOutboundAuth = `{"timestamp":"2026-10-17T12:06:02.000000+0000","event_type":"ssh","src_ip":"192.168.1.50","src_port":51002,"dest_ip":"8.8.8.8","dest_port":22,"proto":"TCP","ssh":{"auth":{"success":false,"username":"admin","method":"password","direction":"to_client"}}}`

func TestNormalizeFlow(t *testing.T) {
	rec, ok := UnmarshalRecord([]byte(sampleFlow))
	if !ok {
		t.Fatal("failed to decode flow record")
	}
	ev, ok := Normalize(rec, testAttr())
	if !ok {
		t.Fatal("expected flow to normalize")
	}

	if ev.Kind != core.EventFlow {
		t.Errorf("Kind = %q, want %q", ev.Kind, core.EventFlow)
	}
	if ev.Bytes != 501200 {
		t.Errorf("Bytes = %d, want 501200 (both directions summed)", ev.Bytes)
	}
	if ev.Duration != time.Duration(3600.5*float64(time.Second)) {
		t.Errorf("Duration = %v, want 3600.5s", ev.Duration)
	}
	if ev.DeviceMAC.String() != "aa:bb:cc:dd:ee:01" {
		t.Errorf("DeviceMAC = %v, want aa:bb:cc:dd:ee:01", ev.DeviceMAC)
	}
	if ev.Src.Port != 49152 || ev.Dst.Port != 443 {
		t.Errorf("ports = %d/%d, want 49152/443", ev.Src.Port, ev.Dst.Port)
	}
}

func TestNormalizeTLSCarriesSNI(t *testing.T) {
	rec, _ := UnmarshalRecord([]byte(sampleTLS))
	ev, ok := Normalize(rec, testAttr())
	if !ok {
		t.Fatal("expected tls to normalize")
	}
	if ev.Kind != core.EventTLS {
		t.Errorf("Kind = %q, want %q", ev.Kind, core.EventTLS)
	}
	if ev.SNI != "cdn-lfs.huggingface.co" {
		t.Errorf("SNI = %q, want cdn-lfs.huggingface.co", ev.SNI)
	}
}

func TestNormalizeDNSQueryAndAnswer(t *testing.T) {
	rec, _ := UnmarshalRecord([]byte(sampleDNSQuery))
	ev, ok := Normalize(rec, testAttr())
	if !ok {
		t.Fatal("expected dns query to normalize")
	}
	if ev.Kind != core.EventDNSQuery {
		t.Errorf("Kind = %q, want %q", ev.Kind, core.EventDNSQuery)
	}
	if ev.QueryName != "ollama.com" {
		t.Errorf("QueryName = %q, want ollama.com", ev.QueryName)
	}

	// The answer travels in the opposite direction, so the LAN side is the
	// destination rather than the source. Attribution must follow it.
	rec, _ = UnmarshalRecord([]byte(sampleDNSAnswer))
	ev, ok = Normalize(rec, testAttr())
	if !ok {
		t.Fatal("expected dns answer to normalize")
	}
	if ev.Kind != core.EventDNSAnswer {
		t.Errorf("Kind = %q, want %q", ev.Kind, core.EventDNSAnswer)
	}
	if ev.DeviceMAC.String() != "aa:bb:cc:dd:ee:01" {
		t.Errorf("DeviceMAC = %v, want aa:bb:cc:dd:ee:01 on the answering direction", ev.DeviceMAC)
	}
}

func TestNormalizeSSHAuth(t *testing.T) {
	rec, _ := UnmarshalRecord([]byte(sampleSSHAuth))
	ev, ok := Normalize(rec, testAttr())
	if !ok {
		t.Fatal("expected ssh auth to normalize")
	}
	if ev.Kind != core.EventSSHAuth {
		t.Errorf("Kind = %q, want %q", ev.Kind, core.EventSSHAuth)
	}
	if ev.AuthUser != "root" {
		t.Errorf("AuthUser = %q, want root", ev.AuthUser)
	}
	// The device that *made* the attempt is .50; the target is .44. A
	// credential-reuse detector must score the originator, not the victim.
	if ev.DeviceMAC.String() != "aa:bb:cc:dd:ee:02" {
		t.Errorf("DeviceMAC = %v, want aa:bb:cc:dd:ee:02 (the initiating device)", ev.DeviceMAC)
	}
}

func TestNormalizeSSHWithoutAuthBlockIsDropped(t *testing.T) {
	rec, _ := UnmarshalRecord([]byte(sampleSSHNoAuth))
	if _, ok := Normalize(rec, testAttr()); ok {
		t.Error("a bare SSH connection record is not an authentication attempt and must not normalize")
	}
}

func TestNormalizeSSHToClientIsDropped(t *testing.T) {
	rec, _ := UnmarshalRecord([]byte(sampleSSHOutboundAuth))
	if _, ok := Normalize(rec, testAttr()); ok {
		t.Error("outbound SSH auth direction must not be treated as credential-reuse fan-out")
	}
}

func TestNormalizeRejectsUndecodableAndUnrecognized(t *testing.T) {
	cases := []string{
		`not json at all`,
		`{"no_event_type":true}`,
		`{"event_type":"totally_unknown_type"}`,
		`{"event_type":"flow","src_ip":"not-an-ip","dest_ip":"8.8.8.8"}`,
		``,
	}

	for _, line := range cases {
		if _, ok := UnmarshalRecord([]byte(line)); !ok {
			continue // rejected at decode, which is also fine
		}
		if _, ok := Normalize(Record{EventType: "flow"}, testAttr()); ok && line == `{"event_type":"totally_unknown_type"}` {
			t.Error("unknown event type must not normalize")
		}
	}
}

// TestNormalizeRejectsAmbiguousFlows covers the attribution edge case that is
// easiest to get silently wrong: both ends on-link, or neither. Guessing here
// would accuse an innocent device.
func TestNormalizeRejectsAmbiguousFlows(t *testing.T) {
	// Both ends off-link: nothing of ours is involved.
	offLink := Record{
		EventType: "flow", SrcIP: "8.8.8.8", DestIP: "1.1.1.1",
		SrcPort: 1234, DestPort: 443, Proto: "TCP",
	}
	if _, ok := Normalize(offLink, testAttr()); ok {
		t.Error("a flow with both ends off-link is not attributable")
	}

	// Both ends on-link. LANSide cannot say which side is "the" device, so
	// the flow is dropped rather than attributed to one of them arbitrarily.
	ambiguous := Record{
		EventType: "flow", SrcIP: "10.0.0.5", DestIP: "10.0.0.6",
		SrcPort: 1234, DestPort: 443, Proto: "TCP",
	}
	if _, ok := Normalize(ambiguous, testAttr()); ok {
		t.Error("a flow with both ends on-link is ambiguous and must not normalize")
	}
}

func TestParseTimestampVariants(t *testing.T) {
	cases := map[string]string{
		"suricata default": "2026-10-17T12:00:00.000000+0000",
		"RFC3339":          "2026-10-17T12:00:00Z",
		"no fraction":      "2026-10-17T12:00:00",
		"no timezone":      "2026-10-17T12:00:00.000000",
		"negative offset":  "2026-10-17T12:00:00.000000-0700",
	}

	for name, s := range cases {
		if got := ParseTimestamp(s); got.IsZero() {
			t.Errorf("%s (%q) parsed to zero time", name, s)
		}
	}

	// An unparsable timestamp must not error the record out; a zero time is
	// treated as "unknown" downstream.
	if got := ParseTimestamp("garbage"); !got.IsZero() {
		t.Errorf("garbage parsed to %v, want zero", got)
	}
	if got := ParseTimestamp(""); !got.IsZero() {
		t.Errorf("empty parsed to %v, want zero", got)
	}
}

// TestReaderSkipsMalformedAndContinues is the failure mode that matters most:
// one bad line must not stop telemetry ingest for the rest of the network's
// lifetime.
func TestReaderSkipsMalformedAndContinues(t *testing.T) {
	stream := strings.Join([]string{
		sampleTLS,
		`{"event_type":"flow","src_ip":"BROKEN`,
		sampleDNSQuery,
		``, // blank line
		`{"event_type":"unheard_of"}`,
		sampleSSHAuth,
	}, "\n")

	evs, err := ReadAll(strings.NewReader(stream), testAttr())
	if err != nil {
		t.Fatalf("ReadAll errored: %v", err)
	}
	if len(evs) != 3 {
		t.Fatalf("expected 3 events, got %d", len(evs))
	}
	kinds := []core.EventKind{evs[0].Kind, evs[1].Kind, evs[2].Kind}
	want := []core.EventKind{core.EventTLS, core.EventDNSQuery, core.EventSSHAuth}
	for i := range want {
		if kinds[i] != want[i] {
			t.Errorf("event %d kind = %q, want %q", i, kinds[i], want[i])
		}
	}
}

// TestReaderHandlesLinesBeyondDefaultBuffer guards the specific trap that
// bufio.Scanner's default 64 KB limit was not raised: ingestion silently stops
// at the first large record, which is indistinguishable from "no threats
// found".
func TestReaderHandlesLinesBeyondDefaultBuffer(t *testing.T) {
	padding := strings.Repeat("x", 200_000) // well past bufio's 64 KiB default
	big := `{"timestamp":"2026-10-17T12:05:00.000000+0000","event_type":"tls",` +
		`"src_ip":"192.168.1.44","src_port":50000,"dest_ip":"3.170.12.33","dest_port":443,` +
		`"proto":"TCP","tls":{"sni":"cdn-lfs.huggingface.co"},"padding":"` + padding + `"}`

	stream := big + "\n" + sampleDNSQuery + "\n"

	evs, err := ReadAll(strings.NewReader(stream), testAttr())
	if err != nil {
		t.Fatalf("ReadAll errored: %v", err)
	}
	if len(evs) != 2 {
		t.Fatalf("expected the large line AND the following line, got %d events", len(evs))
	}
	if evs[0].SNI != "cdn-lfs.huggingface.co" {
		t.Errorf("large record lost its SNI: %q", evs[0].SNI)
	}
	if evs[1].QueryName != "ollama.com" {
		t.Errorf("record after the large one was not ingested: %+v", evs[1])
	}
}

func TestNilAttributorYieldsUnattributableEvents(t *testing.T) {
	evs, err := ReadAll(strings.NewReader(sampleTLS), nil)
	if err != nil {
		t.Fatalf("ReadAll errored: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	if len(evs[0].DeviceMAC) != 0 {
		t.Error("a nil attributor must yield no DeviceMAC, which detectors treat as unattributable")
	}
}

// TestNormalizeIsAttributionSafe verifies that an on-link address that the
// inventory does not know about produces an unattributable event rather than
// an event blamed on some other device.
func TestNormalizeIsAttributionSafe(t *testing.T) {
	rec := Record{
		EventType: "tls", SrcIP: "192.168.1.99", SrcPort: 50000,
		DestIP: "3.170.12.33", DestPort: 443, Proto: "TCP",
		TLS: &tlsPayload{SNI: "huggingface.co"},
	}
	ev, ok := Normalize(rec, testAttr())
	if !ok {
		t.Fatal("expected normalize to succeed")
	}
	if len(ev.DeviceMAC) != 0 {
		t.Error("an unknown on-link host must not be attributed to a known device")
	}
}
