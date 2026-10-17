package detect

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

func mac(s string) net.HardwareAddr {
	hw, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return hw
}

func baseEvent() core.NormalizedEvent {
	return core.NormalizedEvent{
		Time:      time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC),
		Kind:      core.EventTLS,
		DeviceMAC: mac("aa:bb:cc:dd:ee:ff"),
		Src: core.Endpoint{
			IP:   netip.MustParseAddr("192.168.1.44"),
			Port: 49152,
		},
		Dst: core.Endpoint{
			IP:   netip.MustParseAddr("3.170.12.33"),
			Port: 443,
		},
	}
}

func TestModelHostDetector_MatchesConfiguredDomain(t *testing.T) {
	d := NewModelHostDetector(nil)

	e := baseEvent()
	e.SNI = "huggingface.co"

	got := d.Evaluate(e)
	if len(got) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(got))
	}
	sig := got[0]
	if sig.Kind != core.SignalModelHostOnIoT {
		t.Errorf("Kind = %q, want %q", sig.Kind, core.SignalModelHostOnIoT)
	}
	if sig.Class != core.SignalReplicationRequired {
		t.Errorf("Class = %q, want %q", sig.Class, core.SignalReplicationRequired)
	}
	if sig.Reason == "" {
		t.Error("Reason must be non-empty; it is rendered into the remediation portal")
	}
	if sig.DeviceMAC.String() != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("DeviceMAC = %v, want aa:bb:cc:dd:ee:ff", sig.DeviceMAC)
	}
}

func TestModelHostDetector_MatchesSubdomain(t *testing.T) {
	d := NewModelHostDetector(nil)

	// A CDN subdomain is the realistic case for a multi-gigabyte weight
	// pull; it would never appear as a bare apex domain.
	e := baseEvent()
	e.SNI = "cdn-lfs.huggingface.co"

	if got := d.Evaluate(e); len(got) != 1 {
		t.Fatalf("expected subdomain to match, got %d signals", len(got))
	}

	// registry.ollama.ai is configured explicitly and must also match.
	e.SNI = "registry.ollama.ai"
	if got := d.Evaluate(e); len(got) != 1 {
		t.Fatalf("expected registry.ollama.ai to match, got %d signals", len(got))
	}
}

func TestModelHostDetector_RejectsBareHuggingfaceLookalike(t *testing.T) {
	d := NewModelHostDetector(nil)

	cases := []string{
		"huggingface.co.evil.example", // suffix confusion: the configured
		"evilhuggingface.co",          // domain is not at the end
		"notollama.com",
		"",
	}

	for _, host := range cases {
		e := baseEvent()
		e.SNI = host
		if got := d.Evaluate(e); len(got) != 0 {
			t.Errorf("host %q should not match, got %d signals", host, len(got))
		}
	}
}

func TestModelHostDetector_IgnoresUnattributableEvents(t *testing.T) {
	d := NewModelHostDetector(nil)

	// An inbound flow with no LAN-side MAC tells us nothing about which of
	// our devices is responsible, so it must not produce a signal.
	e := baseEvent()
	e.DeviceMAC = nil
	e.SNI = "huggingface.co"

	if got := d.Evaluate(e); len(got) != 0 {
		t.Fatalf("expected no signal without an attributable device, got %d", len(got))
	}
}

func TestModelHostDetector_FallsBackToDNSQueryName(t *testing.T) {
	d := NewModelHostDetector(nil)

	// A device that queries but never completes TLS still reveals intent,
	// and DNS is our only guaranteed sensor in passive-only mode.
	e := baseEvent()
	e.Kind = core.EventDNSQuery
	e.SNI = ""
	e.QueryName = "ollama.com"

	got := d.Evaluate(e)
	if len(got) != 1 {
		t.Fatalf("expected DNS query name to be consulted, got %d signals", len(got))
	}
	if got[0].Evidence["host"] != "ollama.com" {
		t.Errorf("evidence host = %v, want ollama.com", got[0].Evidence["host"])
	}
}

func TestModelHostDetector_PrefersSNIOverQueryName(t *testing.T) {
	d := NewModelHostDetector(nil)

	e := baseEvent()
	e.SNI = "huggingface.co"
	e.QueryName = "example.com" // unrelated

	got := d.Evaluate(e)
	if len(got) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(got))
	}
	if got[0].Evidence["host"] != "huggingface.co" {
		t.Errorf("evidence host = %v, want huggingface.co", got[0].Evidence["host"])
	}
}

func TestModelHostDetector_CustomSuffixesReplaceDefaults(t *testing.T) {
	d := NewModelHostDetector([]string{"models.internal.example"})

	e := baseEvent()
	e.SNI = "huggingface.co"
	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("default suffix should not match when custom suffixes supplied, got %d", len(got))
	}

	e.SNI = "models.internal.example"
	if got := d.Evaluate(e); len(got) != 1 {
		t.Errorf("custom suffix should match, got %d", len(got))
	}
}

func TestModelHostDetector_StripWildcardPrefix(t *testing.T) {
	d := NewModelHostDetector([]string{"*.cdn.example"})

	e := baseEvent()
	e.SNI = "files.cdn.example"

	if got := d.Evaluate(e); len(got) != 1 {
		t.Errorf("wildcard-prefixed suffix should match, got %d", len(got))
	}
}

// TestModelHostDetector_IsPure asserts the contract this package depends on:
// evaluating the same event twice produces identical results, and evaluation
// does not mutate the event. If this fails, a detector has grown state and
// will misbehave under concurrent ingest.
func TestModelHostDetector_IsPure(t *testing.T) {
	d := NewModelHostDetector(nil)

	e := baseEvent()
	e.SNI = "huggingface.co"

	a := d.Evaluate(e)
	b := d.Evaluate(e)

	if len(a) != len(b) {
		t.Fatalf("non-deterministic: %d then %d signals", len(a), len(b))
	}
	if a[0].Reason != b[0].Reason {
		t.Errorf("non-deterministic reason: %q then %q", a[0].Reason, b[0].Reason)
	}
	if e.SNI != "huggingface.co" {
		t.Error("Evaluate mutated the event")
	}
	if len(e.DeviceMAC) != 6 {
		t.Error("Evaluate mutated the event's DeviceMAC")
	}
}
