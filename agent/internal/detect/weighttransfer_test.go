package detect

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

func weightTransferBaseFlowEvent() core.NormalizedEvent {
	return core.NormalizedEvent{
		Time:      time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC),
		Kind:      core.EventFlow,
		DeviceMAC: mac("aa:bb:cc:dd:ee:ff"),
		Src: core.Endpoint{
			IP:   netip.MustParseAddr("192.168.1.44"),
			Port: 49152,
		},
		Dst: core.Endpoint{
			IP:   netip.MustParseAddr("3.170.12.33"),
			Port: 443,
		},
		Bytes:     600 << 20, // 600 MiB
		SNI:       "huggingface.co",
		QueryName: "huggingface.co",
	}
}

func TestWeightTransferDetector_FiresOnLargeTransferToModelHost(t *testing.T) {
	d := NewWeightTransferDetector(nil)

	e := weightTransferBaseFlowEvent()
	e.SNI = "huggingface.co"

	got := d.Evaluate(e)
	if len(got) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(got))
	}
	sig := got[0]
	if sig.Kind != core.SignalWeightTransfer {
		t.Errorf("Kind = %q, want %q", sig.Kind, core.SignalWeightTransfer)
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
	if sig.Weight <= 0 || sig.Confidence <= 0 {
		t.Errorf("weight/confidence must be positive, got %v/%v", sig.Weight, sig.Confidence)
	}
}

func TestWeightTransferDetector_RejectsSmallTransfers(t *testing.T) {
	d := NewWeightTransferDetector(nil)

	e := weightTransferBaseFlowEvent()
	e.Bytes = 100 << 20 // 100 MiB, below 500 MiB threshold

	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("small transfer should not fire, got %d signals", len(got))
	}
}

func TestWeightTransferDetector_RejectsNonModelHostDestinations(t *testing.T) {
	d := NewWeightTransferDetector(nil)

	e := weightTransferBaseFlowEvent()
	e.SNI = "example.com"

	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("non-model host should not fire, got %d signals", len(got))
	}
}

func TestWeightTransferDetector_FiresOnCDNSubdomains(t *testing.T) {
	d := NewWeightTransferDetector(nil)

	testCases := []string{
		"cdn-lfs.huggingface.co",
		"hf.co",
		"ollama.com",
		"registry.ollama.ai",
	}

	for _, host := range testCases {
		e := weightTransferBaseFlowEvent()
		e.SNI = host
		if got := d.Evaluate(e); len(got) != 1 {
			t.Errorf("host %q should fire, got %d signals", host, len(got))
		}
	}
}

func TestWeightTransferDetector_RejectsLookalikeDomains(t *testing.T) {
	d := NewWeightTransferDetector(nil)

	cases := []string{
		"huggingface.co.evil.example",
		"evilhuggingface.co",
		"notollama.com",
		"example.com",
		"",
	}

	for _, host := range cases {
		e := weightTransferBaseFlowEvent()
		e.SNI = host
		if host == "" {
			e.QueryName = ""
		}
		if got := d.Evaluate(e); len(got) != 0 {
			t.Errorf("host %q should not match, got %d signals", host, len(got))
		}
	}
}

func TestWeightTransferDetector_RequiresFlowEvent(t *testing.T) {
	d := NewWeightTransferDetector(nil)

	e := weightTransferBaseFlowEvent()
	e.Kind = core.EventTLS
	e.Bytes = 600 << 20
	e.SNI = "huggingface.co"

	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("non-flow events should not fire, got %d signals", len(got))
	}
}

func TestWeightTransferDetector_IgnoresUnattributableEvents(t *testing.T) {
	d := NewWeightTransferDetector(nil)

	e := weightTransferBaseFlowEvent()
	e.DeviceMAC = nil
	e.SNI = "huggingface.co"

	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("unattributable event should not fire, got %d signals", len(got))
	}
}

func TestWeightTransferDetector_RequiresMinimumBytes(t *testing.T) {
	d := NewWeightTransferDetector(nil)

	e := weightTransferBaseFlowEvent()
	e.Bytes = 0

	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("zero bytes should not fire, got %d signals", len(got))
	}
}

func TestWeightTransferDetector_CustomThreshold(t *testing.T) {
	d := NewWeightTransferDetector(nil)
	// Note: WeightTransferDetector constructor only takes suffixes, not threshold
	// The threshold is fixed at 500 MiB in the current implementation
	// This test documents the current behavior
	e := weightTransferBaseFlowEvent()
	e.Bytes = 400 << 20 // 400 MiB

	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("400 MiB should not fire with 500 MiB threshold, got %d signals", len(got))
	}
}

func TestWeightTransferDetector_CustomSuffixes(t *testing.T) {
	d := NewWeightTransferDetector([]string{"models.internal.example"})

	e := weightTransferBaseFlowEvent()
	e.SNI = "huggingface.co"
	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("default suffix should not match when custom suffixes supplied, got %d", len(got))
	}

	e.SNI = "models.internal.example"
	if got := d.Evaluate(e); len(got) != 1 {
		t.Errorf("custom suffix should match, got %d", len(got))
	}
}

func TestWeightTransferDetector_SuffixMatching(t *testing.T) {
	d := NewWeightTransferDetector(nil)

	// Test exact match
	e := weightTransferBaseFlowEvent()
	e.SNI = "huggingface.co"
	if got := d.Evaluate(e); len(got) != 1 {
		t.Errorf("exact match should fire, got %d", len(got))
	}

	// Test subdomain match
	e.SNI = "cdn-lfs.huggingface.co"
	if got := d.Evaluate(e); len(got) != 1 {
		t.Errorf("subdomain match should fire, got %d", len(got))
	}

	// Test no match for prefix
	e.SNI = "huggingface.co.evil.example"
	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("prefix match should not fire, got %d", len(got))
	}
}

func TestWeightTransferDetector_IsPure(t *testing.T) {
	d := NewWeightTransferDetector(nil)

	e := weightTransferBaseFlowEvent()

	a := d.Evaluate(e)
	b := d.Evaluate(e)

	if len(a) != len(b) {
		t.Fatalf("non-deterministic: %d then %d signals", len(a), len(b))
	}
	if len(a) > 0 && a[0].Reason != b[0].Reason {
		t.Errorf("non-deterministic reason: %q then %q", a[0].Reason, b[0].Reason)
	}
	if e.SNI != "huggingface.co" {
		t.Error("Evaluate mutated the event")
	}
}

func TestWeightTransferDetector_Suppression(t *testing.T) {
	d := NewWeightTransferDetector(nil)

	// Test that the detector has the suppression hook
	// WeightTransferDetector doesn't implement ShouldSuppressDeviceClass
	// because it's a replication-required signal that applies to all device classes
	// The risk engine handles class weighting
	_ = d
}

func TestWeightTransferDetector_CustomSuffixesReplaceDefaults(t *testing.T) {
	d := NewWeightTransferDetector([]string{"models.internal.example"})

	e := weightTransferBaseFlowEvent()
	e.SNI = "huggingface.co"
	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("default suffix should not match when custom suffixes supplied, got %d", len(got))
	}

	e.SNI = "models.internal.example"
	if got := d.Evaluate(e); len(got) != 1 {
		t.Errorf("custom suffix should match, got %d", len(got))
	}
}
