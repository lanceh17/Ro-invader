package detect

import (
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

var driftMAC = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x07}

// dnsEvent builds an attributed DNS query event.
func dnsEvent(name string) core.NormalizedEvent {
	return core.NormalizedEvent{
		Kind:      core.EventDNSQuery,
		Src:       core.Endpoint{IP: netip.MustParseAddr("192.168.1.50")},
		QueryName: name,
		DeviceMAC: driftMAC,
	}
}

// primeBaseline feeds n queries to an ordinary domain so the device has an
// established baseline without touching any watched category.
func primeBaseline(d *DNSDriftDetector, n int) {
	for i := 0; i < n; i++ {
		d.Evaluate(dnsEvent("ordinary.example"))
	}
}

func TestDNSDriftNoBaselineDoesNotFire(t *testing.T) {
	// A device seen for the first time cannot deviate from a baseline that
	// does not exist; that is R8's job, not R7's.
	d := NewDNSDriftDetector(100, nil)
	if sigs := d.Evaluate(dnsEvent("cdn-lfs.huggingface.co")); len(sigs) != 0 {
		t.Errorf("first-ever query fired with no baseline: %v", sigs)
	}
}

func TestDNSDriftFiresOnFirstContactAfterBaseline(t *testing.T) {
	d := NewDNSDriftDetector(10, nil)
	primeBaseline(d, 10)

	sigs := d.Evaluate(dnsEvent("cdn-lfs.huggingface.co"))
	if len(sigs) != 1 {
		t.Fatalf("got %d signals, want 1", len(sigs))
	}
	s := sigs[0]
	if s.Kind != core.SignalDNSDrift {
		t.Errorf("Kind = %v, want SignalDNSDrift", s.Kind)
	}
	if s.Class != core.SignalReplicationRequired {
		t.Errorf("Class = %v, want SignalReplicationRequired", s.Class)
	}
	if s.DeviceMAC.String() != driftMAC.String() {
		t.Errorf("DeviceMAC = %v, want %v", s.DeviceMAC, driftMAC)
	}
	if s.Weight <= 0 || s.Confidence <= 0 {
		t.Errorf("weight/confidence must be positive, got %v/%v", s.Weight, s.Confidence)
	}
}

func TestDNSDriftSecondContactDoesNotFire(t *testing.T) {
	// Only the FIRST contact is a state transition. The second is baseline.
	d := NewDNSDriftDetector(10, nil)
	primeBaseline(d, 10)

	d.Evaluate(dnsEvent("cdn-lfs.huggingface.co"))
	if sigs := d.Evaluate(dnsEvent("cdn-lfs.huggingface.co")); len(sigs) != 0 {
		t.Errorf("second contact fired: %v", sigs)
	}
	if sigs := d.Evaluate(dnsEvent("registry.ollama.ai")); len(sigs) != 0 {
		t.Errorf("same category, different host, fired again: %v", sigs)
	}
}

func TestDNSDriftOtherCategoryCanStillFire(t *testing.T) {
	// A different category is a different first contact.
	d := NewDNSDriftDetector(10, map[string][]string{
		"model_host": {"huggingface.co"},
		"registry":   {"registry.ollama.ai"},
	})
	primeBaseline(d, 10)

	if len(d.Evaluate(dnsEvent("huggingface.co"))) != 1 {
		t.Error("first model_host contact did not fire")
	}
	if len(d.Evaluate(dnsEvent("registry.ollama.ai"))) != 1 {
		t.Error("first registry contact did not fire")
	}
}

func TestDNSDriftSuffixMatch(t *testing.T) {
	d := NewDNSDriftDetector(1, nil)
	primeBaseline(d, 1)
	if len(d.Evaluate(dnsEvent("patch.cdn-lfs.huggingface.co"))) != 1 {
		t.Error("a subdomain of a watched suffix must fire")
	}
}

func TestDNSDriftNonCategoryAdvancesBaseline(t *testing.T) {
	// Ordinary queries still count toward the baseline; a baseline measures how
	// much we have seen, not how anomalous it has been.
	d := NewDNSDriftDetector(5, nil)
	for i := 0; i < 5; i++ {
		if sigs := d.Evaluate(dnsEvent("ordinary.example")); len(sigs) != 0 {
			t.Fatalf("ordinary query fired: %v", sigs)
		}
	}
	if got := d.Baseline(core.Device{MAC: driftMAC}); got != 5 {
		t.Errorf("Baseline = %d, want 5", got)
	}
	if len(d.Evaluate(dnsEvent("huggingface.co"))) != 1 {
		t.Error("a category query after a 5-query baseline must fire")
	}
}

// TestDNSDriftTooEarlyContactNeverFires is the subtle case: the first contact
// happens before the baseline is established, so it does not fire, and because
// the contact already happened it is no longer "first-ever" later.
func TestDNSDriftTooEarlyContactNeverFires(t *testing.T) {
	d := NewDNSDriftDetector(10, nil)
	if sigs := d.Evaluate(dnsEvent("huggingface.co")); len(sigs) != 0 {
		t.Fatalf("fired with no baseline: %v", sigs)
	}
	primeBaseline(d, 50)
	if sigs := d.Evaluate(dnsEvent("huggingface.co")); len(sigs) != 0 {
		t.Errorf("fired on a later query to a category already contacted: %v", sigs)
	}
}

func TestDNSDriftRequiresDeviceMAC(t *testing.T) {
	d := NewDNSDriftDetector(1, nil)
	ev := dnsEvent("huggingface.co")
	ev.DeviceMAC = nil
	if sigs := d.Evaluate(ev); sigs != nil {
		t.Errorf("an unattributable event must produce nothing, got %v", sigs)
	}
}

func TestDNSDriftRequiresAName(t *testing.T) {
	d := NewDNSDriftDetector(1, nil)
	ev := dnsEvent("")
	if sigs := d.Evaluate(ev); sigs != nil {
		t.Errorf("a nameless event must produce nothing, got %v", sigs)
	}
}

func TestDNSDriftUsesSNIAsFallback(t *testing.T) {
	d := NewDNSDriftDetector(1, nil)
	primeBaseline(d, 1)
	ev := core.NormalizedEvent{
		Kind:      core.EventTLS,
		SNI:       "huggingface.co",
		DeviceMAC: driftMAC,
	}
	if len(d.Evaluate(ev)) != 1 {
		t.Error("SNI must be accepted as the contact host when no query name is present")
	}
}

func TestDNSDriftZeroMinBaselineUsesDefault(t *testing.T) {
	// A zero-valued detector would record a category contacted on the very
	// first query and then never fire. The constructor must not allow that.
	d := NewDNSDriftDetector(0, nil)
	if d.minBaseline != DefaultDNSDriftMinBaseline {
		t.Errorf("minBaseline = %d, want the default %d", d.minBaseline, DefaultDNSDriftMinBaseline)
	}
	// With the default of 100, one query must not fire.
	if sigs := d.Evaluate(dnsEvent("huggingface.co")); len(sigs) != 0 {
		t.Errorf("fired below the default baseline: %v", sigs)
	}
}

func TestDNSDriftCustomCategoriesReplaceDefaults(t *testing.T) {
	d := NewDNSDriftDetector(1, map[string][]string{"watch": {"watched.example"}})
	primeBaseline(d, 1)
	if len(d.Evaluate(dnsEvent("watched.example"))) != 1 {
		t.Error("a custom category must fire")
	}
	// The default model-host category is gone, not merged.
	if sigs := d.Evaluate(dnsEvent("huggingface.co")); len(sigs) != 0 {
		t.Errorf("the default category leaked into a custom configuration: %v", sigs)
	}
}

// TestDNSDriftIsConcurrentSafe exercises the mutex the way a live ingest loop
// would: many goroutines evaluating for the same and different devices. Run
// with -race in CI this is what proves the instance state is guarded.
func TestDNSDriftIsConcurrentSafe(t *testing.T) {
	d := NewDNSDriftDetector(1, nil)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				d.Evaluate(dnsEvent("huggingface.co"))
				d.Evaluate(dnsEvent("ordinary.example"))
			}
		}()
	}
	wg.Wait()
	// Exactly one first contact must have fired no matter the interleaving.
	// We cannot count signals from concurrent Evaluate calls directly, but the
	// category must be marked contacted and the baseline must be consistent.
	if got := d.Baseline(core.Device{MAC: driftMAC}); got != 8*50*2 {
		t.Errorf("Baseline = %d, want %d", got, 8*50*2)
	}
}

// TestDNSDriftInRegistryIsTheDNSDetector confirms the default set actually
// includes R7, because a registry that silently omits it would leave the
// resolver's primary signal unwired with no error anywhere.
func TestDNSDriftInRegistryIsTheDNSDetector(t *testing.T) {
	found := false
	for _, det := range All() {
		if det.Kind() == core.SignalDNSDrift {
			found = true
		}
	}
	if !found {
		t.Error("detect.All() does not include the R7 DNS drift detector")
	}
}
