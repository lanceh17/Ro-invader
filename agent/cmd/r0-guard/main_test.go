package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
	"github.com/lanceh17/Ro-invader/agent/internal/feeds"
	"github.com/lanceh17/Ro-invader/agent/internal/inventory"
	"github.com/lanceh17/Ro-invader/agent/internal/normalize"
	"github.com/lanceh17/Ro-invader/agent/internal/portal"
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
	qf := quarantineFunc(inv, risk.New(), nil)
	if qf(netip.MustParseAddr("192.168.1.99")) {
		t.Error("an unknown IP was contained")
	}
}

func TestQuarantineFuncNilInputsAreNotContained(t *testing.T) {
	inv := testInventory(t)
	qf := quarantineFunc(nil, risk.New(), nil)
	if qf(netip.MustParseAddr(testDeviceIP)) {
		t.Error("nil inventory must not contain")
	}
	qf = quarantineFunc(inv, nil, nil)
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

	qf := quarantineFunc(inv, eng, nil)
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

	qf := quarantineFunc(inv, eng, nil)
	if qf(netip.MustParseAddr(testDeviceIP)) {
		t.Error("a single signal kind was contained despite a high score; corroboration must gate containment")
	}
}

func withMAC(s core.Signal, mac net.HardwareAddr) core.Signal {
	s.DeviceMAC = mac
	return s
}

// testClock is a manually advanced clock for expiry tests.
type testClock struct{ t time.Time }

func (c *testClock) now() time.Time { return c.t }

// TestQuarantineFuncReleasedDeviceIsNotContained: an operator's time-boxed
// release overrides containment for exactly its duration; when it lapses the
// engine's tier applies again by itself, with no one acting on it. This is
// the SAFETY.md guarantee "reversible by a human, always" in both directions
// -- reversible, but not permanent.
func TestQuarantineFuncReleasedDeviceIsNotContained(t *testing.T) {
	inv := testInventory(t)
	mac := testMAC(t)
	eng := risk.New()
	now := time.Now()
	for i := 0; i < 3; i++ {
		eng.Observe(withMAC(mkSignal(core.SignalModelHostOnIoT, core.SignalReplicationRequired, 20, 0.6), mac), now)
		eng.Observe(withMAC(mkSignal(core.SignalDNSDrift, core.SignalReplicationRequired, 25, 0.5), mac), now)
	}

	clk := &testClock{t: now}
	exc, err := portal.NewExceptions("", clk.now)
	if err != nil {
		t.Fatalf("NewExceptions: %v", err)
	}
	ip := netip.MustParseAddr(testDeviceIP)

	qf := quarantineFunc(inv, eng, exc)
	if !qf(ip) {
		t.Fatal("precondition: fixture device is not contained")
	}
	if _, err := exc.Release(mac, "test", time.Hour); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if qf(ip) {
		t.Error("a released device is still contained")
	}
	clk.t = clk.t.Add(2 * time.Hour)
	if !qf(ip) {
		t.Error("an expired release did not re-contain the device")
	}
}

func TestBuildPullersParsesAndDedupes(t *testing.T) {
	pullers, skipped, err := buildPullers("threatfox, urlhaus, kev, threatfox", "test-key")
	if err != nil {
		t.Fatalf("buildPullers: %v", err)
	}
	if len(pullers) != 3 {
		t.Fatalf("got %d pullers, want 3", len(pullers))
	}
	if len(skipped) != 0 {
		t.Fatalf("skipped = %v, want none", skipped)
	}
	names := make([]string, len(pullers))
	for i, p := range pullers {
		names[i] = p.Name()
	}
	want := []string{"threatfox", "urlhaus", "kev"}
	for i, w := range want {
		if names[i] != w {
			t.Errorf("pullers[%d] = %q, want %q", i, names[i], w)
		}
	}
}

func TestBuildPullersSkipsKeyedFeedsWithoutKey(t *testing.T) {
	pullers, skipped, err := buildPullers("threatfox,urlhaus,kev", "")
	if err != nil {
		t.Fatalf("buildPullers: %v", err)
	}
	if len(pullers) != 1 || pullers[0].Name() != "kev" {
		t.Fatalf("got %d pullers (%v), want 1 [kev]", len(pullers), pullers)
	}
	if len(skipped) != 2 {
		t.Fatalf("skipped = %v, want [threatfox urlhaus]", skipped)
	}
	for _, s := range skipped {
		if s != "threatfox" && s != "urlhaus" {
			t.Errorf("unexpected skipped feed %q", s)
		}
	}
}

func TestBuildPullersUnknownFeedFails(t *testing.T) {
	_, _, err := buildPullers("bogus", "k")
	if err == nil {
		t.Fatal("unknown feed was accepted")
	}
	if !strings.Contains(err.Error(), "unknown feed") || !strings.Contains(err.Error(), "threatfox") || !strings.Contains(err.Error(), "urlhaus") || !strings.Contains(err.Error(), "kev") {
		t.Errorf("error %q should name the valid feeds", err)
	}
}

func TestBuildPullersEmptyListIsNothing(t *testing.T) {
	pullers, skipped, err := buildPullers("", "k")
	if err != nil || len(pullers) != 0 || len(skipped) != 0 {
		t.Errorf("buildPullers(\"\") = (%d, %d, %v), want (0, 0, nil)", len(pullers), len(skipped), err)
	}
	pullers, skipped, err = buildPullers("   ", "k")
	if err != nil || len(pullers) != 0 || len(skipped) != 0 {
		t.Errorf("buildPullers(whitespace) = (%d, %d, %v), want (0, 0, nil)", len(pullers), len(skipped), err)
	}
}

func TestFeedsAuthKeyFallsBack(t *testing.T) {
	t.Setenv("R0_ABUSECH_KEY", "")
	t.Setenv("R0_THREATFOX_KEY", "legacy-key")
	if got := feedsAuthKey(); got != "legacy-key" {
		t.Errorf("feedsAuthKey() = %q with R0_THREATFOX_KEY set, want legacy-key", got)
	}

	t.Setenv("R0_ABUSECH_KEY", "abusech-key")
	t.Setenv("R0_THREATFOX_KEY", "legacy-key")
	if got := feedsAuthKey(); got != "abusech-key" {
		t.Errorf("feedsAuthKey() = %q with both set, want abusech-key (precedence)", got)
	}
}

func TestRunServeRejectsUnknownFeed(t *testing.T) {
	// Validation happens before any bind, so no root/port required.
	err := runServe([]string{"-portal", "192.168.1.1", "-feeds", "bogus"})
	if err == nil {
		t.Fatal("runServe accepted unknown feed")
	}
	if !strings.Contains(err.Error(), "unknown feed") {
		t.Errorf("error %q should say 'unknown feed'", err)
	}
}

func TestRunServeRejectsNonPositiveFeedInterval(t *testing.T) {
	// kev requires no key, so the feed is enabled and interval validation runs.
	err := runServe([]string{"-portal", "192.168.1.1", "-feeds", "kev", "-feed-interval", "0"})
	if err == nil {
		t.Fatal("runServe accepted non-positive feed-interval")
	}
	if !strings.Contains(err.Error(), "feed-interval") {
		t.Errorf("error %q should mention feed-interval", err)
	}
	err = runServe([]string{"-portal", "192.168.1.1", "-feeds", "kev", "-ioc-ttl", "-1h"})
	if err == nil {
		t.Fatal("runServe accepted non-positive ioc-ttl")
	}
	if !strings.Contains(err.Error(), "ioc-ttl") {
		t.Errorf("error %q should mention ioc-ttl", err)
	}
}

func TestRecordIOCBlockWritesAuditWithProvenance(t *testing.T) {
	inv := testInventory(t)
	now := time.Now().Add(24 * time.Hour)

	store := normalize.NewStore(0)
	store.Replace("threatfox", []normalize.IoC{
		{Value: "c2.evil.example", Kind: feeds.KindDomain, Confidence: 75, Feeds: []string{"threatfox"}, Expires: now},
	})

	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	audit := portal.NewAudit(auditPath, func() time.Time { return time.Now() })
	t.Cleanup(func() { audit.Close() })

	ev := core.NormalizedEvent{
		Time:      time.Now(),
		Kind:      core.EventDNSQuery,
		Src:       core.Endpoint{IP: netip.MustParseAddr(testDeviceIP)},
		Dst:       core.Endpoint{Host: "c2.evil.example"},
		QueryName: "c2.evil.example",
	}
	recordIOCBlock(audit, inv, store, ev)
	audit.Close()

	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var entry portal.AuditEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		t.Fatalf("unmarshal audit: %v", err)
	}

	if entry.Action != "ioc-block" {
		t.Errorf("Action = %q, want ioc-block", entry.Action)
	}
	if entry.MAC == "" {
		t.Error("MAC is empty; inventory had the device")
	}
	if entry.Query != "c2.evil.example" {
		t.Errorf("Query = %q, want c2.evil.example", entry.Query)
	}
	if entry.Score != 0 {
		t.Errorf("Score = %v, want 0 (blocklist is not a device score)", entry.Score)
	}
	if entry.Tier != "" {
		t.Errorf("Tier = %q, want empty", entry.Tier)
	}
	if len(entry.Reasons) != 1 || !strings.Contains(entry.Reasons[0], "threatfox") || !strings.Contains(entry.Reasons[0], "confidence 75") {
		t.Errorf("Reasons = %v, want provenance with threatfox and confidence", entry.Reasons)
	}
}

const tinyThreatFoxFixture = `{
    "query_status": "ok",
    "data": [
        {"ioc": "c2.fixture.example", "ioc_type": "domain", "confidence_level": 80, "first_seen": "2026-10-17 12:00:00 UTC", "tags": ["mirai"]},
        {"ioc": "203.0.113.9:443", "ioc_type": "ip:port", "confidence_level": 50, "first_seen": "2026-10-17 12:00:00 UTC", "tags": null}
    ]
}`

func TestPullAllReplacesAndKeepsOnFailure(t *testing.T) {
	// A working pull refreshes the store.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.Header.Get("Auth-Key") != "test-key" {
			t.Errorf("Auth-Key = %q, want test-key", r.Header.Get("Auth-Key"))
		}
		w.Write([]byte(tinyThreatFoxFixture))
	}))
	t.Cleanup(srv.Close)

	p := feeds.NewThreatFox("test-key")
	p.Endpoint = srv.URL

	store := normalize.NewStore(0)
	ctx := context.Background()

	// First cycle: 2 items
	pullAll(ctx, []feeds.Puller{p}, store, time.Hour)
	if got := store.Count(time.Now()); got != 2 {
		t.Errorf("after first pull Count = %d, want 2", got)
	}
	if _, ok := store.Match("c2.fixture.example", time.Now()); !ok {
		t.Error("Match missing after first pull")
	}

	// Second cycle: endpoint returns 500. The previous snapshot must stay.
	srvBroke := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srvBroke.Close)

	pBroken := feeds.NewThreatFox("test-key")
	pBroken.Endpoint = srvBroke.URL
	pullAll(ctx, []feeds.Puller{pBroken}, store, time.Hour)
	if got := store.Count(time.Now()); got != 2 {
		t.Errorf("after failed pull Count = %d, want 2 (old snapshot kept)", got)
	}
	if _, ok := store.Match("c2.fixture.example", time.Now()); !ok {
		t.Error("Match missing after failed pull — old snapshot was lost")
	}
}
