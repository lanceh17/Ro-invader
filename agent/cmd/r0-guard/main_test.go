package main

import (
	"context"
	"encoding/json"
	"errors"
	"html"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
	"github.com/lanceh17/Ro-invader/agent/internal/feeds"
	"github.com/lanceh17/Ro-invader/agent/internal/ingest/router"
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
	qf := quarantineFunc(newDeviceTable(inv, nil), risk.New(), nil)
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
	qf = quarantineFunc(newDeviceTable(inv, nil), nil, nil)
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

	qf := quarantineFunc(newDeviceTable(inv, nil), eng, nil)
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

	qf := quarantineFunc(newDeviceTable(inv, nil), eng, nil)
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

	qf := quarantineFunc(newDeviceTable(inv, nil), eng, exc)
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
	recordIOCBlock(audit, newDeviceTable(inv, nil), store, ev)
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

// --- router-backed device table ---------------------------------------------

// stubRouterSource is a router.Source served from a fixture, so the wiring can
// be exercised with no router on the network. It is the same seam the router
// package's own tests use.
type stubRouterSource struct {
	name   string
	leases []router.Lease
	err    error
}

func (s *stubRouterSource) Name() string { return s.name }

func (s *stubRouterSource) Leases(context.Context) ([]router.Lease, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.leases, nil
}

// mustMAC parses a hardware address for comparison in assertions.
func mustMAC(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC(s)
	if err != nil {
		t.Fatalf("ParseMAC(%q): %v", s, err)
	}
	return mac
}

// twoDeviceInventory is a static table with one classified device and one
// that is only an address.
func twoDeviceInventory(t *testing.T) *inventory.Inventory {
	t.Helper()
	inv, err := inventory.Parse([]byte(`[
		{"mac":"aa:bb:cc:dd:ee:01","ips":["192.168.1.50"],"class":"camera","vendor":"Hikvision"},
		{"mac":"aa:bb:cc:dd:ee:02","ips":["192.168.1.51"]}
	]`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return inv
}

// mustRouterClient builds a Client over src and performs one poll, so a test
// starts from a table the router has already filled.
func mustRouterClient(t *testing.T, src router.Source) *router.Client {
	t.Helper()
	c, err := router.New(router.Config{
		BaseURL: "http://192.168.1.1",
		Sources: []router.Source{src},
	})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	if err := c.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	return c
}

// routerSourcesFor runs the two build steps a serve run performs, so a test
// exercises the same order an operator's flags go through.
func routerSourcesFor(list string, cfg router.Config) ([]router.Source, []string, error) {
	names, err := parseRouterList(list)
	if err != nil {
		return nil, nil, err
	}
	return buildRouterSources(names, cfg)
}

func TestBuildRouterSourcesParsesAndDedupes(t *testing.T) {
	cfg := router.Config{
		BaseURL:  "http://192.168.1.1",
		Username: "root",
		Token:    "key",
		Password: "secret",
	}
	sources, skipped, err := routerSourcesFor("openwrt, OPNsense, openwrt", cfg)
	if err != nil {
		t.Fatalf("routerSourcesFor: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("skipped = %v, want none", skipped)
	}
	names := make([]string, len(sources))
	for i, s := range sources {
		names[i] = s.Name()
	}
	want := []string{"openwrt", "opnsense"}
	if len(names) != len(want) {
		t.Fatalf("got %d sources (%v), want %d", len(names), names, len(want))
	}
	for i, w := range want {
		if names[i] != w {
			t.Errorf("sources[%d] = %q, want %q", i, names[i], w)
		}
	}
}

// TestBuildRouterSourcesSkipsKeyedBackendsWithoutKey pins the credential
// rule to the one buildPullers already follows for a missing Auth-Key: a
// backend that needs a key and did not get one is skipped and reported, not a
// failure. OpenWrt authenticates with a username and password, so it is never
// skipped for anything.
func TestBuildRouterSourcesSkipsKeyedBackendsWithoutKey(t *testing.T) {
	sources, skipped, err := routerSourcesFor("openwrt,vyos,opnsense", router.Config{
		BaseURL:  "http://192.168.1.1",
		Username: "root",
	})
	if err != nil {
		t.Fatalf("routerSourcesFor: %v", err)
	}
	if len(sources) != 1 || sources[0].Name() != "openwrt" {
		t.Fatalf("got %d sources, want 1 [openwrt]", len(sources))
	}
	if len(skipped) != 2 || skipped[0] != "vyos" || skipped[1] != "opnsense" {
		t.Fatalf("skipped = %v, want [vyos opnsense]", skipped)
	}
}

// TestBuildRouterSourcesMissingCredentialForOneBackendIsAnError is the other
// half of the rule. A key is skippable because another backend may still
// work; a username or an API secret with nothing else to fall back on is a
// misconfiguration, and starting a poll loop that can only fail every cycle
// would be worse than refusing.
func TestBuildRouterSourcesMissingCredentialForOneBackendIsAnError(t *testing.T) {
	_, _, err := routerSourcesFor("openwrt", router.Config{BaseURL: "http://192.168.1.1"})
	if err == nil {
		t.Fatal("openwrt without a username was accepted")
	}
	if !strings.Contains(err.Error(), "openwrt") || !strings.Contains(err.Error(), "Username") {
		t.Errorf("error %q should name the backend and the missing field", err)
	}

	_, _, err = routerSourcesFor("opnsense", router.Config{
		BaseURL: "http://192.168.1.1",
		Token:   "key",
	})
	if err == nil {
		t.Fatal("opnsense without an API secret was accepted")
	}
	if !strings.Contains(err.Error(), "secret") {
		t.Errorf("error %q should name the missing secret", err)
	}
}

func TestParseRouterListUnknownRouterFails(t *testing.T) {
	_, err := parseRouterList("bogus")
	if err == nil {
		t.Fatal("unknown router backend was accepted")
	}
	msg := err.Error()
	for _, want := range []string{"unknown router", "openwrt", "vyos", "opnsense"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q should mention %q", msg, want)
		}
	}
}

// TestParseRouterListEmptyIsNothing: the default has to mean "off", not "a
// backend named by the empty string".
func TestParseRouterListEmptyIsNothing(t *testing.T) {
	for _, list := range []string{"", "   ", ",,"} {
		names, err := parseRouterList(list)
		if err != nil || len(names) != 0 {
			t.Errorf("parseRouterList(%q) = (%v, %v), want (0, nil)", list, names, err)
		}
	}
}

// TestRouterAPIKeyFallsBackToEnv: the flag wins so an operator can override an
// inherited key, and R0_ROUTER_KEY is what keeps the key off the command line
// when there is nothing to override.
func TestRouterAPIKeyFallsBackToEnv(t *testing.T) {
	t.Setenv(routerKeyEnv, "")
	if got := routerAPIKey(""); got != "" {
		t.Errorf("routerAPIKey(\"\") with no env = %q, want empty", got)
	}

	t.Setenv(routerKeyEnv, "env-key")
	if got := routerAPIKey(""); got != "env-key" {
		t.Errorf("routerAPIKey(\"\") = %q with %s set, want env-key", got, routerKeyEnv)
	}
	if got := routerAPIKey("flag-key"); got != "flag-key" {
		t.Errorf("routerAPIKey(\"flag-key\") = %q, want flag-key (flag takes precedence)", got)
	}

	// The fallback has to reach the backend, not just the helper.
	sources, skipped, err := routerSourcesFor("vyos", router.Config{
		BaseURL: "http://192.168.1.1",
		Token:   routerAPIKey(""),
	})
	if err != nil {
		t.Fatalf("routerSourcesFor: %v", err)
	}
	if len(skipped) != 0 || len(sources) != 1 || sources[0].Name() != "vyos" {
		t.Fatalf("env fallback did not reach the backend: %d sources, skipped %v", len(sources), skipped)
	}
}

func TestRunServeRejectsUnknownRouter(t *testing.T) {
	err := runServe([]string{"-portal", "192.168.1.1", "-router", "bogus"})
	if err == nil {
		t.Fatal("runServe accepted unknown router backend")
	}
	if !strings.Contains(err.Error(), "unknown router") {
		t.Errorf("error %q should say 'unknown router'", err)
	}
	for _, want := range []string{"openwrt", "vyos", "opnsense"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should name the valid backend %q", err, want)
		}
	}
}

func TestRunServeRequiresRouterURL(t *testing.T) {
	err := runServe([]string{"-portal", "192.168.1.1", "-router", "openwrt", "-router-user", "root"})
	if err == nil {
		t.Fatal("runServe accepted -router with no -router-url")
	}
	if !strings.Contains(err.Error(), "-router-url") {
		t.Errorf("error %q should mention -router-url", err)
	}

	// Blank counts as absent: a flag passed with an empty value is the same
	// misconfiguration as one never passed.
	err = runServe([]string{"-portal", "192.168.1.1", "-router", "openwrt", "-router-url", "  "})
	if err == nil || !strings.Contains(err.Error(), "-router-url") {
		t.Errorf("a whitespace -router-url was accepted (err = %v)", err)
	}
}

func TestRunServeRejectsNonPositiveRouterInterval(t *testing.T) {
	args := []string{
		"-portal", "192.168.1.1",
		"-router", "openwrt",
		"-router-url", "http://192.168.1.1",
		"-router-user", "root",
	}
	err := runServe(append(args, "-router-interval", "0"))
	if err == nil {
		t.Fatal("runServe accepted non-positive router-interval")
	}
	if !strings.Contains(err.Error(), "-router-interval") {
		t.Errorf("error %q should mention -router-interval", err)
	}
	err = runServe(append(args, "-router-interval", "-5m"))
	if err == nil || !strings.Contains(err.Error(), "-router-interval") {
		t.Errorf("runServe accepted a negative router-interval (err = %v)", err)
	}
}

// TestRunServeRouterValidationPrecedesBind: every -router rejection has to
// happen before a socket is taken, so that a typo costs a line on the
// operator's terminal rather than a half-started daemon holding :53 and :80.
//
// :80 is named explicitly, and the run is bounded by a timeout because the
// failure this guards against is exactly the one where validation has moved
// past the bind and the daemon sits there serving instead of returning.
func TestRunServeRouterValidationPrecedesBind(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"unknown backend", []string{"-router", "bogus"}, "unknown router"},
		{"missing url", []string{"-router", "openwrt", "-router-user", "root"}, "-router-url"},
		{"bad interval", []string{
			"-router", "openwrt",
			"-router-url", "http://192.168.1.1",
			"-router-user", "root",
			"-router-interval", "0",
		}, "-router-interval"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"-portal", "192.168.1.1", "-portal-http", ":80", "-listen", "127.0.0.1:0"}, tc.args...)

			done := make(chan error, 1)
			go func() { done <- runServe(args) }()

			select {
			case err := <-done:
				if err == nil {
					t.Fatal("runServe returned nil; the flags should have been rejected")
				}
				if !strings.Contains(err.Error(), tc.want) {
					t.Errorf("error %q should mention %q", err, tc.want)
				}
				if strings.Contains(err.Error(), "portal http") {
					t.Errorf("error %q came from binding the portal, so validation ran after the bind", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("runServe did not return: validation happened after the socket bind")
			}
		})
	}
}

// TestDeviceTablePrefersRouterForAttribution is the precedence rule stated as
// a test: where the router and the file disagree about an address, the router
// wins. The file is stale by definition in that situation -- a lease moved and
// nobody regenerated it -- and trusting it is how the previous holder gets
// quarantined for the current one's traffic.
func TestDeviceTablePrefersRouterForAttribution(t *testing.T) {
	inv := twoDeviceInventory(t)
	rtr := mustRouterClient(t, &stubRouterSource{
		name: "openwrt",
		leases: []router.Lease{
			{MAC: mustMAC(t, "11:22:33:44:55:66"), IP: netip.MustParseAddr(testDeviceIP), Hostname: "newcomer"},
		},
	})
	table := newDeviceTable(inv, rtr)

	mac, ok := table.MACFor(netip.MustParseAddr(testDeviceIP))
	if !ok {
		t.Fatal("address is not attributed at all")
	}
	if mac.String() != "11:22:33:44:55:66" {
		t.Errorf("MACFor = %s, want the router's 11:22:33:44:55:66 (static file said aa:bb:cc:dd:ee:01)", mac)
	}

	// The static inventory is a fallback, not a replacement: an address the
	// router has not mentioned still resolves while the table is filling.
	mac, ok = table.MACFor(netip.MustParseAddr("192.168.1.51"))
	if !ok || mac.String() != "aa:bb:cc:dd:ee:02" {
		t.Errorf("MACFor(192.168.1.51) = %s, %v; want the static entry aa:bb:cc:dd:ee:02", mac, ok)
	}

	// And nothing invents a device for an address neither source knows.
	if _, ok := table.MACFor(netip.MustParseAddr("192.168.1.99")); ok {
		t.Error("an unknown address was attributed")
	}
}

// TestDeviceTableClassifiesFromInventory: the router says which device, the
// file says what kind of device it is, and the score depends on the second.
func TestDeviceTableClassifiesFromInventory(t *testing.T) {
	inv := twoDeviceInventory(t)
	rtr := mustRouterClient(t, &stubRouterSource{
		name: "openwrt",
		leases: []router.Lease{
			{MAC: mustMAC(t, "11:22:33:44:55:66"), IP: netip.MustParseAddr(testDeviceIP)},
			{MAC: mustMAC(t, "aa:bb:cc:dd:ee:01"), IP: netip.MustParseAddr("192.168.1.90")},
		},
	})
	table := newDeviceTable(inv, rtr)

	// Known to the file: the class and vendor come from the file, even though
	// the router is what placed the device at this address.
	dev, ok := table.Get(mustMAC(t, "aa:bb:cc:dd:ee:01"))
	if !ok {
		t.Fatal("a device named by both sources was not found")
	}
	if dev.Class != core.ClassCamera || dev.Vendor != "Hikvision" {
		t.Errorf("class = %q vendor = %q, want camera/Hikvision from the static inventory", dev.Class, dev.Vendor)
	}

	// Known only to the router: reported, but classified as unknown rather than
	// guessed at, because a guess here would move a risk score.
	dev, ok = table.Get(mustMAC(t, "11:22:33:44:55:66"))
	if !ok {
		t.Fatal("a router-discovered device was not found")
	}
	if dev.Class != core.ClassUnknown {
		t.Errorf("router-only class = %q, want unknown", dev.Class)
	}
}

// --- a device only the router knows -----------------------------------------
//
// Containment and release are enforced in two different packages, by one
// lookup each against the same table, and the fixtures below are built from
// the real deviceTable, the real portal handler and a real release store
// rather than from those pieces separately. Testing them apart would pass with
// either one broken.

const (
	// routerOnlyMAC and routerOnlyIP name a device the static inventory has
	// never heard of. twoDeviceInventory holds .50 and .51 and no others, so
	// this address and this MAC belong to the router alone.
	routerOnlyMAC = "11:22:33:44:55:66"
	routerOnlyIP  = "192.168.1.77"
)

// routerOnlyEnv is a daemon whose device table holds one device purely because
// the router said so, together with everything the portal needs to be a real
// portal: an engine that has flagged it, a release store backed by a file, and
// an audit log.
type routerOnlyEnv struct {
	table   *deviceTable
	eng     *risk.Engine
	exc     *portal.Exceptions
	aud     *portal.Audit
	auditP  string
	clk     *testClock
	mac     net.HardwareAddr
	src     *stubRouterSource
	rtr     *router.Client
	handler http.Handler
}

// newRouterOnlyEnv wires it. The signals are observed at the clock's own time
// so the engine's decay is neutral; the predicate and the portal evaluate at
// different clocks by design, and the fixture must not depend on that gap.
func newRouterOnlyEnv(t *testing.T) *routerOnlyEnv {
	t.Helper()
	src := &stubRouterSource{
		name:   "openwrt",
		leases: []router.Lease{{MAC: mustMAC(t, routerOnlyMAC), IP: netip.MustParseAddr(routerOnlyIP)}},
	}
	rtr := mustRouterClient(t, src)
	clk := &testClock{t: time.Now()}
	mac := mustMAC(t, routerOnlyMAC)

	eng := risk.New()
	for i := 0; i < 4; i++ {
		eng.Observe(withMAC(mkSignal(core.SignalModelHostOnIoT, core.SignalReplicationRequired, 20, 0.6), mac), clk.t)
		eng.Observe(withMAC(mkSignal(core.SignalDNSDrift, core.SignalReplicationRequired, 25, 0.5), mac), clk.t)
	}

	dir := t.TempDir()
	exc, err := portal.NewExceptions(filepath.Join(dir, "state.json"), clk.now)
	if err != nil {
		t.Fatalf("NewExceptions: %v", err)
	}
	auditP := filepath.Join(dir, "audit.jsonl")
	aud := portal.NewAudit(auditP, clk.now)
	// Windows keeps an open handle exclusive; without this the TempDir
	// cleanup fails while the log file is still open.
	t.Cleanup(func() { _ = aud.Close() })

	e := &routerOnlyEnv{
		table:  newDeviceTable(twoDeviceInventory(t), rtr),
		eng:    eng,
		exc:    exc,
		aud:    aud,
		auditP: auditP,
		clk:    clk,
		mac:    mac,
		src:    src,
		rtr:    rtr,
	}
	e.handler = e.portalFor(t, e.table)
	return e
}

// portalFor builds a portal over any table, sharing this run's engine, release
// store and audit log. It is what lets a test model the daemon coming back up
// against a different device table without losing the operator's decisions.
func (e *routerOnlyEnv) portalFor(t *testing.T, table *deviceTable) http.Handler {
	t.Helper()
	srv, err := portal.New(portal.Config{
		Engine:       e.eng,
		DeviceSource: table,
		Garden:       []string{"support.example"},
		Exceptions:   e.exc,
		Audit:        e.aud,
		Token:        "test-token",
		ReleaseTTL:   time.Hour,
		Now:          e.clk.now,
	})
	if err != nil {
		t.Fatalf("portal.New: %v", err)
	}
	return srv.Handler()
}

func (e *routerOnlyEnv) get(t *testing.T, ip string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = net.JoinHostPort(ip, "54321")
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}

func (e *routerOnlyEnv) release(t *testing.T, ip string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/release",
		strings.NewReader(url.Values{"token": {"test-token"}, "ip": {ip}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = net.JoinHostPort("192.168.1.60", "5555")
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}

// contained is the resolver's verdict for ip on this run.
func (e *routerOnlyEnv) contained(ip string) bool {
	return quarantineFunc(e.table, e.eng, e.exc)(netip.MustParseAddr(ip))
}

// readAuditEntries parses the JSON Lines log the portal wrote. The portal
// package has an identical reader, but it is a test helper in another package
// and reaching across for it would mean exporting test-only code to make a
// test possible.
func readAuditEntries(t *testing.T, path string) []portal.AuditEntry {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	var out []portal.AuditEntry
	for i, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var e portal.AuditEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("audit line %d is not valid JSON: %v", i, err)
		}
		out = append(out, e)
	}
	return out
}

// TestQuarantineFuncContainsRouterOnlyDevice is the positive case for a device
// no file names, and it was the negative one until the portal began reading
// this same table. Refusing it was correct while the portal had no page for it:
// a contained device whose lookups resolve to a page saying it is not
// contained, with no button anywhere to change that, is worse than an
// uncontained one. Now that the page is built from the table the two are no
// longer separable, and the rule is simply whether the device can be described.
func TestQuarantineFuncContainsRouterOnlyDevice(t *testing.T) {
	e := newRouterOnlyEnv(t)

	// Precondition, or the test passes vacuously if the predicate starts
	// refusing everything.
	dev, ok := e.table.Get(e.mac)
	if !ok {
		t.Fatal("precondition: the router-only device is not in the table")
	}
	if tier := e.eng.Evaluate(dev, time.Now()).Tier; tier != core.ContainmentQuarantined {
		t.Fatalf("precondition: tier = %v, want quarantined", tier)
	}

	if !e.contained(routerOnlyIP) {
		t.Error("a corroborated, over-threshold router-only device was not contained")
	}

	// The rule is not "router only" -- it is "describable". The same signals
	// against a device the file names is contained exactly as it always was,
	// which is what shows the change widened containment rather than moved it.
	static := mustMAC(t, "aa:bb:cc:dd:ee:02")
	for i := 0; i < 4; i++ {
		e.eng.Observe(withMAC(mkSignal(core.SignalModelHostOnIoT, core.SignalReplicationRequired, 20, 0.6), static), e.clk.t)
		e.eng.Observe(withMAC(mkSignal(core.SignalDNSDrift, core.SignalReplicationRequired, 25, 0.5), static), e.clk.t)
	}
	if !e.contained("192.168.1.51") {
		t.Error("a device named by the inventory was not contained")
	}
}

// TestRouterOnlyDevicePortalPageIsReleasable: the page that device is
// redirected to has to name it, tell it what happened, and offer the button --
// with no class and no vendor to show, because the router publishes neither.
func TestRouterOnlyDevicePortalPageIsReleasable(t *testing.T) {
	e := newRouterOnlyEnv(t)
	rec := e.get(t, routerOnlyIP)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s), want 200", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		routerOnlyMAC,                     // it is named
		`is <strong>quarantined</strong>`, // and told it is contained
		`action="/release"`,               // and handed the button
		`name="token"`,
		// Nothing published about it, stated rather than left blank, and the
		// reason for that stated with it.
		"Unknown (none published)",
		"Unclassified",
		"No vendor or class has been published",
		// The generic steps, because there is no vendor to match on. The page
		// is HTML, so the rendered step is the escaped form.
		html.EscapeString(portal.DefaultRemediation[0]),
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
}

// TestRouterOnlyDeviceReleaseEndToEnd: the release an operator clicks is
// persisted, audited, honoured by the resolver on its next query, and lapses on
// its own so the device is contained again with nobody acting.
func TestRouterOnlyDeviceReleaseEndToEnd(t *testing.T) {
	e := newRouterOnlyEnv(t)

	rec := e.release(t, routerOnlyIP)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("release status = %d (%s), want 303", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/?released=1" {
		t.Errorf("Location = %q, want /?released=1", loc)
	}

	exc, ok := e.exc.Active(e.mac)
	if !ok {
		t.Fatal("release did not become active for a router-only device")
	}
	if exc.By != "portal" || !exc.ExpiresAt.Equal(e.clk.t.Add(time.Hour)) {
		t.Errorf("exception = %+v, want by=portal, expiry now+1h", exc)
	}

	entries := readAuditEntries(t, e.auditP)
	if len(entries) != 1 {
		t.Fatalf("audit has %d entries, want 1", len(entries))
	}
	a := entries[0]
	if a.Action != "release" || a.MAC != e.mac.String() || a.By != "portal" {
		t.Errorf("audit entry = %+v, want release for %s by portal", a, e.mac)
	}
	if a.Tier != "quarantined" || a.Score <= risk.DefaultConfig().QuarantineThreshold {
		t.Errorf("audit assessment = score %v tier %q, want the state that justified release", a.Score, a.Tier)
	}
	if a.Expires == nil || !a.Expires.Equal(exc.ExpiresAt) {
		t.Errorf("audit expiry = %v, want %v", a.Expires, exc.ExpiresAt)
	}

	// Honoured immediately: the resolver consults the same store on every query.
	if e.contained(routerOnlyIP) {
		t.Error("the device is still contained after its release")
	}
	if !strings.Contains(e.get(t, routerOnlyIP).Body.String(), "Released by portal") {
		t.Error("the released device's own page does not show the release")
	}

	// And time-boxed: reversible, but not permanent.
	e.clk.t = e.clk.t.Add(2 * time.Hour)
	if !e.contained(routerOnlyIP) {
		t.Error("an expired release did not re-contain the router-only device")
	}
}

// TestReleaseSurvivesTheDeviceLeavingTheTable is the guarantee that makes it
// safe to contain a device the portal learned about from a router. The release
// is keyed on the MAC, which does not change when the table is rebuilt, so a
// device that drops out of the table and comes back is still under the
// operator's decision and is not re-contained until that decision lapses.
//
// The device is made to disappear by starting from an empty router rather than
// by a poll: router.Client.merge never removes what it learned, by design, so a
// rebuilt table is the only way this state is reached -- and it is exactly what
// a restart against an unresponsive router looks like.
func TestReleaseSurvivesTheDeviceLeavingTheTable(t *testing.T) {
	e := newRouterOnlyEnv(t)
	if rec := e.release(t, routerOnlyIP); rec.Code != http.StatusSeeOther {
		t.Fatalf("release status = %d (%s), want 303", rec.Code, rec.Body.String())
	}

	blank := newDeviceTable(twoDeviceInventory(t), mustRouterClient(t, &stubRouterSource{name: "openwrt"}))
	if _, ok := blank.Get(e.mac); ok {
		t.Fatal("precondition: a router that reported nothing still describes the device")
	}
	e.handler = e.portalFor(t, blank)

	// The decision outlives the table it was made against.
	if _, ok := e.exc.Active(e.mac); !ok {
		t.Error("the release did not survive the device leaving the table")
	}
	if e.contained(routerOnlyIP) {
		t.Error("an address no table resolves was contained")
	}
	if body := e.get(t, routerOnlyIP).Body.String(); !strings.Contains(body, "No record") {
		t.Error("the page did not report that the device table could not name the address")
	}

	// The device comes back, into the same store and the same run.
	if err := e.rtr.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if _, ok := e.table.Get(e.mac); !ok {
		t.Fatalf("precondition: the device did not return to the table (Len = %d)", e.rtr.Len())
	}
	if e.contained(routerOnlyIP) {
		t.Error("a device under an unexpired release was re-contained when it returned to the table")
	}
	e.handler = e.portalFor(t, e.table)
	if !strings.Contains(e.get(t, routerOnlyIP).Body.String(), "Released by portal") {
		t.Error("the returning device's page lost its release banner")
	}

	e.clk.t = e.clk.t.Add(2 * time.Hour)
	if !e.contained(routerOnlyIP) {
		t.Error("an expired release did not re-contain the device after it returned")
	}
}

// TestPortalConcurrentWithRouterPoll is the test that fails under -race if the
// portal reaches anything the poll loop mutates without a lock.
//
// This is the ordinary shape of a serve run: an operator loading a device's
// status page at the moment a poll lands. Everything on that path is either
// immutable after construction or internally locked -- deviceTable is written
// once and never reassigned, *inventory.Inventory is read-only after Load, and
// router.Client holds an RWMutex across exactly the maps the portal reads -- so
// a race here would mean one of those claims is false. CI runs the suite with
// -race, which is where that is actually enforced.
func TestPortalConcurrentWithRouterPoll(t *testing.T) {
	e := newRouterOnlyEnv(t)
	stop := make(chan struct{})
	var wg sync.WaitGroup

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
				// Every handler path a contained device's browser can take:
				// the page itself, and the lookup the release button's page
				// already performed.
				if rec := e.get(t, routerOnlyIP); rec.Code != http.StatusOK {
					t.Errorf("status page = %d during a poll", rec.Code)
					return
				}
				if _, ok := e.table.Get(e.mac); !ok {
					t.Error("the device vanished from the table during a poll")
					return
				}
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
			if err := e.rtr.Poll(context.Background()); err != nil {
				t.Errorf("Poll: %v", err)
				return
			}
		}
	}()

	// Hold the writers against the readers long enough for them to overlap.
	for i := 0; i < 500; i++ {
		if err := e.rtr.Poll(context.Background()); err != nil {
			t.Fatalf("Poll: %v", err)
		}
	}
	close(stop)
	wg.Wait()
}

// TestPollRouterKeepsLeasesAfterFailure: one failed refresh must not cost the
// table. A router that reboots mid-run is an ordinary event, and the
// alternative -- an inventory that blinks out for a cycle with no error
// anywhere to show for it -- blinds every detector downstream.
func TestPollRouterKeepsLeasesAfterFailure(t *testing.T) {
	src := &stubRouterSource{
		name:   "openwrt",
		leases: []router.Lease{{MAC: mustMAC(t, "11:22:33:44:55:66"), IP: netip.MustParseAddr(testDeviceIP)}},
	}
	rtr := mustRouterClient(t, src)
	if rtr.Len() != 1 {
		t.Fatalf("Len = %d, want 1", rtr.Len())
	}

	src.err = errors.New("router rebooting")
	pollRouter(context.Background(), rtr)

	if rtr.Len() != 1 {
		t.Errorf("Len = %d after a failed poll, want 1 (leases learned earlier stay)", rtr.Len())
	}
	if _, ok := rtr.MACFor(netip.MustParseAddr(testDeviceIP)); !ok {
		t.Error("attribution was lost after a failed poll")
	}
}

// TestPollRouterSilentOnShutdown: the loop is stopped by canceling its
// context, and that is not a fault to print.
func TestPollRouterSilentOnShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rtr := mustRouterClient(t, &stubRouterSource{name: "vyos"})
	pollRouter(ctx, rtr) // must not panic and must not exit
	if rtr.Len() != 0 {
		t.Errorf("Len = %d on a canceled poll, want 0", rtr.Len())
	}
}
