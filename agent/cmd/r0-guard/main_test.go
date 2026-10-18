package main

import (
	"context"
	"encoding/json"
	"errors"
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
	dev, ok := table.Device(mustMAC(t, "aa:bb:cc:dd:ee:01"))
	if !ok {
		t.Fatal("a device named by both sources was not found")
	}
	if dev.Class != core.ClassCamera || dev.Vendor != "Hikvision" {
		t.Errorf("class = %q vendor = %q, want camera/Hikvision from the static inventory", dev.Class, dev.Vendor)
	}

	// Known only to the router: reported, but classified as unknown rather than
	// guessed at, because a guess here would move a risk score.
	dev, ok = table.Device(mustMAC(t, "11:22:33:44:55:66"))
	if !ok {
		t.Fatal("a router-discovered device was not found")
	}
	if dev.Class != core.ClassUnknown {
		t.Errorf("router-only class = %q, want unknown", dev.Class)
	}
}

// TestQuarantineFuncRouterOnlyDeviceIsNotContained is the load-bearing
// consequence of that asymmetry. The engine has this device well past the
// quarantine threshold with corroboration, the router attributes the address
// to it, and the containment predicate still says no -- because the portal,
// which is the only place a human can release a contained device, is built from
// the static inventory and has no page for this device at all.
//
// Containing it would redirect its lookups to a page saying it is not
// contained, with no button anywhere to change that.
func TestQuarantineFuncRouterOnlyDeviceIsNotContained(t *testing.T) {
	inv := twoDeviceInventory(t)
	rtr := mustRouterClient(t, &stubRouterSource{
		name: "openwrt",
		leases: []router.Lease{
			{MAC: mustMAC(t, "11:22:33:44:55:66"), IP: netip.MustParseAddr(testDeviceIP)},
		},
	})
	eng := risk.New()
	now := time.Now()
	routerMAC := mustMAC(t, "11:22:33:44:55:66")
	for i := 0; i < 4; i++ {
		eng.Observe(withMAC(mkSignal(core.SignalModelHostOnIoT, core.SignalReplicationRequired, 20, 0.6), routerMAC), now)
		eng.Observe(withMAC(mkSignal(core.SignalDNSDrift, core.SignalReplicationRequired, 25, 0.5), routerMAC), now)
	}

	table := newDeviceTable(inv, rtr)

	// Sanity: the fixture must really be over the line, or the test passes
	// vacuously if quarantineFunc refused everything.
	dev, ok := table.Device(routerMAC)
	if !ok {
		t.Fatal("precondition: the device is not in the table")
	}
	if tier := eng.Evaluate(dev, now).Tier; tier != core.ContainmentQuarantined {
		t.Fatalf("precondition: fixture device tier = %v, want quarantined", tier)
	}

	qf := quarantineFunc(table, eng, nil)
	if qf(netip.MustParseAddr(testDeviceIP)) {
		t.Error("a device the portal cannot release was contained")
	}

	// The same signals against a device the file does name is contained, so
	// the refusal above is about the missing record and not about the score.
	static := mustMAC(t, "aa:bb:cc:dd:ee:02")
	for i := 0; i < 4; i++ {
		eng.Observe(withMAC(mkSignal(core.SignalModelHostOnIoT, core.SignalReplicationRequired, 20, 0.6), static), now)
		eng.Observe(withMAC(mkSignal(core.SignalDNSDrift, core.SignalReplicationRequired, 25, 0.5), static), now)
	}
	if !qf(netip.MustParseAddr("192.168.1.51")) {
		t.Error("a device named by the inventory was not contained")
	}
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
