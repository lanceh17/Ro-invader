package portal

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
	"github.com/lanceh17/Ro-invader/agent/internal/inventory"
	"github.com/lanceh17/Ro-invader/agent/internal/risk"
)

type portalEnv struct {
	cfg    Config
	mac    net.HardwareAddr
	clk    *fixedClock
	auditP string
}

// newPortalEnv builds the realistic case: a camera pushed into quarantine by
// two corroborated signal kinds, plus a clean workstation that must stay free.
func newPortalEnv(t *testing.T) *portalEnv {
	t.Helper()
	inv, err := inventory.Parse([]byte(`[
		{"mac":"aa:bb:cc:dd:ee:01","ips":["192.168.1.50"],"class":"camera","vendor":"Hikvision"},
		{"mac":"aa:bb:cc:dd:ee:02","ips":["192.168.1.51"],"class":"workstation","vendor":"Dell"}
	]`))
	if err != nil {
		t.Fatalf("inventory.Parse: %v", err)
	}
	mac := mustMAC(t)
	clk := &fixedClock{t: time.Date(2026, 3, 1, 8, 0, 0, 0, time.UTC)}
	eng := risk.New()
	for i := 0; i < 3; i++ {
		eng.Observe(withMAC(mkSignal(core.SignalModelHostOnIoT, core.SignalReplicationRequired, 20, 0.6, "device contacted a model-hosting endpoint (cdn.example)"), mac), clk.now())
		eng.Observe(withMAC(mkSignal(core.SignalDNSDrift, core.SignalReplicationRequired, 25, 0.5, "device resolved a novel domain for the first time (cdn.example)"), mac), clk.now())
	}
	dev, _ := inv.Get(mac)
	if tier := eng.Evaluate(dev, clk.now()).Tier; tier != core.ContainmentQuarantined {
		t.Fatalf("fixture tier = %v, want quarantined", tier)
	}

	dir := t.TempDir()
	stateP := filepath.Join(dir, "state.json")
	auditP := filepath.Join(dir, "audit.jsonl")
	exc, err := NewExceptions(stateP, clk.now)
	if err != nil {
		t.Fatalf("NewExceptions: %v", err)
	}
	aud := NewAudit(auditP, clk.now)
	// Windows keeps an open handle exclusive; without this the TempDir
	// cleanup fails while the log file is still open.
	t.Cleanup(func() { _ = aud.Close() })
	cfg := Config{
		Engine:      eng,
		Inventory:   inv,
		Garden:      []string{"support.example"},
		Remediation: map[string][]string{"hikvision": {"Install the 2026 firmware published by Hikvision."}},
		Exceptions:  exc,
		Audit:       aud,
		Token:       "test-token",
		ReleaseTTL:  time.Hour,
		Now:         clk.now,
	}
	return &portalEnv{cfg: cfg, mac: mac, clk: clk, auditP: auditP}
}

func (e *portalEnv) handler(t *testing.T) http.Handler {
	t.Helper()
	s, err := New(e.cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s.Handler()
}

func getStatus(t *testing.T, h http.Handler, remoteIP string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteIP + ":54321"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func postRelease(t *testing.T, h http.Handler, remoteIP string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/release", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = remoteIP + ":5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func mkSignal(kind core.SignalKind, cls core.SignalClass, w, c float64, reason string) core.Signal {
	return core.Signal{Kind: kind, Class: cls, Weight: w, Confidence: c, Reason: reason}
}

func withMAC(s core.Signal, mac net.HardwareAddr) core.Signal {
	s.DeviceMAC = mac
	return s
}

// TestStatusPageQuarantinedDevice: the page a sinkholed device sees must show
// why it is contained (the actual signal reasons), what it may still reach,
// what to do, and the release form.
func TestStatusPageQuarantinedDevice(t *testing.T) {
	env := newPortalEnv(t)
	rec := getStatus(t, env.handler(t), "192.168.1.50")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"aa:bb:cc:dd:ee:01",
		`is <strong>quarantined</strong>`,
		"Why this device is flagged",
		`name="token"`,
		`<code>support.example</code>`,
		"Install the 2026 firmware published by Hikvision.",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
}

func TestStatusPageUnknownAddressIsNotARecord(t *testing.T) {
	env := newPortalEnv(t)
	rec := getStatus(t, env.handler(t), "192.168.1.99")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "No record") {
		t.Error("unknown address page missing the no-record notice")
	}
	if strings.Contains(body, `action="/release"`) {
		t.Error("unknown address was offered a release form")
	}
}

func TestStatusPageUncontainedDevice(t *testing.T) {
	env := newPortalEnv(t)
	rec := getStatus(t, env.handler(t), "192.168.1.51")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "This device is not contained") {
		t.Error("clean device page missing its status")
	}
	if strings.Contains(body, `action="/release"`) {
		t.Error("a device that is not contained was offered a release form")
	}
	if strings.Contains(body, "Why this device is flagged") {
		t.Error("clean device page shows a flagging section")
	}
}

// TestReleaseHappyPath: an operator posting from a different machine releases
// the contained camera by address; the exception becomes active and the audit
// log records who, what, and until when.
func TestReleaseHappyPath(t *testing.T) {
	env := newPortalEnv(t)
	h := env.handler(t)

	rec := postRelease(t, h, "192.168.1.60", url.Values{
		"token": {"test-token"},
		"ip":    {"192.168.1.50"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d (%s), want 303", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/?released=1" {
		t.Errorf("Location = %q, want /?released=1", loc)
	}

	exc, ok := env.cfg.Exceptions.Active(env.mac)
	if !ok {
		t.Fatal("release did not become active")
	}
	if exc.By != "portal" || !exc.ExpiresAt.Equal(env.clk.t.Add(time.Hour)) {
		t.Errorf("exception = %+v, want by=portal, expiry now+1h", exc)
	}

	entries := readEntries(t, env.auditP)
	if len(entries) != 1 {
		t.Fatalf("audit has %d entries, want 1", len(entries))
	}
	e := entries[0]
	if e.Action != "release" || e.MAC != env.mac.String() || e.By != "portal" {
		t.Errorf("audit entry = %+v, want release for %s by portal", e, env.mac)
	}
	if e.Expires == nil || !e.Expires.Equal(exc.ExpiresAt) {
		t.Errorf("audit expiry = %v, want %v", e.Expires, exc.ExpiresAt)
	}
	if e.Score <= risk.DefaultConfig().QuarantineThreshold || e.Tier != "quarantined" {
		t.Errorf("audit assessment = score %v tier %q, want the state that justified release", e.Score, e.Tier)
	}

	// The device's own page now shows the release.
	rec = getStatus(t, h, "192.168.1.50")
	if !strings.Contains(rec.Body.String(), "Released by portal") {
		t.Error("released device page missing the release banner")
	}
}

func TestReleaseRejectsWrongToken(t *testing.T) {
	env := newPortalEnv(t)
	h := env.handler(t)
	rec := postRelease(t, h, "192.168.1.50", url.Values{
		"token": {"guessed"},
		"ip":    {"192.168.1.50"},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if _, ok := env.cfg.Exceptions.Active(env.mac); ok {
		t.Error("wrong token produced an exception")
	}
	if _, err := os.Stat(env.auditP); !os.IsNotExist(err) {
		t.Error("failed release wrote an audit entry")
	}
}

// TestReleaseRefusesUncontainedDevice: releasing a device that is not
// quarantined is not an error worth acting on — it would salt the state and
// audit log with no-op releases (and is how a typo becomes noise).
func TestReleaseRefusesUncontainedDevice(t *testing.T) {
	env := newPortalEnv(t)
	rec := postRelease(t, env.handler(t), "192.168.1.50", url.Values{
		"token": {"test-token"},
		"ip":    {"192.168.1.51"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d (%s), want 400", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not quarantined") {
		t.Errorf("body = %q, want the refusal reason", rec.Body.String())
	}
	if _, err := os.Stat(env.auditP); !os.IsNotExist(err) {
		t.Error("refused release wrote an audit entry")
	}
}

func TestReleaseUnknownAddressIsNotFound(t *testing.T) {
	env := newPortalEnv(t)
	rec := postRelease(t, env.handler(t), "192.168.1.50", url.Values{
		"token": {"test-token"},
		"ip":    {"192.168.1.77"},
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestReleaseWithoutConfigIsReadOnly(t *testing.T) {
	env := newPortalEnv(t)
	env.cfg.Token = ""
	env.cfg.Exceptions = nil
	env.cfg.Audit = nil
	h := env.handler(t)

	if strings.Contains(getStatus(t, h, "192.168.1.50").Body.String(), `action="/release"`) {
		t.Error("page offers release although release is not configured")
	}
	rec := postRelease(t, h, "192.168.1.50", url.Values{"token": {""}, "ip": {"192.168.1.50"}})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// TestMuxAndHeaders: the page is pinned to the root, health stays plain, and
// the hardening headers ride on every response.
func TestMuxAndHeaders(t *testing.T) {
	env := newPortalEnv(t)
	h := env.handler(t)

	rec := getStatus(t, h, "192.168.1.50")
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Error("missing CSP")
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing nosniff")
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("device status must not be cacheable")
	}

	other := httptest.NewRequest(http.MethodGet, "/crawler-canary", nil)
	other.RemoteAddr = "192.168.1.50:1"
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, other)
	if rec2.Code != http.StatusNotFound {
		t.Errorf("non-root path status = %d, want 404", rec2.Code)
	}

	health := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, health)
	if rec3.Code != http.StatusOK || !strings.Contains(rec3.Body.String(), "ok") {
		t.Errorf("healthz = %d %q", rec3.Code, rec3.Body.String())
	}
}

// TestStatusPageObservingMode: in -observe the engine may say quarantined
// while nothing is contained; the page must report observation, not claim a
// containment that is not happening, and must not offer release.
func TestStatusPageObservingMode(t *testing.T) {
	env := newPortalEnv(t)
	env.cfg.ReadOnly = true
	h := env.handler(t)

	rec := getStatus(t, h, "192.168.1.50")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "observe mode") {
		t.Error("observing page does not say it is observing")
	}
	if strings.Contains(body, `action="/release"`) {
		t.Error("observing page offers release for a device that is not contained")
	}
	if strings.Contains(body, `is <strong>quarantined</strong>`) {
		t.Error("observing page claims active containment")
	}

	// A direct POST must be refused too: the form is hidden, not the rule.
	rec = postRelease(t, h, "192.168.1.50", url.Values{"token": {"test-token"}, "ip": {"192.168.1.50"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "observing only") {
		t.Errorf("body = %q, want the observe-mode refusal", rec.Body.String())
	}
}

func TestNewRequiresEngine(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("New accepted a config without an engine")
	}
}
