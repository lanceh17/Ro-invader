package portal

import (
	"html"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
	"github.com/lanceh17/Ro-invader/agent/internal/inventory"
)

// stubSource is a DeviceSource with fixed answers.
//
// It exists to reach the states the shipped tables reach only by accident: an
// address the table resolves to a MAC it then has no record for. That happens
// in a real run whenever a poll lands between two requests, and it is the one
// case the page is not allowed to answer confidently in either direction.
type stubSource struct {
	ip   netip.Addr
	mac  net.HardwareAddr
	know bool
	dev  core.Device
}

func (s stubSource) MACFor(ip netip.Addr) (net.HardwareAddr, bool) {
	if s.mac == nil || ip != s.ip {
		return nil, false
	}
	return s.mac, true
}

func (s stubSource) Get(mac net.HardwareAddr) (core.Device, bool) {
	if !s.know || s.mac == nil || mac.String() != s.mac.String() {
		return core.Device{}, false
	}
	return s.dev, true
}

// namedButUnrecorded is the degraded table: it can say who owns the address
// and has nothing to say about them.
func namedButUnrecorded(t *testing.T) stubSource {
	t.Helper()
	return stubSource{ip: netip.MustParseAddr("192.168.1.50"), mac: mustMAC(t)}
}

// withSource reuses the quarantined-camera environment -- same engine, same
// release store, same page -- and changes only what the device table can
// answer, so these tests vary one thing at a time.
func withSource(t *testing.T, src DeviceSource) *portalEnv {
	t.Helper()
	e := newPortalEnv(t)
	e.cfg.DeviceSource = src
	return e
}

// TestStatusPageNamedButUnrecordedDoesNotClaimFree: the device table resolved
// this address to a MAC, which is exactly the lookup the containment predicate
// makes before deciding to sinkhole. So the device is probably being contained
// at this very moment, and a page telling it otherwise is a device told it may
// go back to work while it is still walled in.
func TestStatusPageNamedButUnrecordedDoesNotClaimFree(t *testing.T) {
	env := withSource(t, namedButUnrecorded(t))
	rec := getStatus(t, env.handler(t), "192.168.1.50")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s), want 200 -- a degraded table is not a broken server", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "not contained") {
		t.Error("the page reported a contained device as not contained while its record was unavailable")
	}
	if !strings.Contains(body, "No record") {
		t.Error("the page did not say the record is unavailable")
	}
	// It knows who this is; saying so is what lets an operator match the page
	// against the audit log.
	if !strings.Contains(body, mustMAC(t).String()) {
		t.Error("the page did not name the device it had identified")
	}
	if strings.Contains(body, `action="/release"`) {
		t.Error("the page offered a release form for a device it cannot assess")
	}
}

// TestReleaseUnrecordedDeviceIsUnavailableNotServerError: a release needs the
// record to confirm the device is actually quarantined. Not having it is a
// transient condition of the table, so it is reported as one -- a 404 would
// tell the operator the device does not exist, and a 500 would blame the server
// for something that is usually true again within one poll interval.
func TestReleaseUnrecordedDeviceIsUnavailableNotServerError(t *testing.T) {
	env := withSource(t, namedButUnrecorded(t))
	rec := postRelease(t, env.handler(t), "192.168.1.60", url.Values{
		"token": {"test-token"},
		"ip":    {"192.168.1.50"},
	})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d (%s), want 503", rec.Code, rec.Body.String())
	}
	if _, ok := env.cfg.Exceptions.Active(mustMAC(t)); ok {
		t.Error("a release was recorded for a device with no record")
	}
	if _, err := os.Stat(env.auditP); !os.IsNotExist(err) {
		t.Error("the refused release wrote an audit entry")
	}
}

// TestReleaseIsStillReportedWhenTheRecordIsGone: the release store is keyed on
// the MAC, so an operator's decision outlives whatever the table happens to be
// describing. Dropping the banner because the record went missing would make
// an active release look like it had lapsed.
func TestReleaseIsStillReportedWhenTheRecordIsGone(t *testing.T) {
	src := stubSource{
		ip:   netip.MustParseAddr("192.168.1.50"),
		mac:  mustMAC(t),
		know: true,
		dev: core.Device{
			MAC:    mustMAC(t),
			IPs:    []netip.Addr{netip.MustParseAddr("192.168.1.50")},
			Vendor: "Hikvision",
			Class:  core.ClassCamera,
		},
	}
	env := withSource(t, src)
	if _, err := env.cfg.Exceptions.Release(mustMAC(t), "operator", time.Hour); err != nil {
		t.Fatalf("Release: %v", err)
	}

	src.know = false
	env.cfg.DeviceSource = src
	body := getStatus(t, env.handler(t), "192.168.1.50").Body.String()
	if !strings.Contains(body, "Released by operator") {
		t.Error("the page stopped reporting an active release when the device record went away")
	}
}

// TestUnclassifiedDeviceStatesWhatItDoesNotKnow: a device discovered by a
// router is containable long before anyone classifies it, so an empty vendor
// and an unknown class are ordinary states. They render as statements about
// the device rather than as blank cells, and the generic steps are shown
// because there is no vendor to look up -- not because the lookup silently
// found nothing.
func TestUnclassifiedDeviceStatesWhatItDoesNotKnow(t *testing.T) {
	mac := mustMAC(t)
	env := withSource(t, stubSource{
		ip:   netip.MustParseAddr("192.168.1.50"),
		mac:  mac,
		know: true,
		dev:  core.Device{MAC: mac, IPs: []netip.Addr{netip.MustParseAddr("192.168.1.50")}},
	})

	body := getStatus(t, env.handler(t), "192.168.1.50").Body.String()
	for _, want := range []string{
		unknownVendorLabel,
		unknownClassLabel,
		"No vendor or class has been published",
		// The page is HTML, so the rendered step is the escaped form. Quoting
		// DefaultRemediation escaped rather than a copy of it means a change to
		// the wording shows up here instead of silently un-testing this.
		html.EscapeString(DefaultRemediation[0]),
	} {
		if !strings.Contains(body, want) {
			t.Errorf("unclassified device page missing %q", want)
		}
	}
	// The other direction matters just as much: a device with no vendor must
	// not be handed a specific vendor's instructions.
	if strings.Contains(body, "Install the 2026 firmware published by Hikvision.") {
		t.Error("a device with no published vendor was given that vendor's steps")
	}
}

// TestNilDeviceSourceIsHonestNothing: nil means there is no device table. The
// portal must then report no record for every address and refuse to release,
// which is the same nothing the handler produced before there was a source
// interface at all -- not a page that renders an empty device, and not a
// release that acts on a guess.
func TestNilDeviceSourceIsHonestNothing(t *testing.T) {
	env := newPortalEnv(t)
	env.cfg.DeviceSource = nil
	h := env.handler(t)

	rec := getStatus(t, h, "192.168.1.50")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "No record") {
		t.Error("with no device table the page did not report no record")
	}
	if strings.Contains(rec.Body.String(), `action="/release"`) {
		t.Error("with no device table the page offered a release")
	}

	rec = postRelease(t, h, "192.168.1.50", url.Values{"token": {"test-token"}, "ip": {"192.168.1.50"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("release status = %d (%s), want 400", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(env.auditP); !os.IsNotExist(err) {
		t.Error("the refused release wrote an audit entry")
	}
}

// TestInventorySatisfiesDeviceSource keeps the file-backed table in the
// contract. Without it the portal could drift onto a source only the router
// happens to implement, and the -inventory-only deployment would quietly lose
// every page it has today. The daemon's router-backed table asserts the same
// against itself, next to the code that builds it.
func TestInventorySatisfiesDeviceSource(t *testing.T) {
	inv, err := inventory.Parse([]byte(`[
		{"mac":"aa:bb:cc:dd:ee:01","ips":["192.168.1.50"],"class":"camera","vendor":"Hikvision"}
	]`))
	if err != nil {
		t.Fatalf("inventory.Parse: %v", err)
	}
	var src DeviceSource = inv
	mac, ok := src.MACFor(netip.MustParseAddr("192.168.1.50"))
	if !ok {
		t.Fatal("a file-backed table did not resolve an address it lists")
	}
	if _, ok := src.Get(mac); !ok {
		t.Error("a file-backed table resolved a MAC it cannot describe")
	}
}
