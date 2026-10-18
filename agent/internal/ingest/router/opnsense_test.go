package router

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// --- fixtures --------------------------------------------------------------

// opnSenseLeaseRowset is a search_lease page. The third row has no MAC — a
// reservation, or a stale row with the hardware address cleared.
const opnSenseLeaseRowset = `{"total":3,"rowCount":3,"current":1,"rows":[
  {"address":"192.168.1.30","mac":"00:50:79:66:68:05","hostname":"nas","state":"active","status":"V4","type":"dynamic","man":"Raspberry Pi","starts":"2026/10/18 09:00:00","ends":"2026/10/18 21:00:00"},
  {"address":"192.168.1.31","mac":"AA-BB-CC-DD-EE-06","hostname":"","state":"active","status":"V4","type":"dynamic","man":"","starts":"2026/10/18 09:05:00","ends":"2026/10/18 21:05:00"},
  {"address":"192.168.1.99","mac":"","hostname":"reserved","state":"reserved","status":"V4","type":"static","man":"","starts":"","ends":""}
]}`

// opnSenseARPRowset is a search_arp page. The second row is expired: it names
// an address that has since been handed to somebody else. The third has no
// MAC at all.
const opnSenseARPRowset = `{"total":3,"rowCount":3,"current":1,"rows":[
  {"ip":"192.168.1.10","mac":"00:aa:bb:cc:dd:ee","intf":"lan","intf_description":"LAN","expired":false,"expires":"1199","permanent":false,"type":"arp","manufacturer":"Hikvision","hostname":"camera1"},
  {"ip":"192.168.1.11","mac":"00:aa:bb:cc:dd:f0","intf":"lan","intf_description":"LAN","expired":true,"expires":"0","permanent":false,"type":"arp","manufacturer":"","hostname":""},
  {"ip":"192.168.1.12","mac":"","intf":"lan","intf_description":"LAN","expired":false,"expires":"600","permanent":false,"type":"arp","manufacturer":"","hostname":""}
]}`

// --- mock ------------------------------------------------------------------

// opnSenseRequest is one recorded API call.
type opnSenseRequest struct {
	Path   string
	Query  url.Values
	Auth   string
	Accept string
}

// mockOPNsense is a Doer that emulates OPNsense's two rowset endpoints.
type mockOPNsense struct {
	mu       sync.Mutex
	log      []opnSenseRequest
	leases   string
	arp      string
	failPath string
	status   int
}

func newMockOPNsense() *mockOPNsense {
	return &mockOPNsense{leases: opnSenseLeaseRowset, arp: opnSenseARPRowset}
}

func (m *mockOPNsense) Do(req *http.Request) (*http.Response, error) {
	q, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.log = append(m.log, opnSenseRequest{
		Path:   req.URL.Path,
		Query:  q,
		Auth:   req.Header.Get("Authorization"),
		Accept: req.Header.Get("Accept"),
	})
	m.mu.Unlock()

	if m.status != 0 {
		return opnSenseBody(m.status, `{"message":"denied"}`), nil
	}
	if m.failPath == req.URL.Path {
		return opnSenseBody(http.StatusOK, `{"rows":[]}`), nil
	}
	if req.URL.Path == opnSenseLeaseEndpoint {
		return opnSenseBody(http.StatusOK, m.leases), nil
	}
	if req.URL.Path == opnSenseARPEndpoint {
		return opnSenseBody(http.StatusOK, m.arp), nil
	}
	return opnSenseBody(http.StatusNotFound, `{"message":"no such endpoint"}`), nil
}

func opnSenseBody(code int, body string) *http.Response {
	return &http.Response{
		Status:     fmt.Sprintf("%d %s", code, http.StatusText(code)),
		StatusCode: code,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func (m *mockOPNsense) requests() []opnSenseRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]opnSenseRequest(nil), m.log...)
}

func newOPNsenseSource(t *testing.T, m *mockOPNsense) *opnSenseSource {
	t.Helper()
	src, err := NewOPNsense(Config{
		BaseURL:   "https://fw.example",
		Token:     "key-123",
		Password:  "secret-456",
		Transport: m,
	})
	if err != nil {
		t.Fatalf("NewOPNsense: %v", err)
	}
	return src.(*opnSenseSource)
}

// --- tests -----------------------------------------------------------------

// TestOPNsenseRequestsEveryRow pins the paging parameters. rowCount=-1 is
// OPNsense's no-limit sentinel and is the whole reason this endpoint is used:
// walking pages instead would silently drop the tail of a large table, and
// the devices that get dropped are the newly deployed ones.
func TestOPNsenseRequestsEveryRow(t *testing.T) {
	m := newMockOPNsense()
	src := newOPNsenseSource(t, m)

	if _, err := src.Leases(context.Background()); err != nil {
		t.Fatalf("Leases: %v", err)
	}

	reqs := m.requests()
	if len(reqs) != 2 {
		t.Fatalf("issued %d requests, want 2 (leases and arp)", len(reqs))
	}

	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("key-123:secret-456"))
	for _, r := range reqs {
		if r.Auth != wantAuth {
			t.Errorf("%s Authorization = %q, want the key/secret pair as basic auth", r.Path, r.Auth)
		}
		// Without Accept: application/json, OPNsense renders its login page
		// and the response parses as garbage — a failure that looks like a
		// vendor format change rather than a missing header.
		if r.Accept != "application/json" {
			t.Errorf("%s Accept = %q, want application/json", r.Path, r.Accept)
		}
		if got := r.Query.Get("rowCount"); got != "-1" {
			t.Errorf("%s rowCount = %q, want -1 (every row in one page)", r.Path, got)
		}
		if got := r.Query.Get("current"); got != "1" {
			t.Errorf("%s current = %q, want 1", r.Path, got)
		}
		if _, ok := r.Query["searchPhrase"]; !ok {
			t.Errorf("%s omitted searchPhrase; OPNsense requires the parameter to be present", r.Path)
		}
	}

	if reqs[0].Path != opnSenseLeaseEndpoint {
		t.Errorf("first path = %q, want %q", reqs[0].Path, opnSenseLeaseEndpoint)
	}
	if got := reqs[0].Query.Get("sort[column]"); got != "address" {
		t.Errorf("lease sort column = %q, want address", got)
	}
	if reqs[1].Path != opnSenseARPEndpoint {
		t.Errorf("second path = %q, want %q", reqs[1].Path, opnSenseARPEndpoint)
	}
	// The neighbour table names its address column differently and rejects a
	// sort on a column it does not have, so none is sent.
	if got := reqs[1].Query.Get("sort[column]"); got != "" {
		t.Errorf("arp sort column = %q, want none", got)
	}
}

func TestOPNsenseParsesLeasesAndARP(t *testing.T) {
	m := newMockOPNsense()
	src := newOPNsenseSource(t, m)

	leases, err := src.Leases(context.Background())
	if err != nil {
		t.Fatalf("Leases: %v", err)
	}
	// Two leases plus one live neighbour row. The MAC-less reservation, the
	// expired neighbour entry and the MAC-less neighbour row are all dropped.
	if len(leases) != 3 {
		t.Fatalf("got %d leases, want 3: %+v", len(leases), leases)
	}

	var foundCamera bool
	for _, l := range leases {
		if l.IP == netip.MustParseAddr("192.168.1.10") {
			foundCamera = true
			if l.MAC.String() != "00:aa:bb:cc:dd:ee" {
				t.Errorf("camera MAC = %s", l.MAC)
			}
			// OPNsense resolves the OUI from its own MAC database, so the
			// manufacturer is a fact rather than a guess at the first three
			// bytes of the address.
			if l.Vendor != "Hikvision" {
				t.Errorf("camera vendor = %q, want Hikvision", l.Vendor)
			}
			if l.Hostname != "camera1" {
				t.Errorf("camera hostname = %q, want camera1", l.Hostname)
			}
		}
		// The dash spelling must normalize to the same key as the colon one.
		if l.IP == netip.MustParseAddr("192.168.1.31") && l.MAC.String() != "aa:bb:cc:dd:ee:06" {
			t.Errorf("dash-form MAC parsed as %s", l.MAC)
		}
	}
	if !foundCamera {
		t.Error("the reachable neighbour entry was dropped")
	}
}

// TestOPNsenseSkipsUnusableNeighbourRows is the safety case for attribution.
// An expired neighbour entry names an address that has since been reassigned:
// recording it would blame whatever device holds the address now for traffic
// its predecessor generated, which in this system means quarantining the wrong
// device on the strength of stale bookkeeping.
func TestOPNsenseSkipsUnusableNeighbourRows(t *testing.T) {
	leases, err := parseOPNsenseARP([]byte(opnSenseARPRowset))
	if err != nil {
		t.Fatalf("parseOPNsenseARP: %v", err)
	}
	if len(leases) != 1 {
		t.Fatalf("got %d rows, want only the live one: %+v", len(leases), leases)
	}
	if leases[0].IP != netip.MustParseAddr("192.168.1.10") {
		t.Errorf("kept %s, want 192.168.1.10", leases[0].IP)
	}
}

func TestOPNsenseSkipsMAClessRows(t *testing.T) {
	leases, err := parseOPNsenseLeases([]byte(opnSenseLeaseRowset))
	if err != nil {
		t.Fatalf("parseOPNsenseLeases: %v", err)
	}
	for _, l := range leases {
		if l.IP == netip.MustParseAddr("192.168.1.99") {
			t.Error("a reservation with no MAC became a device; there is no identity to record")
		}
	}
	if len(leases) != 2 {
		t.Errorf("got %d leases, want 2", len(leases))
	}
}

func TestOPNsenseParsersRejectMalformedRowsets(t *testing.T) {
	if _, err := parseOPNsenseLeases([]byte(`{"rows":`)); err == nil {
		t.Error("a malformed rowset must be an error, not an empty result")
	}
	if _, err := parseOPNsenseARP([]byte(`<html>login</html>`)); err == nil {
		t.Error("an HTML body must be an error; it means the JSON Accept header was dropped")
	}
}

func TestOPNsenseNonSuccessStatusSurfaces(t *testing.T) {
	m := newMockOPNsense()
	m.status = http.StatusUnauthorized
	src := newOPNsenseSource(t, m)

	_, err := src.Leases(context.Background())
	if err == nil {
		t.Fatal("Leases must fail on a non-2xx response")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error %q does not name the HTTP status", err)
	}
	if !strings.Contains(err.Error(), opnSenseLeaseEndpoint) {
		t.Errorf("error %q does not name the endpoint that failed", err)
	}
}

// TestOPNsenseKeepsTheWorkingEndpoint mirrors the rule the other two backends
// follow: the DHCP server and the neighbour table are enabled independently,
// and one failing must not blind the other.
func TestOPNsenseKeepsTheWorkingEndpoint(t *testing.T) {
	m := newMockOPNsense()
	m.failPath = opnSenseLeaseEndpoint
	src := newOPNsenseSource(t, m)

	leases, err := src.Leases(context.Background())
	if err != nil {
		t.Fatalf("Leases must not fail when one of two endpoints fails: %v", err)
	}
	if len(leases) != 1 {
		t.Fatalf("got %d leases, want the 1 live neighbour row", len(leases))
	}
}

func TestOPNsenseRequiresBothCredentialHalves(t *testing.T) {
	m := newMockOPNsense()

	_, err := NewOPNsense(Config{BaseURL: "https://fw.example", Password: "s", Transport: m})
	if err == nil || !strings.Contains(err.Error(), opnSenseKeyEnv) {
		t.Errorf("missing key: err = %v, want it to name %s", err, opnSenseKeyEnv)
	}

	_, err = NewOPNsense(Config{BaseURL: "https://fw.example", Token: "k", Transport: m})
	if err == nil || !strings.Contains(err.Error(), opnSenseSecretEnv) {
		t.Errorf("missing secret: err = %v, want it to name %s", err, opnSenseSecretEnv)
	}
	if len(m.requests()) != 0 {
		t.Error("no request should reach the firewall without full credentials")
	}
}
