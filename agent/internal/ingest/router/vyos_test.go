package router

import (
	"context"
	"encoding/json"
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

// vyosLeaseTable is `show dhcp server leases` output: whitespace-aligned
// columns, a dash underline, timestamps that each occupy two fields, and a
// hostname that is empty for the second device because it never announced one.
const vyosLeaseTable = `IP Address    MAC address        State    Lease start          Lease expiration     Remaining    Pool        Hostname
------------  -----------------  -------  -------------------  -------------------  -----------  ----------  ----------
192.168.0.30  00:50:79:66:68:05  active   2023/05/11 13:08:50  2023/05/12 13:08:50  23:59:16     DHCPTun100  VPCS
192.168.0.31  00:50:79:66:68:06  active   2023/05/11 13:09:00  2023/05/12 13:09:00  23:59:00     DHCPTun100
`

// vyosARPTable is `show arp` output. The last row is unresolved: VyOS prints
// "(incomplete)" where the link layer address would be, and there is no
// identity to record until it has one.
const vyosARPTable = `Address  Interface  Link layer address  State
-------  ---------  -----------------  -----------
192.168.1.10  eth0  00:aa:bb:cc:dd:ee  REACHABLE
192.168.1.11  eth1  00:aa:bb:cc:dd:ef  STALE
192.168.1.12  eth1  (incomplete)       FAILED
`

// --- mock ------------------------------------------------------------------

// vyosRequestLog is one recorded call to the mock /show endpoint.
type vyosRequestLog struct {
	ContentType string
	Key         string
	Path        []string
}

// mockVyOS is a Doer that emulates VyOS's /show endpoint.
//
// It answers with a JSON envelope carrying a plain-text table, served as
// text/html — which is what the endpoint actually does, and the reason the
// backend must never dispatch on Content-Type.
type mockVyOS struct {
	mu      sync.Mutex
	log     []vyosRequestLog
	leases  string
	arp     string
	failFor string
	failAll bool
	status  int
}

func newMockVyOS() *mockVyOS {
	return &mockVyOS{leases: vyosLeaseTable, arp: vyosARPTable}
}

func (m *mockVyOS) Do(req *http.Request) (*http.Response, error) {
	if req.URL.Path != "/show" {
		return vyosBody(http.StatusNotFound, `{"success":false,"data":null,"error":"no such endpoint"}`), nil
	}
	if req.Method != http.MethodPost {
		return vyosBody(http.StatusMethodNotAllowed, `{"success":false,"data":null,"error":"method not allowed"}`), nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, fmt.Errorf("mock: body is not form-encoded: %s", body)
	}
	var doc struct {
		Op   string   `json:"op"`
		Path []string `json:"path"`
	}
	if err := json.Unmarshal([]byte(form.Get("data")), &doc); err != nil {
		return nil, fmt.Errorf("mock: data field is not the command document: %s", body)
	}

	m.mu.Lock()
	m.log = append(m.log, vyosRequestLog{
		ContentType: req.Header.Get("Content-Type"),
		Key:         form.Get("key"),
		Path:        doc.Path,
	})
	m.mu.Unlock()

	if m.status != 0 {
		return vyosBody(m.status, `{"success":false,"data":null,"error":"router is unhappy"}`), nil
	}
	// A non-empty failFor fails exactly one path, so a test can show that the
	// other table still contributes.
	if m.failAll || (m.failFor != "" && m.failFor == strings.Join(doc.Path, " ")) {
		return vyosBody(http.StatusOK, `{"success":false,"data":null,"error":{"code":32004,"message":"Invalid API key"}}`), nil
	}

	switch strings.Join(doc.Path, " ") {
	case "dhcp server leases":
		// JSON wrapped around a string: the table has to survive one level of
		// escaping, which is why a JSON-aware client must not try to parse the
		// payload as JSON.
		env, _ := json.Marshal(map[string]any{"success": true, "data": m.leases, "error": nil})
		return vyosBody(http.StatusOK, string(env)), nil
	case "arp":
		env, _ := json.Marshal(map[string]any{"success": true, "data": m.arp, "error": nil})
		return vyosBody(http.StatusOK, string(env)), nil
	}
	return vyosBody(http.StatusOK, `{"success":true,"data":"","error":null}`), nil
}

// vyosBody answers with the JSON envelope under a text/html Content-Type,
// because that is the header VyOS sends and a client that trusted it would
// reject every successful response from the endpoint it exists to read.
func vyosBody(code int, body string) *http.Response {
	return &http.Response{
		Status:     fmt.Sprintf("%d %s", code, http.StatusText(code)),
		StatusCode: code,
		Header:     http.Header{"Content-Type": []string{"text/html; charset=UTF-8"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func (m *mockVyOS) requests() []vyosRequestLog {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]vyosRequestLog(nil), m.log...)
}

func newVyOSSource(t *testing.T, m *mockVyOS) *vyosSource {
	t.Helper()
	src, err := NewVyOS(Config{BaseURL: "http://vyos.example", Token: "test-api-key", Transport: m})
	if err != nil {
		t.Fatalf("NewVyOS: %v", err)
	}
	return src.(*vyosSource)
}

// --- tests -----------------------------------------------------------------

// TestVyOSUsesFormEncodedShow covers the request contract: form-encoded body,
// API key in the "key" field, command document in the "data" field, and the
// two paths this backend reads.
func TestVyOSUsesFormEncodedShow(t *testing.T) {
	m := newMockVyOS()
	src := newVyOSSource(t, m)

	if _, err := src.Leases(context.Background()); err != nil {
		t.Fatalf("Leases: %v", err)
	}

	reqs := m.requests()
	if len(reqs) != 2 {
		t.Fatalf("issued %d requests, want 2 (leases and arp)", len(reqs))
	}
	for _, r := range reqs {
		if r.ContentType != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q, want form encoding", r.ContentType)
		}
		if r.Key != "test-api-key" {
			t.Errorf("key = %q, want the configured API key", r.Key)
		}
	}
	if got := strings.Join(reqs[0].Path, " "); got != "dhcp server leases" {
		t.Errorf("first path = %q, want \"dhcp server leases\"", got)
	}
	if got := strings.Join(reqs[1].Path, " "); got != "arp" {
		t.Errorf("second path = %q, want \"arp\"", got)
	}
}

// TestVyOSParsesLeaseTable covers the whitespace-aligned table, including the
// two traps in it: timestamps occupy two fields each, so the columns are not
// positional, and the hostname is the last column and may be empty.
func TestVyOSParsesLeaseTable(t *testing.T) {
	leases := parseVyOSLeases(vyosLeaseTable)
	if len(leases) != 2 {
		t.Fatalf("got %d leases, want 2: %+v", len(leases), leases)
	}

	first := leases[0]
	if first.IP != netip.MustParseAddr("192.168.0.30") {
		t.Errorf("IP = %s, want 192.168.0.30", first.IP)
	}
	if first.MAC.String() != "00:50:79:66:68:05" {
		t.Errorf("MAC = %s, want 00:50:79:66:68:05", first.MAC)
	}
	if first.Hostname != "VPCS" {
		t.Errorf("Hostname = %q, want VPCS", first.Hostname)
	}

	// The second row has no hostname at all. Reading the columns positionally
	// would put the pool name "DHCPTun100" here, which is worse than leaving
	// it blank: an operator would then see a device named after a subnet.
	if leases[1].Hostname != "" {
		t.Errorf("Hostname = %q, want empty for a device that announced none", leases[1].Hostname)
	}
	if leases[1].MAC.String() != "00:50:79:66:68:06" {
		t.Errorf("MAC = %s, want 00:50:79:66:68:06", leases[1].MAC)
	}
}

// TestVyOSSkipsDecorationAndJunk asserts that the header and the dash
// underline never become devices. They are the two lines that look like data
// and are not, and an "IP Address" row that parsed would put a bogus device
// in the operator's list.
func TestVyOSSkipsDecorationAndJunk(t *testing.T) {
	for _, text := range []string{
		"IP Address  MAC address  State\n------------  -----------  -----\n",
		"",
		"\n\n   \n",
		"not a table at all",
		"192.168.0.30  not-a-mac  active  2023/05/11 13:08:50  2023/05/12 13:08:50  23:59:16  pool",
		"192.168.0.30  00:50:79:66:68:05  active  2023/05/11",
	} {
		if got := parseVyOSLeases(text); len(got) != 0 {
			t.Errorf("parseVyOSLeases(%q) produced %+v, want nothing", text, got)
		}
	}
	if !isRuleRow("------------  ---------") || isRuleRow("192.168.0.30  00:50:79:66:68:05") {
		t.Error("isRuleRow does not distinguish an underline from a data row")
	}
}

func TestVyOSParsesARPTable(t *testing.T) {
	rows := parseVyOSARP(vyosARPTable)
	if len(rows) != 2 {
		t.Fatalf("got %d neighbour rows, want 2: %+v", len(rows), rows)
	}
	if rows[0].IP != netip.MustParseAddr("192.168.1.10") || rows[0].MAC.String() != "00:aa:bb:cc:dd:ee" {
		t.Errorf("first neighbour = %s/%s", rows[0].IP, rows[0].MAC)
	}
	if rows[1].IP != netip.MustParseAddr("192.168.1.11") {
		t.Errorf("second neighbour = %s", rows[1].IP)
	}
	// The unresolved entry is dropped: there is no identity to record until
	// the router has resolved one.
	for _, r := range rows {
		if r.IP == netip.MustParseAddr("192.168.1.12") {
			t.Error("an unresolved neighbour entry was recorded as a device")
		}
	}
}

// TestVyOSMissingKeyNamesTheEnvVar checks that a configuration failure tells
// the operator where to set the credential. Naming only the Config field
// would send them to read this package; naming the variable sends them to
// their shell.
func TestVyOSMissingKeyNamesTheEnvVar(t *testing.T) {
	m := newMockVyOS()
	_, err := NewVyOS(Config{BaseURL: "http://vyos.example", Transport: m})
	if err == nil {
		t.Fatal("NewVyOS must reject an empty API key")
	}
	if !strings.Contains(err.Error(), "Token") {
		t.Errorf("error %q does not name the Config field", err)
	}
	if !strings.Contains(err.Error(), vyosAPIKeyEnv) {
		t.Errorf("error %q does not name %s", err, vyosAPIKeyEnv)
	}
	if len(m.requests()) != 0 {
		t.Error("no request should reach the router without a key")
	}
}

// TestVyOSFailureEnvelopeSurfaces covers the "success": false path. The error
// body is the one part of the response an operator needs, and a client that
// decoded it into a typed field of the wrong shape would print a nil pointer
// instead of the reason.
func TestVyOSFailureEnvelopeSurfaces(t *testing.T) {
	m := newMockVyOS()
	m.failAll = true
	src := newVyOSSource(t, m)

	_, err := src.Leases(context.Background())
	if err == nil {
		t.Fatal("Leases must fail when the router reports success:false")
	}
	if !strings.Contains(err.Error(), "Invalid API key") {
		t.Errorf("error %q does not carry the router's reason", err)
	}
}

func TestVyOSHTTPFailureSurfaces(t *testing.T) {
	m := newMockVyOS()
	m.status = http.StatusUnauthorized
	src := newVyOSSource(t, m)

	_, err := src.Leases(context.Background())
	if err == nil {
		t.Fatal("Leases must fail on a non-2xx response")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error %q does not name the HTTP status", err)
	}
}

func TestParseVyOSEnvelope(t *testing.T) {
	if _, err := parseVyOSEnvelope([]byte(`not json`)); err == nil {
		t.Error("a non-JSON body must be an error, not an empty result")
	}
	if _, err := parseVyOSEnvelope([]byte(`{"success":false,"data":null,"error":null}`)); err == nil ||
		!strings.Contains(err.Error(), "no error detail") {
		t.Errorf("a bare rejection should still say something, got %v", err)
	}
	if _, err := parseVyOSEnvelope([]byte(`{"success":false,"error":"flat string reason"}`)); err == nil ||
		!strings.Contains(err.Error(), "flat string reason") {
		t.Errorf("a string error body was not reported, got %v", err)
	}
}

// TestVyOSLeasesKeepsTheWorkingTable mirrors the OpenWrt partial-availability
// rule: a router with static addressing on one LAN and DHCP on another has an
// empty lease table and a full neighbour table, and neither should cost the
// other.
func TestVyOSLeasesKeepsTheWorkingTable(t *testing.T) {
	m := newMockVyOS()
	m.failFor = "dhcp server leases"
	src := newVyOSSource(t, m)

	leases, err := src.Leases(context.Background())
	if err != nil {
		t.Fatalf("Leases must not fail when one of two calls fails: %v", err)
	}
	if len(leases) != 2 {
		t.Fatalf("got %d leases, want the 2 neighbour-table rows", len(leases))
	}
}
