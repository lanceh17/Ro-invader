package router

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

// --- fixtures --------------------------------------------------------------

// dnsmasqLeaseFile is a lease database as dnsmasq writes it: bare-hex MACs, a
// "*" where the client sent no hostname, a "*" client id, and the comment
// header dnsmasq puts at the top of the file.
const dnsmasqLeaseFile = `# this is a comment line
1684000000 aabbccddeeff 192.168.1.30 nas *
1684000100 aabbccddeefe 192.168.1.31 * 01:aabbccddeefe
1684000200 thisisnotamac 192.168.1.32 broken *
1684000300 aabbccddeeff not-an-address broken *
1684000400
# 1684000500 aabbccddeefe 192.168.1.33 commented-out *
`

// ipv6LeasesPayload is the dhcp ipv6leases shape: nested by interface, then
// by lease, then by address.
const ipv6LeasesPayload = `{"device":{"br-lan":{"leases":[
  {"mac":"aabbccddee01","hostname":"nas6","ipv6-addr":[
     {"address":"fd00::30","preferred-lifetime":3600,"valid-lifetime":7200},
     {"address":"fd00::31","preferred-lifetime":3600,"valid-lifetime":7200}]},
  {"mac":"","hostname":"relay","ipv6-addr":[{"address":"fd00::99"}]},
  {"mac":"aabbccddee02","hostname":"","ipv6-addr":[{"address":"fd00::32/64"}]}]}}}`

// --- mock router -----------------------------------------------------------

// ubusCall is one recorded request to the mock router.
type ubusCall struct {
	Session string
	Obj     string
	Method  string
	Args    map[string]any
}

// mockOpenWrt is a Doer that emulates rpcd's JSON-RPC surface well enough to
// exercise every code path without a physical router. It records what it was
// asked for, which is the point: a backend that quietly stopped asking for
// the lease file would still return a clean, plausible, empty inventory, and
// the only way to notice is to assert on the requests actually issued.
type mockOpenWrt struct {
	mu     sync.Mutex
	log    []ubusCall
	logins int
	// denyOnce makes the next authenticated call answer ubus status 6,
	// which is what an expired session looks like from here.
	denyOnce bool
	// fileData is returned for file.read.
	fileData string
	// ipv6 is returned for dhcp.ipv6leases.
	ipv6 string
	// failObject, when set, answers that ubus object with status 4.
	failObject string
	// denyAll answers every authenticated object with status 4, modelling an
	// rpcd ACL that grants nothing this backend asks for.
	denyAll bool
	// status, when non-zero, is returned as the HTTP status for every call.
	status int
}

func newMockOpenWrt() *mockOpenWrt {
	return &mockOpenWrt{
		fileData: dnsmasqLeaseFile,
		ipv6:     ipv6LeasesPayload,
	}
}

func (m *mockOpenWrt) Do(req *http.Request) (*http.Response, error) {
	if req.URL.Path != "/ubus" {
		return jsonResponse(http.StatusNotFound, `{"error":{"message":"not found"}}`), nil
	}
	if req.Method != http.MethodPost {
		return jsonResponse(http.StatusMethodNotAllowed, `{"error":{"message":"method not allowed"}}`), nil
	}
	if ct := req.Header.Get("Content-Type"); ct != "application/json" {
		return jsonResponse(http.StatusUnsupportedMediaType, `{"error":{"message":"bad content-type"}}`), nil
	}
	if m.status != 0 {
		return jsonResponse(m.status, `{"error":{"message":"router is unhappy"}}`), nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	var jr struct {
		ID     int   `json:"id"`
		Params []any `json:"params"`
	}
	if err := json.Unmarshal(body, &jr); err != nil {
		return nil, fmt.Errorf("mock: malformed request: %s", body)
	}
	if len(jr.Params) < 4 {
		return nil, fmt.Errorf("mock: malformed params: %s", body)
	}
	sess, _ := jr.Params[0].(string)
	obj, _ := jr.Params[1].(string)
	method, _ := jr.Params[2].(string)
	args, _ := jr.Params[3].(map[string]any)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.log = append(m.log, ubusCall{Session: sess, Obj: obj, Method: method, Args: args})

	if m.denyOnce && obj != "session" {
		m.denyOnce = false
		return ubusReply(jr.ID, 6, nil), nil
	}
	if obj == "session" && method == "login" {
		m.logins++
		return ubusReply(jr.ID, 0, map[string]any{"ubus_rpc_session": "SESS-1"}), nil
	}
	if m.denyAll {
		return ubusReply(jr.ID, 4, nil), nil
	}
	if m.failObject != "" && obj == m.failObject {
		return ubusReply(jr.ID, 4, nil), nil
	}

	switch obj + "." + method {
	case "file.read":
		return ubusReply(jr.ID, 0, map[string]any{"data": m.fileData}), nil
	case "dhcp.ipv6leases":
		return ubusReply(jr.ID, 0, json.RawMessage(m.ipv6)), nil
	}
	// Unknown object: ubus answers with a status, never a transport failure,
	// which is exactly the case a naive client reads as "empty result".
	return ubusReply(jr.ID, 2, nil), nil
}

// ubusResponse builds the [status, payload] envelope rpcd always uses,
// including on failure. A client that read only the payload would decode
// this error as an empty — but successful — lease table.
func ubusReply(id, code int, payload any) *http.Response {
	var raw json.RawMessage
	if payload != nil {
		b, _ := json.Marshal(payload)
		raw = b
	} else {
		raw = json.RawMessage("null")
	}
	env := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  []json.RawMessage{json.RawMessage(fmt.Sprint(code)), raw},
	}
	b, _ := json.Marshal(env)
	return &http.Response{
		Status:     "200 OK",
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(b)),
	}
}

func jsonResponse(code int, body string) *http.Response {
	return &http.Response{
		Status:     fmt.Sprintf("%d %s", code, http.StatusText(code)),
		StatusCode: code,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func (m *mockOpenWrt) callsFor(obj, method string) []ubusCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []ubusCall
	for _, c := range m.log {
		if c.Obj == obj && c.Method == method {
			out = append(out, c)
		}
	}
	return out
}

func newOpenWrtSource(t *testing.T, m *mockOpenWrt) *openWrtSource {
	t.Helper()
	src, err := NewOpenWrt(Config{
		BaseURL:   "http://192.168.1.1",
		Username:  "root",
		Password:  "secret",
		Transport: m,
	})
	if err != nil {
		t.Fatalf("NewOpenWrt: %v", err)
	}
	return src.(*openWrtSource)
}

// --- tests -----------------------------------------------------------------

// TestOpenWrtReadsBothLeaseTables asserts the two calls this backend exists
// to make, with the exact objects and methods. IPv4 comes from the dnsmasq
// lease file rather than `dhcp ipv4leases`, because on stock OpenWrt that
// ubus method reads odhcpd, which usually holds no IPv4 leases at all — it
// answers with an empty set and looks exactly like a network with nothing on
// it. `dhcp ipv4leases` is not expected here and its absence is the point.
func TestOpenWrtReadsBothLeaseTables(t *testing.T) {
	m := newMockOpenWrt()
	src := newOpenWrtSource(t, m)

	leases, err := src.Leases(context.Background())
	if err != nil {
		t.Fatalf("Leases: %v", err)
	}

	reads := m.callsFor("file", "read")
	if len(reads) != 1 {
		t.Fatalf("file.read calls = %d, want 1", len(reads))
	}
	if path, _ := reads[0].Args["path"].(string); path != "/tmp/dhcp.leases" {
		t.Errorf("file.read path = %q, want /tmp/dhcp.leases", path)
	}
	if len(m.callsFor("dhcp", "ipv6leases")) != 1 {
		t.Errorf("dhcp.ipv6leases calls = %d, want 1", len(m.callsFor("dhcp", "ipv6leases")))
	}
	if len(m.callsFor("dhcp", "ipv4leases")) != 0 {
		t.Error("this backend must not call dhcp.ipv4leases; odhcpd does not hold the IPv4 leases on stock OpenWrt")
	}

	// Three usable rows: two from the lease file (the two broken rows and the
	// comment are skipped) and one MAC from the IPv6 payload. The relay entry
	// carries no MAC and the third lease's only address is the same MAC the
	// file already reported.
	want := map[string]bool{
		"192.168.1.30/aa:bb:cc:dd:ee:ff": true,
		"192.168.1.31/aa:bb:cc:dd:ee:fe": true,
		"fd00::30/aa:bb:cc:dd:ee:01":     true,
		"fd00::31/aa:bb:cc:dd:ee:01":     true,
		"fd00::32/aa:bb:cc:dd:ee:02":     true,
	}
	got := map[string]bool{}
	for _, l := range leases {
		got[l.IP.String()+"/"+l.MAC.String()] = true
	}
	for k := range want {
		if !got[k] {
			t.Errorf("missing lease %s; got %v", k, got)
		}
	}
	if len(leases) != len(want) {
		t.Errorf("got %d leases, want %d: %v", len(leases), len(want), got)
	}
}

// TestOpenWrtNeverIssuesFileExec is the safety boundary as an assertion.
//
// `file read` on a fixed path reads state. `file exec` is a general-purpose
// remote command channel: it would let this process run anything at all on
// the router, which is precisely the capability SAFETY.md rules out
// unconditionally. The two are one ubus object apart, so the guarantee is
// worth pinning in a test rather than leaving to review — a later
// "convenience" swap to exec would otherwise pass every functional test and
// only be caught by the CI grep.
func TestOpenWrtNeverIssuesFileExec(t *testing.T) {
	m := newMockOpenWrt()
	src := newOpenWrtSource(t, m)
	ctx := context.Background()

	// Two full passes, so the assertion covers the session-expiry path too
	// and not just the happy one.
	for i := 0; i < 2; i++ {
		if _, err := src.Leases(ctx); err != nil {
			t.Fatalf("Leases %d: %v", i, err)
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.log {
		if c.Obj == "file" && c.Method != "read" {
			t.Errorf("issued file.%s; only file read is permitted (see SAFETY.md)", c.Method)
		}
	}
}

func TestOpenWrtReusesSession(t *testing.T) {
	m := newMockOpenWrt()
	src := newOpenWrtSource(t, m)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := src.Leases(ctx); err != nil {
			t.Fatalf("Leases %d: %v", i, err)
		}
	}
	// One login for three polls. Logging in per call would triple the session
	// churn on a device with a small process table, and each session would
	// sit alive until its timeout before being reclaimed.
	if m.logins != 1 {
		t.Errorf("logins = %d, want 1", m.logins)
	}
	for _, c := range m.callsFor("file", "read") {
		if c.Session != "SESS-1" {
			t.Errorf("file.read used session %q, want SESS-1", c.Session)
		}
	}
}

// TestOpenWrtExpiredSessionReauthenticates covers the failure that would
// otherwise appear as attribution quietly dying an hour after startup, with
// nothing in the logs but status 6.
func TestOpenWrtExpiredSessionReauthenticates(t *testing.T) {
	m := newMockOpenWrt()
	src := newOpenWrtSource(t, m)
	ctx := context.Background()

	if _, err := src.Leases(ctx); err != nil {
		t.Fatalf("first Leases: %v", err)
	}

	m.mu.Lock()
	m.denyOnce = true
	m.mu.Unlock()

	if _, err := src.Leases(ctx); err != nil {
		t.Fatalf("Leases after expiry: %v", err)
	}
	if m.logins != 2 {
		t.Errorf("logins = %d, want 2 (one re-auth after expiry)", m.logins)
	}
}

// TestOpenWrtPermanentDenialIsNotRetriedForever pins the bound on the retry.
// Status 6 means both "session aged out" and "these rights were never
// granted", and only the first is fixed by logging in again. An unbounded
// retry against the second becomes a login loop hammering the router.
func TestOpenWrtPermanentDenialIsNotRetriedForever(t *testing.T) {
	m := newMockOpenWrt()
	m.denyAll = true
	src := newOpenWrtSource(t, m)

	_, err := src.Leases(context.Background())
	if err == nil {
		t.Fatal("Leases must fail when the router refuses every call")
	}
	if !strings.Contains(err.Error(), "status 4") {
		t.Errorf("error %q does not name the ubus status", err)
	}
	// Status 4 is not the expired-session code, so exactly one attempt must be
	// made per call: a retry here would be a login loop against a router whose
	// rights will never be granted.
	if got := len(m.callsFor("file", "read")); got != 1 {
		t.Errorf("file.read issued %d times for a non-session failure, want 1", got)
	}
	if m.logins != 1 {
		t.Errorf("logins = %d, want 1", m.logins)
	}
}

// TestOpenWrtKeepsTheWorkingHalfOfASource covers partial availability: rpcd
// ACLs routinely permit dhcp.ipv6leases while withholding file read, and
// losing the whole source over one of two calls would mean an IPv6-only
// router also loses its IPv4 inventory.
func TestOpenWrtKeepsTheWorkingHalfOfASource(t *testing.T) {
	m := newMockOpenWrt()
	m.failObject = "file"
	src := newOpenWrtSource(t, m)

	leases, err := src.Leases(context.Background())
	if err != nil {
		t.Fatalf("Leases must not fail when one of two calls fails: %v", err)
	}
	if len(leases) == 0 {
		t.Fatal("the IPv6 half was discarded along with the IPv4 half")
	}
	for _, l := range leases {
		if !l.IP.Is6() {
			t.Errorf("unexpected IPv4 lease %s survived a failed file read", l.IP)
		}
	}
}

func TestOpenWrtTransportFailureNamesTheCall(t *testing.T) {
	src, err := NewOpenWrt(Config{
		BaseURL:   "http://192.168.1.1",
		Username:  "root",
		Transport: doerFunc(func(*http.Request) (*http.Response, error) { return nil, fmt.Errorf("connection refused") }),
	})
	if err != nil {
		t.Fatalf("NewOpenWrt: %v", err)
	}
	_, err = src.Leases(context.Background())
	if err == nil {
		t.Fatal("Leases must surface a transport failure")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error %q does not carry the transport cause", err)
	}
}

// TestParseOpenWrtLeases exercises the dnsmasq format directly, with no
// transport in the way. The malformed rows are the interesting half: one
// torn line must cost exactly itself and not the other leases on the network.
func TestParseOpenWrtLeases(t *testing.T) {
	leases, err := parseOpenWrtLeases([]byte(dnsmasqLeaseFile))
	if err != nil {
		t.Fatalf("parseOpenWrtLeases: %v", err)
	}
	if len(leases) != 2 {
		t.Fatalf("got %d leases, want 2 (both broken rows skipped): %+v", len(leases), leases)
	}

	first := leases[0]
	if first.MAC.String() != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("bare-hex MAC parsed as %s", first.MAC)
	}
	if first.IP != netip.MustParseAddr("192.168.1.30") {
		t.Errorf("IP = %s", first.IP)
	}
	if first.Hostname != "nas" {
		t.Errorf("Hostname = %q, want nas", first.Hostname)
	}
	// The "*" placeholder must not reach the operator's portal.
	if leases[1].Hostname != "" {
		t.Errorf("Hostname = %q, want empty for the dnsmasq * placeholder", leases[1].Hostname)
	}
}

// TestParseOpenWrtLeasesRejectsNonText guards the one case that is fatal
// rather than per-row. A payload that is not valid UTF-8 means we did not
// read a lease file at all — a wrong BaseURL, a truncated transfer — and
// treating its bytes as lease rows would invent devices that are not on the
// network.
func TestParseOpenWrtLeasesRejectsNonText(t *testing.T) {
	_, err := parseOpenWrtLeases([]byte{0xff, 0xfe, 0x00, 0x01})
	if err == nil {
		t.Fatal("a binary payload must be rejected outright")
	}
	if !strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("error %q does not explain why the payload was refused", err)
	}
}

func TestParseOpenWrtIPv6Leases(t *testing.T) {
	leases, err := parseOpenWrtIPv6Leases([]byte(ipv6LeasesPayload))
	if err != nil {
		t.Fatalf("parseOpenWrtIPv6Leases: %v", err)
	}
	// Three addresses across two MACs. The relay lease carries no MAC and is
	// dropped: there is no identity to record for it.
	if len(leases) != 3 {
		t.Fatalf("got %d leases, want 3: %+v", len(leases), leases)
	}
	if leases[0].IP != netip.MustParseAddr("fd00::30") || leases[1].IP != netip.MustParseAddr("fd00::31") {
		t.Errorf("a lease with two addresses contributed %s and %s; both must be kept",
			leases[0].IP, leases[1].IP)
	}
	// A prefixed address must still resolve, or the whole lease is lost.
	if leases[2].IP != netip.MustParseAddr("fd00::32") {
		t.Errorf("prefixed address parsed as %s", leases[2].IP)
	}
}

// TestOpenWrtDeduplicatesBindingsAcrossSources covers a lease reported twice
// — once from the dnsmasq file and once from odhcpd — for one MAC and one
// address. Two entries would double-count the device in every report.
func TestOpenWrtDeduplicatesBindingsAcrossSources(t *testing.T) {
	m := newMockOpenWrt()
	// odhcpd restating the addresses dnsmasq already leased is not exotic: the
	// two servers overlap whenever both run on the LAN interface, and the same
	// MAC and the same address arrive from both.
	m.ipv6 = `{"device":{"br-lan":{"leases":[
	  {"mac":"aabbccddeeff","hostname":"nas","ipv6-addr":[{"address":"192.168.1.30"}]},
	  {"mac":"aabbccddeefe","hostname":"","ipv6-addr":[{"address":"192.168.1.31"}]}]}}}`
	src := newOpenWrtSource(t, m)

	leases, err := src.Leases(context.Background())
	if err != nil {
		t.Fatalf("Leases: %v", err)
	}
	if len(leases) != 4 {
		t.Fatalf("source returned %d leases, want 4 (two bindings reported twice)", len(leases))
	}

	c := newTestClient(t, src)
	if err := c.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	devs := c.Devices()
	if len(devs) != 2 {
		t.Errorf("Len = %d, want 2 devices behind 4 duplicate leases", len(devs))
	}
	for _, d := range devs {
		if len(d.IPs) != 1 {
			t.Errorf("device %s holds %d addresses, want the duplicate collapsed to 1", d.MAC, len(d.IPs))
		}
	}
}

func TestParseOpenWrtIPv6LeasesRejectsGarbage(t *testing.T) {
	if _, err := parseOpenWrtIPv6Leases([]byte(`{"device":`)); err == nil {
		t.Fatal("a malformed ipv6leases payload must be an error, not an empty result")
	}
}
