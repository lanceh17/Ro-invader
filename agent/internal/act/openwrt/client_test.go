package openwrt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

// mockRouter is a Doer that emulates rpcd's JSON-RPC surface well enough to
// exercise every code path without a physical OpenWrt device. It records the
// ubus calls it received so tests can assert on the exact operations the
// adapter issued against the router's configuration.
type mockRouter struct {
	mu       sync.Mutex
	log      []rpcCall
	sections map[string]map[string]any // "config.section" -> values
	logins   int
	// denyOnce makes the next call after the first return ubus status 6,
	// which is what an expired session looks like.
	denyOnce bool
	// transportErr, when set, fails the request at the HTTP layer.
	transportErr error
}

type rpcCall struct {
	Session string
	Obj     string
	Method  string
	Params  map[string]any
}

func newMockRouter() *mockRouter {
	return &mockRouter{sections: map[string]map[string]any{}}
}

func (m *mockRouter) Do(req *http.Request) (*http.Response, error) {
	if m.transportErr != nil {
		return nil, m.transportErr
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
		return nil, err
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
	m.log = append(m.log, rpcCall{Session: sess, Obj: obj, Method: method, Params: args})

	// An expired session surfaces as ubus status 6 on any authenticated
	// call. The adapter must re-login rather than give up.
	if m.denyOnce && obj != "session" {
		m.denyOnce = false
		return rpcResponse(jr.ID, []any{6}), nil
	}

	if obj == "session" && method == "login" {
		m.logins++
		return rpcResponse(jr.ID, map[string]any{"ubus_rpc_session": "SESS-1"}), nil
	}

	// Everything else is a [status, payload] pair as the adapter expects.
	switch obj {
	case "uci":
		return m.handleUCI(jr.ID, method, args), nil
	default:
		// firewall.reload, service.event, system.board: succeed with an
		// empty payload.
		return rpcResponse(jr.ID, []any{0}), nil
	}
}

func (m *mockRouter) handleUCI(id int, method string, args map[string]any) *http.Response {
	config, _ := args["config"].(string)
	section, _ := args["section"].(string)
	key := config + "." + section

	switch method {
	case "get":
		vals, ok := m.sections[key]
		if !ok {
			// uci reports a missing section with a non-zero status.
			return rpcResponse(id, []any{4})
		}
		return rpcResponse(id, []any{0, map[string]any{"values": vals}})

	case "add":
		name, _ := args["name"].(string)
		if name == "" {
			name = "cfg" + fmt.Sprint(len(m.sections))
		}
		if m.sections[config+"."+name] == nil {
			m.sections[config+"."+name] = map[string]any{}
		}
		return rpcResponse(id, []any{0, name})

	case "set":
		vals, _ := args["values"].(map[string]any)
		if m.sections[key] == nil {
			return rpcResponse(id, []any{4})
		}
		for k, v := range vals {
			m.sections[key][k] = v
		}
		return rpcResponse(id, []any{0})

	case "delete":
		if _, ok := m.sections[key]; !ok {
			return rpcResponse(id, []any{4})
		}
		delete(m.sections, key)
		return rpcResponse(id, []any{0})

	case "commit":
		return rpcResponse(id, []any{0})
	}
	return rpcResponse(id, []any{0})
}

// rpcResponse builds the JSON-RPC envelope. result[1] carries the ubus
// [status, payload] pair, which is what the adapter unwraps.
func rpcResponse(id int, payload any) *http.Response {
	raw, _ := json.Marshal(payload)
	env := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  []json.RawMessage{json.RawMessage("0"), raw},
	}
	b, _ := json.Marshal(env)
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(bytes.NewReader(b)),
	}
}

func testDevice() core.Device {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	return core.Device{
		MAC:    mac,
		IPs:    []netip.Addr{netip.MustParseAddr("192.168.1.44")},
		Vendor: "Raspberry Pi",
	}
}

func newTestClient(t *testing.T, m *mockRouter) *Client {
	t.Helper()
	c, err := New(Config{
		BaseURL:   "http://192.168.1.1",
		Username:  "root",
		Password:  "secret",
		Transport: m,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func (m *mockRouter) callsFor(obj, method string) []rpcCall {
	var out []rpcCall
	for _, c := range m.log {
		if c.Obj == obj && c.Method == method {
			out = append(out, c)
		}
	}
	return out
}

func (m *mockRouter) sectionsUnder(config string) map[string]map[string]any {
	out := map[string]map[string]any{}
	for k, v := range m.sections {
		if len(k) > len(config) && k[:len(config)+1] == config+"." {
			out[k[len(config)+1:]] = v
		}
	}
	return out
}

func TestNewRequiresBaseURLAndUsername(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("New must reject an empty BaseURL")
	}
	if _, err := New(Config{BaseURL: "http://x"}); err == nil {
		t.Error("New must reject an empty Username")
	}
}

// TestNewDefaultsEgressAllow guards the foot-gun the constructor is meant to
// close: without an allowlist, a quarantined device would be cut off from
// remediation entirely, which is a worse outcome than the original infection.
func TestNewDefaultsEgressAllow(t *testing.T) {
	c, err := New(Config{BaseURL: "http://x", Username: "root", Transport: newMockRouter()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(c.cfg.EgressAllow) == 0 {
		t.Fatal("New must default EgressAllow so a restricted device stays remediable")
	}
}

func TestLoginHappensOnceAndSessionIsReused(t *testing.T) {
	m := newMockRouter()
	c := newTestClient(t, m)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := c.Health(ctx); err != nil {
			t.Fatalf("Health call %d: %v", i, err)
		}
	}
	if m.logins != 1 {
		t.Errorf("login calls = %d, want 1 (session must be cached)", m.logins)
	}
	for _, call := range m.callsFor("system", "board") {
		if call.Session != "SESS-1" {
			t.Errorf("system.board used session %q, want SESS-1", call.Session)
		}
	}
}

// TestExpiredSessionTriggersReauthentication covers the failure that would
// otherwise show up as every call mysteriously failing after the ubus
// timeout elapses.
func TestExpiredSessionTriggersReauthentication(t *testing.T) {
	m := newMockRouter()
	c := newTestClient(t, m)
	ctx := context.Background()

	if err := c.Health(ctx); err != nil {
		t.Fatalf("first Health: %v", err)
	}

	m.mu.Lock()
	m.denyOnce = true
	m.mu.Unlock()

	if err := c.Health(ctx); err != nil {
		t.Fatalf("Health after session expiry: %v", err)
	}
	if m.logins != 2 {
		t.Errorf("login calls = %d, want 2 (one re-auth after expiry)", m.logins)
	}
}

func TestTransportErrorsPropagate(t *testing.T) {
	m := newMockRouter()
	m.transportErr = errors.New("connection refused")
	c := newTestClient(t, m)

	if err := c.Health(context.Background()); err == nil {
		t.Fatal("a transport failure must surface as an error, not be swallowed")
	}
}

func TestAuthoritativeCreatesStaticLease(t *testing.T) {
	m := newMockRouter()
	c := newTestClient(t, m)
	dev := testDevice()

	if err := c.Authoritative(context.Background(), dev); err != nil {
		t.Fatalf("Authoritative: %v", err)
	}

	lease := m.sectionsUnder("dhcp")
	if len(lease) == 0 {
		t.Fatal("Authoritative created no DHCP lease section")
	}
	for name, vals := range lease {
		if vals["mac"] != "aa:bb:cc:dd:ee:01" {
			t.Errorf("lease %s mac = %v, want the device MAC", name, vals["mac"])
		}
		if vals["ip"] != "192.168.1.44" {
			t.Errorf("lease %s ip = %v, want 192.168.1.44", name, vals["ip"])
		}
	}
	if len(m.callsFor("uci", "commit")) == 0 {
		t.Error("Authoritative must commit; staged changes are discarded otherwise")
	}
}

// TestAuthoritativeRequiresIdentity asserts the guard that stops a lease
// being written for a device we cannot name, which would pin an arbitrary IP
// to nothing.
func TestAuthoritativeRequiresIdentity(t *testing.T) {
	m := newMockRouter()
	c := newTestClient(t, m)

	noMAC := testDevice()
	noMAC.MAC = nil
	if err := c.Authoritative(context.Background(), noMAC); err == nil {
		t.Error("Authoritative must reject a device with no MAC")
	}

	noIP := testDevice()
	noIP.IPs = nil
	if err := c.Authoritative(context.Background(), noIP); err == nil {
		t.Error("Authoritative must reject a device with no IP")
	}
	if m.logins != 0 {
		t.Error("a rejected call must not reach the router at all")
	}
}

func TestQuarantineCreatesMACKeyedFirewallRule(t *testing.T) {
	m := newMockRouter()
	c := newTestClient(t, m)
	dev := testDevice()

	if err := c.Quarantine(context.Background(), dev, core.PolicyRestrict); err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	fw := m.sectionsUnder("firewall")
	if len(fw) == 0 {
		t.Fatal("Quarantine created no firewall section")
	}
	for name, vals := range fw {
		// src_mac rather than a src IP: the restriction must survive a DHCP
		// change, or a device that picks up a new lease escapes containment.
		if vals["src_mac"] != "aa:bb:cc:dd:ee:01" {
			t.Errorf("rule %s src_mac = %v, want the device MAC", name, vals["src_mac"])
		}
		if vals["target"] != "REJECT" {
			t.Errorf("rule %s target = %v, want REJECT", name, vals["target"])
		}
		if vals["dest"] != "lan" {
			t.Errorf("rule %s dest = %v, want lan (peer blocking)", name, vals["dest"])
		}
	}
	if len(m.callsFor("firewall", "reload")) == 0 {
		t.Error("Quarantine must reload the firewall; a staged rule is not an active one")
	}
}

func TestQuarantineMonitorReleasesInsteadOfBlocking(t *testing.T) {
	m := newMockRouter()
	c := newTestClient(t, m)
	dev := testDevice()

	// Establish a quarantine, then drop to monitor. The rule must be gone,
	// not merely relabelled.
	if err := c.Quarantine(context.Background(), dev, core.PolicyQuarantine); err != nil {
		t.Fatalf("initial Quarantine: %v", err)
	}
	if err := c.Quarantine(context.Background(), dev, core.PolicyMonitor); err != nil {
		t.Fatalf("drop to monitor: %v", err)
	}

	if got := m.sectionsUnder("firewall"); len(got) != 0 {
		t.Errorf("monitor policy left %d firewall rules in place", len(got))
	}
}

func TestQuarantineRequiresMAC(t *testing.T) {
	m := newMockRouter()
	c := newTestClient(t, m)
	dev := testDevice()
	dev.MAC = nil

	if err := c.Quarantine(context.Background(), dev, core.PolicyRestrict); err == nil {
		t.Error("Quarantine must reject a device with no MAC")
	}
}

func TestReleaseIsIdempotent(t *testing.T) {
	m := newMockRouter()
	c := newTestClient(t, m)
	dev := testDevice()

	if err := c.Quarantine(context.Background(), dev, core.PolicyRestrict); err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	if err := c.Release(context.Background(), dev); err != nil {
		t.Fatalf("first Release: %v", err)
	}
	// A second Release must be a no-op rather than an error, because the
	// remediation portal calls it on a user's confirmation and a user may
	// well click twice.
	if err := c.Release(context.Background(), dev); err != nil {
		t.Errorf("second Release: %v, want idempotent no-op", err)
	}
	if got := m.sectionsUnder("firewall"); len(got) != 0 {
		t.Errorf("Release left %d firewall rules behind", len(got))
	}
}

func TestBlockNetWritesAnExpiringRule(t *testing.T) {
	m := newMockRouter()
	c := newTestClient(t, m)
	prefix := netip.MustParsePrefix("203.0.113.0/24")
	until := time.Now().Add(time.Hour)

	if err := c.BlockNet(context.Background(), prefix, until); err != nil {
		t.Fatalf("BlockNet: %v", err)
	}

	fw := m.sectionsUnder("firewall")
	if len(fw) == 0 {
		t.Fatal("BlockNet created no firewall rule")
	}
	for name, vals := range fw {
		if vals["dest"] != "203.0.113.0/24" {
			t.Errorf("rule %s dest = %v, want the blocked prefix", name, vals["dest"])
		}
		// The expiry must be recorded in the rule itself, so that a crashed
		// control plane leaves a self-identifying orphan rather than a
		// permanent block on the network.
		comment, _ := vals["comment"].(string)
		if comment == "" {
			t.Errorf("rule %s carries no expiry comment", name)
		}
	}
}

func TestBlockDomainUsesDnsmasq(t *testing.T) {
	m := newMockRouter()
	c := newTestClient(t, m)

	if err := c.BlockDomain(context.Background(), "Malicious.Example", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("BlockDomain: %v", err)
	}

	dns := m.sectionsUnder("dnsmasq")
	if len(dns) == 0 {
		t.Fatal("BlockDomain created no dnsmasq section")
	}
	for name, vals := range dns {
		// A leading slash means the exact domain only. Sinking the whole
		// subtree would break every legitimate subdomain the owner uses.
		ip, _ := vals["ip"].(string)
		if len(ip) < 2 || ip[0] != '/' {
			t.Errorf("dnsmasq section %s ip = %q, want an exact-match sinkhole", name, ip)
		}
	}
}

// TestSectionNamesAreNamespaced is the guarantee that this tool never touches
// an operator's own firewall rules. OpenWrt's config is shared state, and
// deleting a rule we did not create would silently destroy their setup.
func TestSectionNamesAreNamespaced(t *testing.T) {
	m := newMockRouter()
	c := newTestClient(t, m)
	dev := testDevice()

	if err := c.Quarantine(context.Background(), dev, core.PolicyQuarantine); err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	if err := c.BlockNet(context.Background(), netip.MustParsePrefix("203.0.113.0/24"), time.Now()); err != nil {
		t.Fatalf("BlockNet: %v", err)
	}
	if err := c.BlockDomain(context.Background(), "bad.example", time.Now()); err != nil {
		t.Fatalf("BlockDomain: %v", err)
	}

	for config := range map[string]bool{"firewall": true, "dhcp": true, "dnsmasq": true} {
		for name := range m.sectionsUnder(config) {
			if len(name) < len(rulePrefix) || name[:len(rulePrefix)] != rulePrefix {
				t.Errorf("section %s.%s is not namespaced under %q", config, name, rulePrefix)
			}
		}
	}
}

// TestReleasesOnlyItsOwnSections verifies the inverse of the namespace
// guarantee: Release must not delete a rule it did not create, even when that
// rule sits in the same config.
func TestReleasesOnlyItsOwnSections(t *testing.T) {
	m := newMockRouter()
	c := newTestClient(t, m)
	dev := testDevice()

	// An operator's own pre-existing rule.
	m.sections["firewall.ssh_allow"] = map[string]any{"target": "ACCEPT"}

	if err := c.Quarantine(context.Background(), dev, core.PolicyRestrict); err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	if err := c.Release(context.Background(), dev); err != nil {
		t.Fatalf("Release: %v", err)
	}

	if _, ok := m.sections["firewall.ssh_allow"]; !ok {
		t.Error("Release deleted an operator's rule it did not create")
	}
}
