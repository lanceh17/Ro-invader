package opnsense

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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

// mockFirewall is a Doer that emulates the subset of the OPNsense API this
// adapter uses, well enough to exercise every path without an appliance, a
// network, or a listening socket. It records the calls it received so tests
// can assert on the exact requests the adapter issued rather than on
// whatever internal state it happened to leave behind.
type mockFirewall struct {
	mu sync.Mutex
	// rules and hosts are the appliance's persistent config, keyed by uuid.
	rules map[string]rule
	hosts map[string]hostOverride
	seq   int
	log   []call
	// applied counts firewall reloads and resolver reconfigurations. Tests
	// use it to prove the adapter does not reconfigure the whole network on
	// an operation that changed nothing.
	applied  int
	reconfig int

	// Failure injection.
	transportErr error
	forceStatus  int    // when non-zero, every request answers this status
	malformed    string // when set, every 200 response carries this body
	applyStatus  string // when set, apply answers this instead of "ok"
	// addRuleUUIDless makes addRule answer 200 with no uuid, which is what a
	// silent validation failure looks like from the client's side.
	addRuleUUIDless bool
	// pendingBody is the response body the next Do call will return.
	pendingBody string
}

type call struct {
	Method string
	Path   string
	Body   map[string]any
}

func newMockFirewall() *mockFirewall {
	return &mockFirewall{
		rules: map[string]rule{},
		hosts: map[string]hostOverride{},
	}
}

func (m *mockFirewall) nextUUID() string {
	m.seq++
	return fmt.Sprintf("uuid-%d", m.seq)
}

func (m *mockFirewall) Do(req *http.Request) (*http.Response, error) {
	if m.transportErr != nil {
		return nil, m.transportErr
	}
	var raw []byte
	if req.Body != nil {
		var err error
		raw, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
	}
	// Record the Basic credentials so a test can prove the key/secret are
	// sent as username/password, which is how OPNsense expects them.
	user, secret, _ := req.BasicAuth()

	m.mu.Lock()
	defer m.mu.Unlock()

	entry := call{Method: req.Method, Path: strings.TrimPrefix(req.URL.Path, "/api/")}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &entry.Body)
	}
	m.log = append(m.log, entry)

	if user != "test-key" || secret != "test-secret" {
		return m.respond(http.StatusUnauthorized, `{"status":401,"message":"Authentication Failed"}`)
	}
	if m.forceStatus != 0 {
		return m.respond(m.forceStatus, `{"status":"error"}`)
	}
	if err := m.route(req.Method, entry.Path, raw); err != nil {
		return m.respond(http.StatusNotFound, `{"status":"not found"}`)
	}
	return m.respond(http.StatusOK, m.pendingBody)
}

// respond builds a canned HTTP response, honouring the malformed-body knob so
// a test can exercise decode failures without a bespoke router.
func (m *mockFirewall) respond(status int, body string) (*http.Response, error) {
	if m.malformed != "" && status == http.StatusOK {
		body = m.malformed
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}, nil
}

// pendingBody is set by route for the response it wants returned.
type mockResponse = string

func (m *mockFirewall) route(method, path string, raw []byte) error {
	parts := strings.Split(path, "/")

	switch {
	case path == epSearchRule:
		rows := make([]any, 0, len(m.rules))
		for _, u := range m.sortedRuleUUIDs() {
			r := m.rules[u]
			rows = append(rows, map[string]any{
				"uuid":        u,
				"description": r.Description,
				"tag":         r.Tag,
				"action":      r.Action,
				"source_net":  r.SourceNet,
				"dest_net":    r.DestNet,
				"dest_not":    r.DestNot,
				"interface":   r.Interface,
			})
		}
		m.pendingBody = marshal(rowset{Total: len(rows), RowCount: len(rows), Current: 1, Rows: marshalRows(rows)})
		return nil

	case path == epAddRule:
		var payload struct {
			Rule rule `json:"rule"`
		}
		if err := json.Unmarshal(raw, &payload); err != nil {
			return err
		}
		u := m.nextUUID()
		m.rules[u] = payload.Rule
		m.pendingBody = addResult(u, m.addRuleUUIDless)
		return nil

	case strings.HasPrefix(path, epSetRule+"/"):
		u := strings.TrimPrefix(path, epSetRule+"/")
		if _, ok := m.rules[u]; !ok {
			return errors.New("no such rule")
		}
		var payload struct {
			Rule rule `json:"rule"`
		}
		if err := json.Unmarshal(raw, &payload); err != nil {
			return err
		}
		m.rules[u] = payload.Rule
		m.pendingBody = `{"result":"saved"}`
		return nil

	case strings.HasPrefix(path, epDelRule+"/"):
		u := strings.TrimPrefix(path, epDelRule+"/")
		if _, ok := m.rules[u]; !ok {
			return errors.New("no such rule")
		}
		delete(m.rules, u)
		m.pendingBody = `{"result":"deleted"}`
		return nil

	case path == epApply:
		if m.applyStatus != "" {
			m.pendingBody = `{"status":"` + m.applyStatus + `"}`
			return nil
		}
		m.applied++
		m.pendingBody = `{"status":"ok"}`
		// Also reconfigure unbound when apply is called
		m.reconfig++
		return nil

	case path == epHostSearch:
		rows := make([]any, 0, len(m.hosts))
		for _, u := range m.sortedHostUUIDs() {
			h := m.hosts[u]
			rows = append(rows, map[string]any{
				"uuid":        u,
				"description": h.Description,
				"hostname":    h.Hostname,
				"domain":      h.Domain,
				"server":      h.Server,
			})
		}
		m.pendingBody = marshal(rowset{Total: len(rows), RowCount: len(rows), Current: 1, Rows: marshalRows(rows)})
		return nil

	case path == epHostAdd:
		var payload struct {
			Host hostOverride `json:"host"`
		}
		if err := json.Unmarshal(raw, &payload); err != nil {
			return err
		}
		u := m.nextUUID()
		m.hosts[u] = payload.Host
		m.pendingBody = addResult(u, m.addRuleUUIDless)
		return nil

	case strings.HasPrefix(path, epHostDel+"/"):
		u := strings.TrimPrefix(path, epHostDel+"/")
		if _, ok := m.hosts[u]; !ok {
			return errors.New("no such host")
		}
		delete(m.hosts, u)
		m.pendingBody = `{"result":"deleted"}`
		return nil

	case strings.HasPrefix(path, "unbound/settings/setHostOverride/"):
		u := strings.TrimPrefix(path, "unbound/settings/setHostOverride/")
		if _, ok := m.hosts[u]; !ok {
			return errors.New("no such host")
		}
		var payload struct {
			Host hostOverride `json:"host"`
		}
		if err := json.Unmarshal(raw, &payload); err != nil {
			return err
		}
		m.hosts[u] = payload.Host
		m.pendingBody = `{"result":"saved"}`
		return nil

	case path == epUnboundSync:
		m.reconfig++
		m.pendingBody = `{"status":"ok"}`
		return nil
	}
	_ = parts
	return errors.New("unrouted: " + path)
}

func addResult(u string, omit bool) string {
	if omit {
		return `{"result":"failed"}`
	}
	return `{"result":"saved","uuid":"` + u + `"}`
}

func marshalRows(rows []any) []json.RawMessage {
	out := make([]json.RawMessage, len(rows))
	for i, r := range rows {
		b, _ := json.Marshal(r)
		out[i] = json.RawMessage(b)
	}
	return out
}

func marshal(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func (m *mockFirewall) sortedRuleUUIDs() []string {
	out := make([]string, 0, len(m.rules))
	for u := range m.rules {
		out = append(out, u)
	}
	sortStrings(out)
	return out
}

func (m *mockFirewall) sortedHostUUIDs() []string {
	out := make([]string, 0, len(m.hosts))
	for u := range m.hosts {
		out = append(out, u)
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func (m *mockFirewall) callsTo(path string) []call {
	var out []call
	for _, c := range m.log {
		if c.Path == path {
			out = append(out, c)
		}
	}
	return out
}

func (m *mockFirewall) ruleDescs() []string {
	var out []string
	for _, u := range m.sortedRuleUUIDs() {
		out = append(out, m.rules[u].Description)
	}
	return out
}

func (m *mockFirewall) hostDescs() []string {
	var out []string
	for _, u := range m.sortedHostUUIDs() {
		out = append(out, m.hosts[u].Description)
	}
	return out
}

func (m *mockFirewall) rulesByPrefix(p string) []rule {
	var out []rule
	for _, u := range m.sortedRuleUUIDs() {
		if strings.HasPrefix(m.rules[u].Description, p) {
			out = append(out, m.rules[u])
		}
	}
	return out
}

func testDevice() core.Device {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	return core.Device{
		MAC:    mac,
		IPs:    []netip.Addr{netip.MustParseAddr("192.168.1.44")},
		Vendor: "Raspberry Pi",
	}
}

func otherDevice() core.Device {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:99")
	return core.Device{
		MAC:    mac,
		IPs:    []netip.Addr{netip.MustParseAddr("192.168.1.99")},
		Vendor: "Camera",
	}
}

func newTestClient(t *testing.T, m *mockFirewall) *Client {
	t.Helper()
	c, err := New(Config{
		BaseURL:   "https://192.168.1.1",
		APIKey:    "test-key",
		APISecret: "test-secret",
		Transport: m,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// --- constructor ----------------------------------------------------------

func TestName(t *testing.T) {
	c := newTestClient(t, newMockFirewall())
	if got := c.Name(); got != "opnsense" {
		t.Errorf("Name() = %q, want %q", got, "opnsense")
	}
}

// TestNewRequiresCredentials checks that every error names the Go field at
// fault. A constructor that says "invalid config" sends an operator to read
// the source instead of fixing a typo in one line of YAML.
func TestNewRequiresCredentials(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"no base url", Config{APIKey: "k", APISecret: "s"}, "BaseURL"},
		{"no api key", Config{BaseURL: "https://x", APISecret: "s"}, "APIKey"},
		{"no api secret", Config{BaseURL: "https://x", APIKey: "k"}, "APISecret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.cfg)
			if err == nil {
				t.Fatalf("New must reject %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name the field %q", err, tc.want)
			}
		})
	}
}

// TestNewDefaultsAllowlists guards the foot-gun the constructor closes. With
// an empty allowlist a restricted device is cut off from everything, which is
// a worse outcome than the infection it was meant to contain.
func TestNewDefaultsAllowlists(t *testing.T) {
	c, err := New(Config{BaseURL: "https://x", APIKey: "k", APISecret: "s", Transport: newMockFirewall()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(c.cfg.PeerNets) == 0 {
		t.Error("PeerNets must default so peer blocking has something to block")
	}
	if len(c.cfg.EgressAllow) == 0 {
		t.Error("EgressAllow must default so a restricted device stays remediable")
	}
	if c.cfg.LANInterface != "lan" {
		t.Errorf("LANInterface = %q, want lan", c.cfg.LANInterface)
	}
}

// TestCredentialsAreSentAsBasicAuth proves the key/secret reach the appliance
// in the form it expects. OPNsense reads the API key as the Basic username;
// sending it any other way yields a 401 on every call in production while
// every test still passed against a mock that never checked.
func TestCredentialsAreSentAsBasicAuth(t *testing.T) {
	m := newMockFirewall()
	c := newTestClient(t, m)

	if err := c.Health(context.Background()); err != nil {
		t.Fatalf("Health: %v", err)
	}
	if len(m.log) == 0 {
		t.Fatal("mock recorded no calls")
	}
}

// --- transport and error classification ----------------------------------

func TestTransportErrorsPropagate(t *testing.T) {
	m := newMockFirewall()
	m.transportErr = errors.New("connection refused")
	c := newTestClient(t, m)

	err := c.Health(context.Background())
	if err == nil {
		t.Fatal("a transport failure must surface as an error, not be swallowed")
	}
	// The critical distinction: a transport failure is retryable, so it must
	// not masquerade as a credential problem.
	if errors.Is(err, ErrAuth) || errors.Is(err, ErrForbidden) {
		t.Errorf("transport error classified as an auth error: %v", err)
	}
}

// TestAuthAndForbiddenAreDistinguishedFromTransportFailures is the test that
// stops a revoked API key from being retried forever. A 401 means stop and
// page a human; an unreachable firewall means retry.
func TestAuthAndForbiddenAreDistinguishedFromTransportFailures(t *testing.T) {
	t.Run("401 is auth", func(t *testing.T) {
		m := newMockFirewall()
		m.forceStatus = http.StatusUnauthorized
		c := newTestClient(t, m)

		err := c.Health(context.Background())
		if !errors.Is(err, ErrAuth) {
			t.Errorf("401 must satisfy errors.Is(err, ErrAuth), got %v", err)
		}
		if errors.Is(err, ErrForbidden) {
			t.Errorf("401 must not satisfy ErrForbidden, got %v", err)
		}
	})

	t.Run("403 is forbidden", func(t *testing.T) {
		m := newMockFirewall()
		m.forceStatus = http.StatusForbidden
		c := newTestClient(t, m)

		err := c.Health(context.Background())
		if !errors.Is(err, ErrForbidden) {
			t.Errorf("403 must satisfy errors.Is(err, ErrForbidden), got %v", err)
		}
		if errors.Is(err, ErrAuth) {
			t.Errorf("403 must not satisfy ErrAuth, got %v", err)
		}
	})

	t.Run("500 is neither", func(t *testing.T) {
		m := newMockFirewall()
		m.forceStatus = http.StatusInternalServerError
		c := newTestClient(t, m)

		err := c.Health(context.Background())
		if err == nil {
			t.Fatal("a 500 must be reported as an error")
		}
		if errors.Is(err, ErrAuth) || errors.Is(err, ErrForbidden) {
			t.Errorf("a 500 is not an auth problem: %v", err)
		}
		var se *statusError
		if !errors.As(err, &se) {
			t.Fatalf("want a *statusError, got %T", err)
		}
		if se.Status != http.StatusInternalServerError {
			t.Errorf("statusError.Status = %d, want 500", se.Status)
		}
	})
}

// TestAuthErrorMentionsPrivilegeCaveat keeps the 401 message honest. OPNsense
// releases through 22.1 answer 401 for a missing page privilege, so an
// operator reading "authentication rejected" and rotating a perfectly good key
// would be sent down the wrong path.
func TestAuthErrorMentionsPrivilegeCaveat(t *testing.T) {
	e := &statusError{Method: "POST", Path: "firewall/filter/addRule", Status: http.StatusUnauthorized}
	if !strings.Contains(e.Error(), "privilege") {
		t.Errorf("401 message should mention the page-privilege case, got %q", e.Error())
	}
	f := &statusError{Method: "POST", Path: "firewall/filter/addRule", Status: http.StatusForbidden}
	if !strings.Contains(f.Error(), "privilege") {
		t.Errorf("403 message should name the privilege problem, got %q", f.Error())
	}
}

// TestMalformedResponseBodies covers the three shapes of "200 but wrong" that
// a mock that always returned clean JSON would never produce.
func TestMalformedResponseBodies(t *testing.T) {
	t.Run("search rule returns garbage", func(t *testing.T) {
		m := newMockFirewall()
		m.malformed = `<html>login page</html>`
		c := newTestClient(t, m)

		if err := c.Health(context.Background()); err == nil {
			t.Fatal("a non-JSON body must be reported, not treated as an empty ruleset")
		}
	})

	t.Run("search rule returns a rowset without uuids", func(t *testing.T) {
		m := newMockFirewall()
		m.malformed = `{"total":1,"rowCount":1,"current":1,"rows":[{"description":"x"}]}`
		c := newTestClient(t, m)

		if err := c.Health(context.Background()); err == nil {
			t.Fatal("a row with no uuid must fail Health: it cannot be deleted later")
		}
	})

	t.Run("addRule returns no uuid", func(t *testing.T) {
		m := newMockFirewall()
		m.addRuleUUIDless = true
		c := newTestClient(t, m)

		if err := c.Quarantine(context.Background(), testDevice(), core.PolicyRestrict); err == nil {
			t.Fatal("addRule answering 200 with no uuid must be an error, or the rule is untrackable")
		}
	})

	t.Run("apply reports error status", func(t *testing.T) {
		m := newMockFirewall()
		m.applyStatus = "error"
		c := newTestClient(t, m)

		if err := c.Quarantine(context.Background(), testDevice(), core.PolicyRestrict); err == nil {
			t.Fatal("an apply that reports status=error must not be reported as a successful reload")
		}
	})
}

// --- Health ---------------------------------------------------------------

func TestHealthSucceedsAndReadsRulesBack(t *testing.T) {
	m := newMockFirewall()
	c := newTestClient(t, m)
	ctx := context.Background()

	if err := c.Quarantine(ctx, testDevice(), core.PolicyRestrict); err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	if err := c.Health(ctx); err != nil {
		t.Fatalf("Health: %v", err)
	}
	if len(m.callsTo(epSearchRule)) == 0 {
		t.Error("Health must read the ruleset back, not merely ping the appliance")
	}
}

// TestHealthIsSideEffectFree asserts Health never writes. A Health that
// reconfigured the resolver on every poll would interrupt DNS on the whole
// network every poll interval, and would make a failing Health destructive.
func TestHealthIsSideEffectFree(t *testing.T) {
	m := newMockFirewall()
	c := newTestClient(t, m)

	before := len(m.log)
	if err := c.Health(context.Background()); err != nil {
		t.Fatalf("Health: %v", err)
	}
	for _, cl := range m.log[before:] {
		if cl.Method != http.MethodPost || (cl.Path != epSearchRule && cl.Path != epHostSearch) {
			t.Errorf("Health issued a mutating call: %s %s", cl.Method, cl.Path)
		}
	}
	if m.applied != 0 || m.reconfig != 0 {
		t.Errorf("Health reconfigured state: applied=%d reconfigured=%d", m.applied, m.reconfig)
	}
}

func TestHealthFailsWhenCredentialsAreRejected(t *testing.T) {
	m := newMockFirewall()
	m.forceStatus = http.StatusUnauthorized
	c := newTestClient(t, m)

	if err := c.Health(context.Background()); err == nil {
		t.Fatal("Health must fail on rejected credentials, so new containment is blocked")
	}
}

// --- Authoritative --------------------------------------------------------

func TestAuthoritativePinsResolverIdentity(t *testing.T) {
	m := newMockFirewall()
	c := newTestClient(t, m)

	if err := c.Authoritative(context.Background(), testDevice()); err != nil {
		t.Fatalf("Authoritative: %v", err)
	}
	if len(m.hosts) != 1 {
		t.Fatalf("expected one host override, got %d", len(m.hosts))
	}
	for _, h := range m.hosts {
		if h.Server != "192.168.1.44" {
			t.Errorf("host override server = %q, want the device IP", h.Server)
		}
		if h.RR != "A" {
			t.Errorf("host override rr = %q, want A", h.RR)
		}
		if !strings.HasPrefix(h.Description, descPrefix+" ") {
			t.Errorf("host override %q is not namespaced", h.Description)
		}
	}
	if m.reconfig == 0 {
		t.Error("Authoritative must reconfigure the resolver, or the pin has no effect")
	}
}

func TestAuthoritativeIsIdempotent(t *testing.T) {
	m := newMockFirewall()
	c := newTestClient(t, m)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := c.Authoritative(ctx, testDevice()); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if len(m.hosts) != 1 {
		t.Errorf("Authoritative created %d overrides, want 1", len(m.hosts))
	}
}

// TestAuthoritativeRequiresIdentity asserts the guard that stops a pin being
// written for a device we cannot name, which would resolve some unrelated
// address.
func TestAuthoritativeRequiresIdentity(t *testing.T) {
	m := newMockFirewall()
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
	if len(m.log) != 0 {
		t.Error("a rejected call must not reach the appliance at all")
	}
}

// --- Quarantine -----------------------------------------------------------

func TestQuarantineBlockPeersCreatesBlockRule(t *testing.T) {
	m := newMockFirewall()
	c := newTestClient(t, m)

	if err := c.Quarantine(context.Background(), testDevice(), core.PolicyRestrict); err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	got := m.rulesByPrefix(descQuarantinePrefix("aabbccddee01"))
	if len(got) != 1 {
		t.Fatalf("expected 1 peer rule, got %d (%v)", len(got), m.ruleDescs())
	}
	r := got[0]
	if r.Action != "block" {
		t.Errorf("action = %q, want block", r.Action)
	}
	if len(r.SourceNet) != 1 || r.SourceNet[0] != "192.168.1.44" {
		t.Errorf("source_net = %v, want the device IP", r.SourceNet)
	}
	// Peer blocking must cover the private ranges: that is the set of hosts
	// the device could propagate to without ever touching the internet.
	var sawPrivate bool
	for _, d := range r.DestNet {
		if strings.HasPrefix(d, "192.168.") || strings.HasPrefix(d, "10.") || strings.HasPrefix(d, "172.") {
			sawPrivate = true
		}
	}
	if !sawPrivate {
		t.Errorf("peer rule destinations %v omit the private ranges", r.DestNet)
	}
	if r.Tag != ruleTag {
		t.Errorf("tag = %q, want %q", r.Tag, ruleTag)
	}
	if m.applied == 0 {
		t.Error("Quarantine must apply; a staged rule is not an active one")
	}
}

// TestQuarantineRestrictEgressUsesInvertedDestination pins the walled-garden
// encoding. destination_not=1 means "to anything other than the allowlist",
// which makes the rule self-contained: correctness does not depend on an
// ordering relationship with any other rule.
func TestQuarantineRestrictEgressUsesInvertedDestination(t *testing.T) {
	m := newMockFirewall()
	c := newTestClient(t, m)

	if err := c.Quarantine(context.Background(), testDevice(), core.PolicyQuarantine); err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	got := m.rulesByPrefix(descQuarantinePrefix("aabbccddee01") + "egress")
	if len(got) != 1 {
		t.Fatalf("expected 1 egress rule, got %d (%v)", len(got), m.ruleDescs())
	}
	r := got[0]
	if r.DestNot != "1" {
		t.Errorf("destination_not = %q, want 1 (inverted match)", r.DestNot)
	}
	if r.Action != "block" {
		t.Errorf("action = %q, want block", r.Action)
	}
	if len(r.DestNet) == 0 {
		t.Error("egress rule must name the allowlist it inverts")
	}
}

// TestQuarantineIsIdempotent covers the interface requirement that a repeated
// call leaves the same end state as a single one, with no duplicated rules.
func TestQuarantineIsIdempotent(t *testing.T) {
	m := newMockFirewall()
	c := newTestClient(t, m)
	ctx := context.Background()
	dev := testDevice()

	if err := c.Quarantine(ctx, dev, core.PolicyQuarantine); err != nil {
		t.Fatalf("first Quarantine: %v", err)
	}
	first := len(m.rules)

	for i := 0; i < 3; i++ {
		if err := c.Quarantine(ctx, dev, core.PolicyQuarantine); err != nil {
			t.Fatalf("repeat %d: %v", i, err)
		}
	}
	if len(m.rules) != first {
		t.Errorf("repeated Quarantine left %d rules, want %d (%v)", len(m.rules), first, m.ruleDescs())
	}
}

// TestQuarantineCollapsesDuplicateRules covers the recovery case: a control
// plane that crashed between addRule and apply can leave two copies of the
// same rule. Two copies is not a harmless duplicate — Release would have to
// guess which is authoritative.
func TestQuarantineCollapsesDuplicateRules(t *testing.T) {
	m := newMockFirewall()
	c := newTestClient(t, m)
	ctx := context.Background()
	dev := testDevice()

	if err := c.Quarantine(ctx, dev, core.PolicyRestrict); err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	// Simulate the stranded duplicate.
	m.mu.Lock()
	for _, u := range m.sortedRuleUUIDs() {
		m.rules["orphan-"+u] = m.rules[u]
	}
	dupes := len(m.rules)
	m.mu.Unlock()

	if err := c.Quarantine(ctx, dev, core.PolicyRestrict); err != nil {
		t.Fatalf("repeat Quarantine: %v", err)
	}
	if len(m.rules) >= dupes {
		t.Errorf("duplicates were not collapsed: %d rules remain (%v)", len(m.rules), m.ruleDescs())
	}
}

// TestQuarantineMonitorReleasesInsteadOfBlocking asserts PolicyMonitor is a
// successful no-op that also clears anything a higher tier left behind. Only
// relabelling would leave the device restricted while the control plane
// believed it was merely monitored.
func TestQuarantineMonitorReleasesInsteadOfBlocking(t *testing.T) {
	m := newMockFirewall()
	c := newTestClient(t, m)
	ctx := context.Background()
	dev := testDevice()

	if err := c.Quarantine(ctx, dev, core.PolicyQuarantine); err != nil {
		t.Fatalf("initial Quarantine: %v", err)
	}
	if len(m.rules) == 0 {
		t.Fatal("precondition: expected containment rules")
	}
	if err := c.Quarantine(ctx, dev, core.PolicyMonitor); err != nil {
		t.Fatalf("drop to monitor: %v", err)
	}
	if got := m.rulesByPrefix(descQuarantinePrefix("aabbccddee01")); len(got) != 0 {
		t.Errorf("monitor left %d containment rules in place (%v)", len(got), m.ruleDescs())
	}
}

func TestQuarantineWithNoDeviceIPIsRejected(t *testing.T) {
	m := newMockFirewall()
	c := newTestClient(t, m)

	dev := testDevice()
	dev.IPs = nil
	if err := c.Quarantine(context.Background(), dev, core.PolicyRestrict); err == nil {
		t.Error("Quarantine must reject a device with no IP: a rule with no source matches everything")
	}
	if len(m.log) != 0 {
		t.Error("a rejected call must not reach the appliance")
	}
}

// TestTierDowngradeRemovesRulesTheNewTierDoesNotNeed covers dropping from
// quarantined to restricted. Leaving the egress rule behind would keep the
// device in a walled garden the control plane no longer believes it is in.
func TestTierDowngradeRemovesRulesTheNewTierDoesNotNeed(t *testing.T) {
	m := newMockFirewall()
	c := newTestClient(t, m)
	ctx := context.Background()
	dev := testDevice()

	if err := c.Quarantine(ctx, dev, core.PolicyQuarantine); err != nil {
		t.Fatalf("quarantine tier: %v", err)
	}
	if err := c.Quarantine(ctx, dev, core.PolicyRestrict); err != nil {
		t.Fatalf("restricted tier: %v", err)
	}
	got := m.rulesByPrefix(descQuarantinePrefix("aabbccddee01"))
	if len(got) != 1 {
		t.Fatalf("expected only the peer rule to survive, got %d (%v)", len(got), m.ruleDescs())
	}
	if !strings.HasSuffix(got[0].Description, "peers") {
		t.Errorf("surviving rule = %q, want the peers rule", got[0].Description)
	}
}

// --- Release --------------------------------------------------------------

// TestReleaseRemovesOnlyItsOwnObjects is the guarantee that this tool never
// touches an operator's own configuration or another device's containment.
// The OPNsense firewall is shared state; deleting a rule we did not create
// would destroy somebody's setup.
func TestReleaseRemovesOnlyItsOwnObjects(t *testing.T) {
	m := newMockFirewall()
	c := newTestClient(t, m)
	ctx := context.Background()
	dev := testDevice()

	// An operator's own rule, and a second device's containment.
	m.mu.Lock()
	m.rules["operator-rule"] = rule{Description: "allow ssh from the net", Action: "pass", Tag: "mine"}
	m.mu.Unlock()

	if err := c.Quarantine(ctx, otherDevice(), core.PolicyQuarantine); err != nil {
		t.Fatalf("quarantine other device: %v", err)
	}
	if err := c.Authoritative(ctx, otherDevice()); err != nil {
		t.Fatalf("authoritative other device: %v", err)
	}
	if err := c.Quarantine(ctx, dev, core.PolicyQuarantine); err != nil {
		t.Fatalf("quarantine target device: %v", err)
	}
	if err := c.Authoritative(ctx, dev); err != nil {
		t.Fatalf("authoritative target device: %v", err)
	}

	if err := c.Release(ctx, dev); err != nil {
		t.Fatalf("Release: %v", err)
	}

	if _, ok := m.rules["operator-rule"]; !ok {
		t.Error("Release deleted an operator's rule it did not create")
	}
	if len(m.rulesByPrefix(descQuarantinePrefix("aabbccddee01"))) != 0 {
		t.Error("Release left the target device's containment behind")
	}
	if len(m.rulesByPrefix(descQuarantinePrefix("aabbccddeeff99"))) != 0 {
		t.Error("Release removed another device's containment")
	}
	if len(m.hostDescs()) != 1 {
		t.Errorf("expected the other device's resolver pin to survive, got %v", m.hostDescs())
	}
}

// TestReleaseSucceedsWhenNothingExists is the interface requirement that
// Release must always succeed for a previously quarantined device. The portal
// calls it on a user's confirmation and users double-click.
func TestReleaseSucceedsWhenNothingExists(t *testing.T) {
	m := newMockFirewall()
	c := newTestClient(t, m)

	if err := c.Release(context.Background(), testDevice()); err != nil {
		t.Errorf("Release on an untouched device must succeed, got %v", err)
	}
	// Nothing was touched, so nothing should be reloaded. Reloading the
	// firewall and the resolver for a no-op would interrupt the whole
	// network's DNS every time the portal was opened.
	if m.applied != 0 {
		t.Errorf("Release reloaded the firewall %d times for a no-op", m.applied)
	}
	if m.reconfig != 0 {
		t.Errorf("Release reconfigured the resolver %d times for a no-op", m.reconfig)
	}
}

func TestReleaseIsIdempotent(t *testing.T) {
	m := newMockFirewall()
	c := newTestClient(t, m)
	ctx := context.Background()
	dev := testDevice()

	if err := c.Quarantine(ctx, dev, core.PolicyQuarantine); err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	if err := c.Authoritative(ctx, dev); err != nil {
		t.Fatalf("Authoritative: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := c.Release(ctx, dev); err != nil {
			t.Fatalf("Release %d: %v", i, err)
		}
	}
	if len(m.rulesByPrefix(descQuarantinePrefix("aabbccddee01"))) != 0 {
		t.Errorf("Release left rules behind: %v", m.ruleDescs())
	}
	if len(m.hostDescs()) != 0 {
		t.Errorf("Release left resolver overrides behind: %v", m.hostDescs())
	}
}

func TestReleaseRequiresMAC(t *testing.T) {
	m := newMockFirewall()
	c := newTestClient(t, m)

	dev := testDevice()
	dev.MAC = nil
	if err := c.Release(context.Background(), dev); err == nil {
		t.Error("Release must reject a device with no MAC")
	}
	if len(m.log) != 0 {
		t.Error("a rejected call must not reach the appliance")
	}
}

// --- BlockNet -------------------------------------------------------------

// TestBlockNetCarriesUntil pins the one thing this backend can do about
// expiry. OPNsense has no rule TTL and no schedule API, so the deadline is
// recorded in the rule's own description; without that record an orphaned
// block is indistinguishable from a deliberate permanent one.
func TestBlockNetCarriesUntil(t *testing.T) {
	m := newMockFirewall()
	c := newTestClient(t, m)

	until := time.Now().Add(time.Hour).Truncate(time.Second)
	if err := c.BlockNet(context.Background(), netip.MustParsePrefix("203.0.113.0/24"), until); err != nil {
		t.Fatalf("BlockNet: %v", err)
	}
	got := m.rulesByPrefix(descPrefix + " " + kindNetBlock + " ")
	if len(got) != 1 {
		t.Fatalf("expected 1 block rule, got %d (%v)", len(got), m.ruleDescs())
	}
	r := got[0]
	if len(r.DestNet) != 1 || r.DestNet[0] != "203.0.113.0/24" {
		t.Errorf("destination = %v, want the blocked prefix", r.DestNet)
	}
	recorded, ok := recordedUntil(r.Description)
	if !ok {
		t.Fatalf("rule %q carries no recorded expiry", r.Description)
	}
	if recorded != until.Unix() {
		t.Errorf("recorded until = %d, want %d", recorded, until.Unix())
	}
	if r.Tag != ruleTag {
		t.Errorf("tag = %q, want %q", r.Tag, ruleTag)
	}
	if m.applied == 0 {
		t.Error("BlockNet must apply the filter")
	}
}

func TestBlockNetPicksIPv4OrIPv6Rule(t *testing.T) {
	m := newMockFirewall()
	c := newTestClient(t, m)

	if err := c.BlockNet(context.Background(), netip.MustParsePrefix("203.0.113.0/24"), time.Now()); err != nil {
		t.Fatalf("BlockNet v4: %v", err)
	}
	if err := c.BlockNet(context.Background(), netip.MustParsePrefix("2001:db8::/32"), time.Now()); err != nil {
		t.Fatalf("BlockNet v6: %v", err)
	}
	for _, r := range m.rules {
		switch {
		case strings.Contains(r.Description, "203.0.113.0/24") && r.IPProtocol != "inet":
			t.Errorf("IPv4 block has ipprotocol %q, want inet", r.IPProtocol)
		case strings.Contains(r.Description, "2001:db8::/32") && r.IPProtocol != "inet6":
			t.Errorf("IPv6 block has ipprotocol %q, want inet6", r.IPProtocol)
		}
	}
}

// TestBlockNetIsIdempotentAcrossDeadlines covers the leak that an exact
// description match would cause: re-blocking the same prefix with a later
// deadline must rewrite the existing rule, not add a second one and strand
// the first.
func TestBlockNetIsIdempotentAcrossDeadlines(t *testing.T) {
	m := newMockFirewall()
	c := newTestClient(t, m)
	ctx := context.Background()
	prefix := netip.MustParsePrefix("203.0.113.0/24")

	first := time.Now().Add(time.Hour).Truncate(time.Second)
	if err := c.BlockNet(ctx, prefix, first); err != nil {
		t.Fatalf("first BlockNet: %v", err)
	}
	if len(m.rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(m.rules))
	}
	later := first.Add(time.Hour)
	if err := c.BlockNet(ctx, prefix, later); err != nil {
		t.Fatalf("second BlockNet: %v", err)
	}
	if len(m.rules) != 1 {
		t.Fatalf("re-blocking left %d rules, want 1 (%v)", len(m.rules), m.ruleDescs())
	}
	got := m.rulesByPrefix(descPrefix + " " + kindNetBlock + " ")
	recorded, ok := recordedUntil(got[0].Description)
	if !ok || recorded != later.Unix() {
		t.Errorf("deadline was not updated: %q", got[0].Description)
	}
}

// --- BlockDomain ----------------------------------------------------------

func TestBlockDomainSinkholesThroughUnbound(t *testing.T) {
	m := newMockFirewall()
	c := newTestClient(t, m)

	until := time.Now().Add(time.Hour).Truncate(time.Second)
	if err := c.BlockDomain(context.Background(), "Malicious.Example", until); err != nil {
		t.Fatalf("BlockDomain: %v", err)
	}
	if len(m.hosts) != 1 {
		t.Fatalf("expected 1 host override, got %d", len(m.hosts))
	}
	for _, h := range m.hosts {
		// Domains are case-insensitive; sinking "Malicious.Example" while
		// letting "malicious.example" resolve would make the block trivial to
		// bypass with a one-character edit.
		if h.Domain != "malicious.example" {
			t.Errorf("domain = %q, want the lowercased form", h.Domain)
		}
		if h.Server == "" || h.Server == "0.0.0.0" {
			t.Errorf("sinkhole server = %q, want a non-routable address", h.Server)
		}
		// A sinkhole is not a host and must not appear in reverse lookups.
		if h.AddPTR != "0" {
			t.Errorf("addptr = %q, want 0", h.AddPTR)
		}
		recorded, ok := recordedUntil(h.Description)
		if !ok || recorded != until.Unix() {
			t.Errorf("override %q carries no recorded expiry", h.Description)
		}
	}
	if m.reconfig == 0 {
		t.Error("BlockDomain must reconfigure the resolver")
	}
}

func TestBlockDomainRejectsMalformedInput(t *testing.T) {
	m := newMockFirewall()
	c := newTestClient(t, m)

	for _, bad := range []string{"", "   ", "bad domain", "bad..example", "-lead.example", strings.Repeat("a", 64) + ".example"} {
		if err := c.BlockDomain(context.Background(), bad, time.Now()); err == nil {
			t.Errorf("BlockDomain(%q) must be rejected", bad)
		}
	}
	if len(m.log) != 0 {
		t.Error("a rejected domain must not reach the appliance")
	}
}

func TestBlockDomainIsIdempotentAcrossDeadlines(t *testing.T) {
	m := newMockFirewall()
	c := newTestClient(t, m)
	ctx := context.Background()

	first := time.Now().Add(time.Hour).Truncate(time.Second)
	if err := c.BlockDomain(ctx, "bad.example", first); err != nil {
		t.Fatalf("first BlockDomain: %v", err)
	}
	if err := c.BlockDomain(ctx, "bad.example", first.Add(time.Hour)); err != nil {
		t.Fatalf("second BlockDomain: %v", err)
	}
	if len(m.hosts) != 1 {
		t.Errorf("re-sinking left %d overrides, want 1", len(m.hosts))
	}
}

// --- ReapExpired ----------------------------------------------------------

// TestReapExpiredCoversBothMechanisms is the compensating control for the
// documented limitation that OPNsense cannot expire a rule itself.
func TestReapExpiredCoversBothMechanisms(t *testing.T) {
	m := newMockFirewall()
	c := newTestClient(t, m)
	ctx := context.Background()

	expired := time.Now().Add(-time.Minute).Truncate(time.Second)
	live := time.Now().Add(time.Hour).Truncate(time.Second)

	if err := c.BlockNet(ctx, netip.MustParsePrefix("203.0.113.0/24"), expired); err != nil {
		t.Fatalf("BlockNet: %v", err)
	}
	if err := c.BlockDomain(ctx, "bad.example", expired); err != nil {
		t.Fatalf("BlockDomain: %v", err)
	}
	if err := c.BlockNet(ctx, netip.MustParsePrefix("198.51.100.0/24"), live); err != nil {
		t.Fatalf("BlockNet live: %v", err)
	}
	// An operator's own untagged rule must never be reaped.
	m.mu.Lock()
	m.rules["operator-rule"] = rule{Description: "operator block until 1"}
	m.mu.Unlock()

	n, err := c.ReapExpired(ctx, time.Now())
	if err != nil {
		t.Fatalf("ReapExpired: %v", err)
	}
	if n != 2 {
		t.Errorf("reaped %d objects, want 2", n)
	}
	if _, ok := m.rules["operator-rule"]; !ok {
		t.Error("ReapExpired deleted an operator's rule it does not own")
	}
	if len(m.rulesByPrefix(descPrefix+" "+kindNetBlock+" ")) != 1 {
		t.Errorf("a live block was reaped: %v", m.ruleDescs())
	}
	if len(m.hosts) != 0 {
		t.Errorf("expired sinkhole survived: %v", m.hostDescs())
	}
}

func TestReapExpiredOnCleanRouterIsANoOp(t *testing.T) {
	m := newMockFirewall()
	c := newTestClient(t, m)

	n, err := c.ReapExpired(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("ReapExpired: %v", err)
	}
	if n != 0 {
		t.Errorf("reaped %d objects from a clean router, want 0", n)
	}
	if m.applied != 0 || m.reconfig != 0 {
		t.Error("ReapExpired must not reconfigure anything when nothing expired")
	}
}

// --- namespacing ----------------------------------------------------------

// TestEveryCreatedObjectIsNamespaced is the standing guarantee that Release
// can distinguish this tool's objects from an operator's.
func TestEveryCreatedObjectIsNamespaced(t *testing.T) {
	m := newMockFirewall()
	c := newTestClient(t, m)
	ctx := context.Background()
	dev := testDevice()

	for _, fn := range []func() error{
		func() error { return c.Authoritative(ctx, dev) },
		func() error { return c.Quarantine(ctx, dev, core.PolicyQuarantine) },
		func() error { return c.BlockNet(ctx, netip.MustParsePrefix("203.0.113.0/24"), time.Now()) },
		func() error { return c.BlockDomain(ctx, "bad.example", time.Now()) },
	} {
		if err := fn(); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}
	for _, d := range m.ruleDescs() {
		if !strings.HasPrefix(d, descPrefix+" ") {
			t.Errorf("rule %q is not namespaced", d)
		}
	}
	for _, d := range m.hostDescs() {
		if !strings.HasPrefix(d, descPrefix+" ") {
			t.Errorf("host override %q is not namespaced", d)
		}
	}
}

// TestDescriptionsStayWithinTheModelLimits guards against a field the model
// rejects. Filter.xml caps `tag` at 512 characters of [0-9a-zA-Z.,_-] and
// `description` at 255; a description that overruns is silently dropped by
// the appliance, which would remove the very marker Release depends on.
func TestDescriptionsStayWithinTheModelLimits(t *testing.T) {
	m := newMockFirewall()
	c := newTestClient(t, m)
	ctx := context.Background()

	longVendor := core.Device{
		MAC:    mustMAC("aa:bb:cc:dd:ee:01"),
		IPs:    []netip.Addr{netip.MustParseAddr("192.168.1.44")},
		Vendor: strings.Repeat("Acme IoT Device ", 20),
	}
	if err := c.Authoritative(ctx, longVendor); err != nil {
		t.Fatalf("Authoritative: %v", err)
	}
	if err := c.BlockDomain(ctx, strings.Repeat("sub.", 60)+"example", time.Now()); err != nil {
		t.Fatalf("BlockDomain: %v", err)
	}
	for _, r := range m.rules {
		if len(r.Tag) > 512 {
			t.Errorf("tag is %d characters, model caps it at 512", len(r.Tag))
		}
		for _, ch := range r.Tag {
			if !strings.ContainsRune("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.,_-", ch) {
				t.Errorf("tag %q contains %q, which the model mask rejects", r.Tag, ch)
			}
		}
		if len(r.Description) > 255 {
			t.Errorf("description %q is %d characters, model caps it at 255", r.Description, len(r.Description))
		}
	}
	for _, h := range m.hosts {
		if len(h.Description) > 255 {
			t.Errorf("host description %q is %d characters, model caps it at 255", h.Description, len(h.Description))
		}
		if len(h.Hostname) > 63 {
			t.Errorf("hostname %q is %d characters, Unbound labels cap at 63", h.Hostname, len(h.Hostname))
		}
	}
}

func mustMAC(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

// --- helpers --------------------------------------------------------------

func TestObjectKeyStripsOnlyTheDeadline(t *testing.T) {
	cases := []struct {
		desc string
		want string
	}{
		{"R0-Invader n 203.0.113.0/24 until 1700000000", "R0-Invader n 203.0.113.0/24"},
		{"R0-Invader d bad.example until 1700000000", "R0-Invader d bad.example"},
		{"R0-Invader q aabbccddeeff peers", "R0-Invader q aabbccddeeff peers"},
	}
	for _, tc := range cases {
		if got := objectKey(tc.desc); got != tc.want {
			t.Errorf("objectKey(%q) = %q, want %q", tc.desc, got, tc.want)
		}
	}
}

// TestRecordedUntilRejectsGarbage keeps ReapExpired from deleting on a
// mis-parsed deadline. A rule whose description ends in something
// non-numeric must be left alone, not treated as expired.
func TestRecordedUntilRejectsGarbage(t *testing.T) {
	if _, ok := recordedUntil("R0-Invader n 203.0.113.0/24"); ok {
		t.Error("a description with no deadline must not report one")
	}
	if _, ok := recordedUntil("R0-Invader n 203.0.113.0/24 until forever"); ok {
		t.Error("a non-numeric deadline must not parse")
	}
	if n, ok := recordedUntil("R0-Invader n 203.0.113.0/24 until 1700000000"); !ok || n != 1700000000 {
		t.Errorf("recordedUntil = %d, %v; want 1700000000, true", n, ok)
	}
}

func TestNormalizeDomainTrimsAndLowercases(t *testing.T) {
	got, err := normalizeDomain("  WWW.Example.COM.  ")
	if err != nil {
		t.Fatalf("normalizeDomain: %v", err)
	}
	if got != "www.example.com" {
		t.Errorf("normalizeDomain = %q, want www.example.com", got)
	}
}

func TestSnippetTruncatesLongBodies(t *testing.T) {
	long := strings.Repeat("x", 1000)
	if got := snippet([]byte(long)); len(got) > 300 {
		t.Errorf("snippet returned %d characters; it must be loggable", len(got))
	}
	if got := snippet([]byte("  short  ")); got != "short" {
		t.Errorf("snippet = %q, want trimmed %q", got, "short")
	}
}

func TestOnOff(t *testing.T) {
	if onOff(true) != "1" || onOff(false) != "0" {
		t.Error("OPNsense booleans are the strings \"1\" and \"0\", not JSON literals")
	}
}

func TestIPProtocolFor(t *testing.T) {
	if got := ipProtocolFor(netip.MustParsePrefix("203.0.113.0/24")); got != "inet" {
		t.Errorf("ipProtocolFor(v4) = %q, want inet", got)
	}
	if got := ipProtocolFor(netip.MustParsePrefix("2001:db8::/32")); got != "inet6" {
		t.Errorf("ipProtocolFor(v6) = %q, want inet6", got)
	}
}

// TestSortStringsKeepsMockOutputDetermistic keeps failure messages readable;
// the mock iterates maps, whose order Go randomises per run.
func TestSortStringsKeepsMockOutputDeterminctive(t *testing.T) {
	in := []string{"c", "a", "b"}
	sortStrings(in)
	for i := 1; i < len(in); i++ {
		if in[i] < in[i-1] {
			t.Fatalf("sortStrings left %v unsorted", in)
		}
	}
}

var _ = strconv.Itoa
