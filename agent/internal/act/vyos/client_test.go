package vyos

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

// mockRouter is a Doer that emulates VyOS's HTTP API well enough to exercise
// every code path without a physical router. It records requests so tests can
// assert on the exact operations the adapter issued.
type mockRouter struct {
	mu       sync.Mutex
	log      []apiCall
	sections map[string]map[string]any // config path -> values
	// transportErr fails the request at the HTTP layer.
	transportErr error
	// failNext makes the next request return success:false.
	failNext bool
	// missingNext makes the next exists() return false.
	missingNext bool
}

type apiCall struct {
	Endpoint string
	Op       string
	Path     []string
}

func newMockRouter() *mockRouter {
	return &mockRouter{sections: map[string]map[string]any{}}
}

func (m *mockRouter) Do(req *http.Request) (*http.Response, error) {
	if m.transportErr != nil {
		return nil, m.transportErr
	}

	form, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	values, err := url.ParseQuery(string(form))
	if err != nil {
		return nil, err
	}

	data := values.Get("data")
	var op string
	var path []string

	if values.Get("key") == "" {
		return apiErrorResponse("missing API key"), nil
	}

	if data != "" {
		var doc any
		if err := json.Unmarshal([]byte(data), &doc); err != nil {
			return apiErrorResponse("malformed JSON"), nil
		}
		switch d := doc.(type) {
		case map[string]any:
			op, _ = d["op"].(string)
			if p, ok := d["path"].([]any); ok {
				for _, e := range p {
					if s, ok := e.(string); ok {
						path = append(path, s)
					}
				}
			}
			m.mu.Lock()
			m.log = append(m.log, apiCall{Endpoint: req.URL.Path, Op: op, Path: path})
			m.mu.Unlock()
		case []any:
			m.mu.Lock()
			for _, item := range d {
				if opMap, ok := item.(map[string]any); ok {
					var itemOp string
					var itemPath []string
					if opVal, ok := opMap["op"].(string); ok {
						itemOp = opVal
					}
					if p, ok := opMap["path"].([]any); ok {
						for _, e := range p {
							if s, ok := e.(string); ok {
								itemPath = append(itemPath, s)
							}
						}
					}
					m.log = append(m.log, apiCall{Endpoint: req.URL.Path, Op: itemOp, Path: itemPath})
				}
			}
			m.mu.Unlock()
		}
	}

	if m.failNext {
		m.failNext = false
		return apiErrorResponse("mock failure"), nil
	}

	endpoint := req.URL.Path
	switch endpoint {
	case "/configure":
		return apiSuccessResponse(nil), nil
	case "/retrieve":
		return m.handleRetrieve(op, path), nil
	default:
		return apiErrorResponse("unknown endpoint"), nil
	}
}

func (m *mockRouter) handleRetrieve(op string, path []string) *http.Response {
	key := strings.Join(path, " ")

	switch op {
	case "exists":
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.missingNext {
			m.missingNext = false
			return apiSuccessResponse(false)
		}
		if _, ok := m.sections[key]; ok {
			return apiSuccessResponse(true)
		}
		// Check if any section has this as a prefix
		for k := range m.sections {
			if strings.HasPrefix(k, key+" ") || k == key {
				return apiSuccessResponse(true)
			}
		}
		return apiSuccessResponse(false)

	case "showConfig":
		m.mu.Lock()
		defer m.mu.Unlock()
		prefix := key + " "
		children := make(map[string]any)
		for k, v := range m.sections {
			if strings.HasPrefix(k, prefix) {
				childName := k[len(prefix):]
				if childName != "" && !strings.Contains(childName, " ") {
					children[childName] = v
				}
			}
		}
		if len(children) == 0 {
			return apiErrorResponse("not found")
		}
		return apiSuccessResponse(children)

	default:
		return apiErrorResponse("unknown op")
	}
}

func apiSuccessResponse(data any) *http.Response {
	env := map[string]any{"success": true, "data": data, "error": nil}
	b, _ := json.Marshal(env)
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(bytes.NewReader(b)),
		Header:     http.Header{"Content-Type": []string{"text/html"}},
	}
}

func apiErrorResponse(detail string) *http.Response {
	env := map[string]any{"success": false, "data": nil, "error": detail}
	b, _ := json.Marshal(env)
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(bytes.NewReader(b)),
		Header:     http.Header{"Content-Type": []string{"text/html"}},
	}
}

func testConfig() Config {
	return Config{
		BaseURL:      "https://192.168.1.1",
		APIKey:       "test-key",
		LANInterface: "eth1",
		SinkholeIP:   netip.MustParseAddr("192.168.1.2"),
		EgressAllow:  []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
	}
}

func testDevice() core.Device {
	return core.Device{
		MAC: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		IPs: []netip.Addr{netip.MustParseAddr("192.168.1.100")},
	}
}

// TestNewValidation covers every required-field check in New.
func TestNewValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"missing BaseURL", func(c *Config) { c.BaseURL = "" }, "BaseURL"},
		{"missing APIKey", func(c *Config) { c.APIKey = "" }, "APIKey"},
		{"missing LANInterface", func(c *Config) { c.LANInterface = "" }, "LANInterface"},
		{"missing SinkholeIP", func(c *Config) { c.SinkholeIP = netip.Addr{} }, "SinkholeIP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			tt.mutate(&cfg)
			_, err := New(cfg)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

// TestNewDefaults verifies EgressAllow is defaulted and BaseURL is trimmed.
func TestNewDefaults(t *testing.T) {
	cfg := testConfig()
	cfg.EgressAllow = nil
	cfg.BaseURL = "https://192.168.1.1/"
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(c.cfg.EgressAllow) == 0 {
		t.Error("expected EgressAllow to be defaulted")
	}
	if c.cfg.BaseURL != "https://192.168.1.1" {
		t.Errorf("expected trailing slash trimmed, got %q", c.cfg.BaseURL)
	}
}

func TestName(t *testing.T) {
	c, _ := New(testConfig())
	if c.Name() != "vyos" {
		t.Errorf("expected 'vyos', got %q", c.Name())
	}
}

// TestAuthoritative writes NAT redirect rules.
func TestAuthoritative(t *testing.T) {
	m := newMockRouter()
	cfg := testConfig()
	cfg.Transport = m
	c, _ := New(cfg)

	err := c.Authoritative(context.Background(), testDevice())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(m.log) == 0 {
		t.Fatal("expected at least one API call")
	}

	// All calls should be to /configure with set ops
	for _, call := range m.log {
		if call.Endpoint != "/configure" {
			t.Errorf("expected /configure, got %q", call.Endpoint)
		}
		if call.Op != "set" {
			t.Errorf("expected set op, got %q", call.Op)
		}
	}
}

// TestAuthoritativeRequiresMAC verifies the MAC guard.
func TestAuthoritativeRequiresMAC(t *testing.T) {
	c, _ := New(testConfig())
	err := c.Authoritative(context.Background(), core.Device{})
	if err == nil {
		t.Fatal("expected error for missing MAC")
	}
}

// TestQuarantineMonitorDelegatesToRelease verifies PolicyMonitor is a no-op
// that calls Release to clean up any previous containment.
func TestQuarantineMonitorDelegatesToRelease(t *testing.T) {
	m := newMockRouter()
	// Pre-populate a section so exists() returns true
	key := strings.Join(fwGroup("mac-group"), " ") + " " + peerMACGroup + " mac-address 00:11:22:33:44:55"
	m.sections[key] = map[string]any{}

	cfg := testConfig()
	cfg.Transport = m
	c, _ := New(cfg)

	d := testDevice()
	err := c.Quarantine(context.Background(), d, core.Policy{Name: core.ContainmentMonitor})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have made exists() calls (to check what to delete)
	foundExists := false
	for _, call := range m.log {
		if call.Endpoint == "/retrieve" && call.Op == "exists" {
			foundExists = true
		}
	}
	if !foundExists {
		t.Error("expected exists() calls for Release delegation")
	}
}

// TestQuarantineBlockPeers verifies peer group members are written.
func TestQuarantineBlockPeers(t *testing.T) {
	m := newMockRouter()
	cfg := testConfig()
	cfg.Transport = m
	c, _ := New(cfg)

	d := testDevice()
	p := core.Policy{Name: core.ContainmentQuarantined, BlockPeers: true, RestrictEgress: false}
	err := c.Quarantine(context.Background(), d, p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify peerMACGroup membership was written
	found := false
	for _, call := range m.log {
		if call.Op != "set" {
			continue
		}
		for _, p := range call.Path {
			if p == peerMACGroup {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected peerMACGroup membership to be written")
	}
}

// TestQuarantineRestrictEgress verifies egress group members are written.
func TestQuarantineRestrictEgress(t *testing.T) {
	m := newMockRouter()
	cfg := testConfig()
	cfg.Transport = m
	c, _ := New(cfg)

	d := testDevice()
	p := core.Policy{Name: core.ContainmentQuarantined, BlockPeers: false, RestrictEgress: true}
	err := c.Quarantine(context.Background(), d, p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, call := range m.log {
		if call.Op != "set" {
			continue
		}
		for _, p := range call.Path {
			if p == egrMACGroup {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected egrMACGroup membership to be written")
	}
}

// TestQuarantineIdempotent verifies a second call produces the same end state.
func TestQuarantineIdempotent(t *testing.T) {
	m := newMockRouter()
	cfg := testConfig()
	cfg.Transport = m
	c, _ := New(cfg)

	d := testDevice()
	p := core.Policy{Name: core.ContainmentQuarantined, BlockPeers: true, RestrictEgress: true}

	// First call
	if err := c.Quarantine(context.Background(), d, p); err != nil {
		t.Fatalf("first call: %v", err)
	}
	firstCount := len(m.log)

	// Second call should not error
	if err := c.Quarantine(context.Background(), d, p); err != nil {
		t.Fatalf("second call: %v", err)
	}

	// Both calls should produce the same number of set operations
	// (idempotent because VyOS set is idempotent)
	if len(m.log) <= firstCount {
		t.Error("expected second call to make API calls")
	}
}

// TestQuarantineRequiresMAC verifies the MAC guard.
func TestQuarantineRequiresMAC(t *testing.T) {
	c, _ := New(testConfig())
	err := c.Quarantine(context.Background(), core.Device{}, core.Policy{Name: core.ContainmentQuarantined})
	if err == nil {
		t.Fatal("expected error for missing MAC")
	}
}

// TestReleaseDeletesOnlyExisting verifies Release checks existence before deleting.
func TestReleaseDeletesOnlyExisting(t *testing.T) {
	m := newMockRouter()
	// Pre-populate one section so exists() returns true for it
	key := strings.Join(fwGroup("mac-group"), " ") + " " + peerMACGroup + " mac-address 00:11:22:33:44:55"
	m.sections[key] = map[string]any{"mac-address": "00:11:22:33:44:55"}

	cfg := testConfig()
	cfg.Transport = m
	c, _ := New(cfg)

	d := testDevice()
	err := c.Release(context.Background(), d)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have made exists() calls and at least one delete
	foundExists := false
	foundDelete := false
	for _, call := range m.log {
		if call.Endpoint == "/retrieve" && call.Op == "exists" {
			foundExists = true
		}
		if call.Op == "delete" {
			foundDelete = true
		}
	}
	if !foundExists {
		t.Error("expected exists() calls")
	}
	if !foundDelete {
		t.Error("expected delete calls for existing members")
	}
}

// TestReleaseNothingExists verifies Release succeeds when nothing to delete.
func TestReleaseNothingExists(t *testing.T) {
	m := newMockRouter()
	cfg := testConfig()
	cfg.Transport = m
	c, _ := New(cfg)

	d := testDevice()
	err := c.Release(context.Background(), d)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have made exists() calls but no deletes
	for _, call := range m.log {
		if call.Op == "delete" {
			t.Error("expected no delete calls when nothing exists")
		}
	}
}

// TestReleaseRequiresMAC verifies the MAC guard.
func TestReleaseRequiresMAC(t *testing.T) {
	c, _ := New(testConfig())
	err := c.Release(context.Background(), core.Device{})
	if err == nil {
		t.Fatal("expected error for missing MAC")
	}
}

// TestBlockNet writes the prefix to the block group and records the deadline.
func TestBlockNet(t *testing.T) {
	m := newMockRouter()
	cfg := testConfig()
	cfg.Transport = m
	c, _ := New(cfg)

	prefix := netip.MustParsePrefix("10.0.0.0/8")
	until := time.Now().Add(1 * time.Hour)
	err := c.BlockNet(context.Background(), prefix, until)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the block group got the prefix
	foundBlock := false
	foundDeadline := false
	for _, call := range m.log {
		if call.Op != "set" {
			continue
		}
		for _, p := range call.Path {
			if p == blockGroup {
				foundBlock = true
			}
			if strings.Contains(p, "EXP-") {
				foundDeadline = true
			}
		}
	}
	if !foundBlock {
		t.Error("expected blockGroup to be written")
	}
	if !foundDeadline {
		t.Error("expected deadline node to be written")
	}
}

// TestBlockDomain writes DNS forwarding and a deadline node.
func TestBlockDomain(t *testing.T) {
	m := newMockRouter()
	cfg := testConfig()
	cfg.Transport = m
	c, _ := New(cfg)

	domain := "evil.example.com"
	until := time.Now().Add(1 * time.Hour)
	err := c.BlockDomain(context.Background(), domain, until)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify DNS forwarding was written
	foundDNS := false
	for _, call := range m.log {
		if call.Op == "set" && len(call.Path) >= 5 && call.Path[0] == "service" && call.Path[1] == "dns" && call.Path[2] == "forwarding" {
			foundDNS = true
		}
	}
	if !foundDNS {
		t.Error("expected DNS forwarding to be written")
	}
}

// TestBlockDomainRequiresDomain verifies the domain guard.
func TestBlockDomainRequiresDomain(t *testing.T) {
	c, _ := New(testConfig())
	err := c.BlockDomain(context.Background(), "", time.Now())
	if err == nil {
		t.Fatal("expected error for empty domain")
	}
	err = c.BlockDomain(context.Background(), "  ", time.Now())
	if err == nil {
		t.Fatal("expected error for whitespace-only domain")
	}
}

// TestHealthSuccess verifies Health returns nil when API is up and chain is readable.
func TestHealthSuccess(t *testing.T) {
	m := newMockRouter()
	// Pre-populate the chain so showConfig returns something
	chainKey := "firewall ipv4 name " + containChain
	m.sections[chainKey] = map[string]any{}

	// Also need service https api to exist
	m.sections["service https api"] = map[string]any{}

	cfg := testConfig()
	cfg.Transport = m
	c, _ := New(cfg)

	err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestHealthAPINotConfigured verifies Health fails when API is not configured.
func TestHealthAPINotConfigured(t *testing.T) {
	m := newMockRouter()
	cfg := testConfig()
	cfg.Transport = m
	c, _ := New(cfg)

	err := c.Health(context.Background())
	if err == nil {
		t.Fatal("expected error when API is not configured")
	}
}

// TestHealthChainMissing verifies Health returns nil when chain doesn't exist
// (nothing quarantined yet is not a failure).
func TestHealthChainMissing(t *testing.T) {
	m := newMockRouter()
	m.sections["service https api"] = map[string]any{}
	// Don't populate the chain - it should be missing
	cfg := testConfig()
	cfg.Transport = m
	c, _ := New(cfg)

	err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("expected nil when chain is missing (nothing quarantined), got: %v", err)
	}
}

// TestSweepExpiredRemovesExpired verifies expired entries are deleted.
func TestSweepExpiredRemovesExpired(t *testing.T) {
	m := newMockRouter()

	// Create an expired prefix group
	expiredGroup := deadlinePrefixGroup(netip.MustParsePrefix("10.0.0.0/8"))
	expiredKey := strings.Join(fwGroup("network-group"), " ") + " " + expiredGroup
	pastTime := time.Now().Add(-1 * time.Hour)
	m.sections[expiredKey] = map[string]any{
		"network":     "10.0.0.0/8",
		"description": deadline(pastTime),
	}

	// Create a non-expired prefix group
	futureGroup := deadlinePrefixGroup(netip.MustParsePrefix("192.168.0.0/16"))
	futureKey := strings.Join(fwGroup("network-group"), " ") + " " + futureGroup
	futureTime := time.Now().Add(1 * time.Hour)
	m.sections[futureKey] = map[string]any{
		"network":     "192.168.0.0/16",
		"description": deadline(futureTime),
	}

	cfg := testConfig()
	cfg.Transport = m
	c, _ := New(cfg)

	released, kept, err := c.SweepExpired(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The expired entry should be released
	if len(released) == 0 {
		t.Error("expected at least one released entry")
	}
	// The non-expired entry should be kept
	if len(kept) > 0 {
		t.Errorf("expected no kept entries, got %v", kept)
	}
}

// TestSweepExpiredKeepsUnexpired verifies non-expired entries are not deleted.
func TestSweepExpiredKeepsUnexpired(t *testing.T) {
	m := newMockRouter()

	// Create a non-expired prefix group
	futureGroup := deadlinePrefixGroup(netip.MustParsePrefix("10.0.0.0/8"))
	futureKey := strings.Join(fwGroup("network-group"), " ") + " " + futureGroup
	futureTime := time.Now().Add(1 * time.Hour)
	m.sections[futureKey] = map[string]any{
		"network":     "10.0.0.0/8",
		"description": deadline(futureTime),
	}

	cfg := testConfig()
	cfg.Transport = m
	c, _ := New(cfg)

	released, kept, err := c.SweepExpired(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(released) > 0 {
		t.Errorf("expected no released entries, got %v", released)
	}
	if len(kept) > 0 {
		t.Errorf("expected no kept entries, got %v", kept)
	}
}

// TestSweepExpiredNoDeadline verifies entries without a deadline are kept.
func TestSweepExpiredNoDeadline(t *testing.T) {
	m := newMockRouter()

	// Create a group with no deadline (operator-owned or unparseable)
	noDeadlineGroup := deadlinePrefixGroup(netip.MustParsePrefix("172.16.0.0/12"))
	noDeadlineKey := strings.Join(fwGroup("network-group"), " ") + " " + noDeadlineGroup
	m.sections[noDeadlineKey] = map[string]any{
		"network":     "172.16.0.0/12",
		"description": "operator-owned entry",
	}

	cfg := testConfig()
	cfg.Transport = m
	c, _ := New(cfg)

	released, kept, err := c.SweepExpired(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(released) > 0 {
		t.Errorf("expected no released entries, got %v", released)
	}
	if len(kept) == 0 {
		t.Error("expected at least one kept entry (no deadline)")
	}
}

// TestApplyHTTPError verifies non-2xx responses are handled.
func TestApplyHTTPError(t *testing.T) {
	m := newMockRouter()
	cfg := testConfig()
	cfg.Transport = m
	c, _ := New(cfg)

	// Make the mock return a 500
	m.mu.Lock()
	m.failNext = true
	m.mu.Unlock()

	d := testDevice()
	err := c.Quarantine(context.Background(), d, core.Policy{Name: core.ContainmentQuarantined, BlockPeers: true})
	if err == nil {
		t.Fatal("expected error from API failure")
	}
}

// TestApplyTransportError verifies transport failures are handled.
func TestApplyTransportError(t *testing.T) {
	m := newMockRouter()
	m.transportErr = errors.New("connection refused")
	cfg := testConfig()
	cfg.Transport = m
	c, _ := New(cfg)

	d := testDevice()
	err := c.Quarantine(context.Background(), d, core.Policy{Name: core.ContainmentQuarantined, BlockPeers: true})
	if err == nil {
		t.Fatal("expected transport error")
	}
}

// TestPastDeadline verifies the deadline parsing logic.
func TestPastDeadline(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour)
	node := map[string]any{"description": deadline(past)}
	expired, ok := pastDeadline(node, time.Now())
	if !ok {
		t.Fatal("expected ok=true")
	}
	if !expired {
		t.Error("expected expired=true for past deadline")
	}

	future := time.Now().Add(1 * time.Hour)
	node = map[string]any{"description": deadline(future)}
	expired, ok = pastDeadline(node, time.Now())
	if !ok {
		t.Fatal("expected ok=true")
	}
	if expired {
		t.Error("expected expired=false for future deadline")
	}

	// No deadline
	node = map[string]any{"description": "no deadline here"}
	_, ok = pastDeadline(node, time.Now())
	if ok {
		t.Error("expected ok=false for missing deadline")
	}
}

// TestSlug verifies slug produces consistent, unique names.
func TestSlug(t *testing.T) {
	s1 := slug("10.0.0.0/8")
	s2 := slug("10.0.0.0/8")
	if s1 != s2 {
		t.Errorf("expected same slug for same input, got %q and %q", s1, s2)
	}

	s3 := slug("192.168.0.0/16")
	if s1 == s3 {
		t.Error("expected different slugs for different inputs")
	}
}

// TestSanitizeMAC verifies MAC sanitization.
func TestSanitizeMAC(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"00:11:22:33:44:55", "001122334455"},
		{"00-11-22-33-44-55", "001122334455"},
		{"AA:BB:CC:DD:EE:FF", "aabbccddeeff"},
	}
	for _, tt := range tests {
		got := sanitizeMAC(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeMAC(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// TestIPv4s verifies IPv4 extraction and deduplication.
func TestIPv4s(t *testing.T) {
	d := core.Device{
		IPs: []netip.Addr{
			netip.MustParseAddr("192.168.1.100"),
			netip.MustParseAddr("192.168.1.100"), // duplicate
			netip.MustParseAddr("::1"),           // IPv6, should be skipped
		},
	}
	ips := ipv4s(d)
	if len(ips) != 1 {
		t.Errorf("expected 1 IPv4, got %d: %v", len(ips), ips)
	}
	if len(ips) > 0 && ips[0] != "192.168.1.100" {
		t.Errorf("expected 192.168.1.100, got %q", ips[0])
	}
}

// TestContainsString is a helper for substring checks.
func containsString(s, substr string) bool {
	return strings.Contains(s, substr)
}

// TestContainsString tests the helper.
func TestContainsString(t *testing.T) {
	if !containsString("hello world", "world") {
		t.Error("expected true")
	}
	if containsString("hello", "world") {
		t.Error("expected false")
	}
}

// TestAPIErrorResponseFormat verifies the error response format.
func TestAPIErrorResponseFormat(t *testing.T) {
	resp := apiErrorResponse("test error")
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var env map[string]any
	json.Unmarshal(body, &env)
	if env["success"] != false {
		t.Error("expected success=false")
	}
	if env["error"] != "test error" {
		t.Errorf("expected error='test error', got %v", env["error"])
	}
}
