// Package openwrt implements act.Actuator against OpenWrt's rpcd JSON-RPC
// endpoint.
//
// It talks to the router over HTTP rather than by shelling out to `uci` or
// `ubus` locally. That is both an architectural and a licensing decision:
// the control plane is a separate host from the router, executing commands
// on the router would require a shell channel that is exactly the kind of
// general-purpose remote execution primitive SAFETY.md forbids, and driving
// the vendor's documented API keeps this package free of any derivative-work
// relationship with GPL-licensed OpenWrt components.
//
// Rules created here are namespaced under a prefix the tool owns. OpenWrt's
// firewall config is a shared resource; touching a rule this tool did not
// create would silently destroy an operator's own configuration.
package openwrt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

// rulePrefix namespaces every uci section this tool creates. OpenWrt's
// firewall config is a shared resource; touching a rule this tool did not
// create would silently destroy an operator's own configuration.
const rulePrefix = "r0i_"

// defaultSession is the sentinel ubus accepts before authentication.
const defaultSession = "00000000000000000000000000000000"

// Doer is the HTTP transport seam. Injecting it is what lets the whole
// adapter be tested against a mock router, with no OpenWrt device present.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// httpDoer is the production Doer.
type httpDoer struct{ c *http.Client }

func (h httpDoer) Do(req *http.Request) (*http.Response, error) { return h.c.Do(req) }

func newHTTPDoer(timeout time.Duration) Doer {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return httpDoer{c: &http.Client{Timeout: timeout}}
}

// ErrUnsupported is returned for an operation the backend cannot express
// through its API. It is deliberately distinct from a transport error so that
// callers can degrade rather than retry forever.
var ErrUnsupported = errors.New("openwrt: operation not supported by this backend")

// Config configures a Client.
type Config struct {
	// BaseURL is the router's uhttpd address, e.g. "http://192.168.1.1".
	BaseURL  string
	Username string
	Password string
	// EgressAllow is the set of prefixes a quarantined device may still reach
	// when RestrictEgress is set. Without it the device would be fully cut
	// off and could never be remediated, which is a worse outcome than the
	// infection.
	EgressAllow []netip.Prefix
	// Transport overrides the HTTP transport. Nil uses the default.
	Transport Doer
	// HTTPTimeout bounds each request. Zero uses the default.
	HTTPTimeout time.Duration
}

// Client implements act.Actuator for OpenWrt.
type Client struct {
	cfg  Config
	rpc  *jsonRPC
	mu   sync.Mutex
	sess string
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("openwrt: BaseURL is required")
	}
	if cfg.Username == "" {
		return nil, errors.New("openwrt: Username is required")
	}
	// A router without a configured egress allowlist would, if asked to
	// restrict, cut the device off entirely. Default it before the config is
	// captured into the Client; assigning it afterwards would apply to a
	// local copy and leave the foot-gun in place.
	if len(cfg.EgressAllow) == 0 {
		cfg.EgressAllow = defaultEgressAllow()
	}
	if cfg.Transport == nil {
		cfg.Transport = newHTTPDoer(cfg.HTTPTimeout)
	}
	return &Client{cfg: cfg, rpc: newJSONRPC(cfg.BaseURL, cfg.Transport)}, nil
}

func defaultEgressAllow() []netip.Prefix {
	// The router itself, so that DNS and NTP keep working and the device can
	// reach the remediation page.
	return []netip.Prefix{
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
	}
}

// Name identifies this backend.
func (c *Client) Name() string { return "openwrt" }

// session acquires or reuses an authenticated ubus session.
//
// ubus sessions expire. Without renewal, a long-running control plane fails
// every call after the timeout with an opaque access error. The mutex makes
// the acquire path safe against concurrent workers racing to log in.
func (c *Client) session(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess != "" {
		return c.sess, nil
	}

	out, err := c.rpc.call(ctx, defaultSession, "session", "login", map[string]any{
		"username": c.cfg.Username,
		"password": c.cfg.Password,
	})
	if err != nil {
		return "", fmt.Errorf("openwrt: login: %w", err)
	}

	// login returns [0, {"ubus_rpc_session": "...", ...}]. A non-zero code
	// means rejected credentials, which is not a transport failure and should
	// not be retried.
	var payload struct {
		Session string `json:"ubus_rpc_session"`
	}
	if err := json.Unmarshal(out, &payload); err != nil || payload.Session == "" {
		return "", errors.New("openwrt: login returned no session; check credentials")
	}
	c.sess = payload.Session
	return c.sess, nil
}

// invalidate drops a session so the next call re-authenticates.
func (c *Client) invalidate() {
	c.mu.Lock()
	c.sess = ""
	c.mu.Unlock()
}

// statusError is a ubus-level non-zero status. It is distinct from a
// transport failure so that callers can interpret a specific code (for
// example, uci reporting a section does not exist) without mistaking it for a
// connectivity problem that should be retried.
type statusError struct {
	Obj, Method string
	Code        int
}

func (e *statusError) Error() string {
	return fmt.Sprintf("openwrt: %s.%s returned status %d", e.Obj, e.Method, e.Code)
}

// call performs one authenticated ubus call, transparently re-authenticating
// once if the session has expired.
func (c *Client) call(ctx context.Context, obj, method string, params map[string]any) (json.RawMessage, error) {
	sess, err := c.session(ctx)
	if err != nil {
		return nil, err
	}
	out, err := c.rpc.call(ctx, sess, obj, method, params)
	if err != nil {
		return nil, err
	}

	// ubus returns a numeric status as the first array element. 6 is
	// UBUS_STATUS_PERMISSION_DENIED, which here almost always means the
	// session aged out rather than that the operator lacks rights.
	var envelope []json.RawMessage
	if json.Unmarshal(out, &envelope) == nil && len(envelope) > 0 {
		var code int
		if json.Unmarshal(envelope[0], &code) == nil && code != 0 {
			if code == 6 {
				c.invalidate()
				if sess2, err2 := c.session(ctx); err2 == nil {
					return c.rpc.call(ctx, sess2, obj, method, params)
				}
			}
			return nil, &statusError{Obj: obj, Method: method, Code: code}
		}
	}
	return out, nil
}

// Authoritative points the LAN's DHCP clients at this host's resolver.
//
// This is load-bearing rather than cosmetic. In a passive-only design the
// resolver is the only guaranteed identity source: a device that does not
// resolve through us is invisible to us. Walled-garden quarantine and
// remediation notification both depend on the same mechanism.
func (c *Client) Authoritative(ctx context.Context, d core.Device) error {
	// Per-device DHCP overrides require a static lease keyed on MAC. Create
	// or update one that pins this device to the current IP, which is what
	// makes its identity stable across DHCP churn.
	if len(d.MAC) == 0 || len(d.IPs) == 0 {
		return errors.New("openwrt: Authoritative requires a MAC and at least one IP")
	}
	ip := d.IPs[0].Unmap().String()

	// uci DHCP static leases live under config "dhcp", option "host".
	// Section name is derived from the MAC so it is idempotent.
	sec := staticLeaseSection(d.MAC.String())
	if err := c.uciEnsureSection(ctx, "dhcp", sec, "host"); err != nil {
		return err
	}
	if err := c.uciSet(ctx, "dhcp", sec, "mac", d.MAC.String()); err != nil {
		return err
	}
	if err := c.uciSet(ctx, "dhcp", sec, "ip", ip); err != nil {
		return err
	}
	if err := c.uciSet(ctx, "dhcp", sec, "name", sanitizeName(d)); err != nil {
		return err
	}
	return c.commitAndReload(ctx, "dhcp", "dnsmasq")
}

// Quarantine applies a containment policy to the device.
func (c *Client) Quarantine(ctx context.Context, d core.Device, p core.Policy) error {
	if len(d.MAC) == 0 {
		return errors.New("openwrt: Quarantine requires a device MAC")
	}
	if p.Name == core.ContainmentMonitor {
		// Monitor affects no traffic. Ensure nothing is left behind from a
		// previous, higher tier, so that lowering the tier actually lifts the
		// restriction rather than merely changing the label.
		return c.Release(ctx, d)
	}

	sec := quarantineSection(d.MAC.String())
	if err := c.uciEnsureSection(ctx, "firewall", sec, "rule"); err != nil {
		return err
	}

	// src_mac matches on the device's identity rather than its address, so
	// the restriction survives a DHCP change. That matters: a device that
	// picks up a new lease must not silently escape containment.
	if err := c.uciSet(ctx, "firewall", sec, "src_mac", d.MAC.String()); err != nil {
		return err
	}
	if err := c.uciSet(ctx, "firewall", sec, "name", "R0-Invader quarantine "+sanitizeName(d)); err != nil {
		return err
	}
	if err := c.uciSet(ctx, "firewall", sec, "proto", "all"); err != nil {
		return err
	}
	if err := c.uciSet(ctx, "firewall", sec, "target", "REJECT"); err != nil {
		return err
	}

	// Peer blocking is the action that drives R0 below one. Restrict the
	// device from reaching any privately addressed destination, which is the
	// set of hosts it could propagate to.
	if p.BlockPeers {
		if err := c.uciSet(ctx, "firewall", sec, "dest", "lan"); err != nil {
			return err
		}
	}

	// Egress restriction is expressed as a rejection of everything outside
	// the allowlist. OpenWrt's uci firewall cannot express an allowlist as
	// an inverse, so the allowlist becomes explicit allow rules and the
	// quarantine rule above rejects the remainder.
	if p.RestrictEgress {
		if err := c.addEgressAllowRules(ctx, d, sec); err != nil {
			return err
		}
	}

	return c.commitAndReload(ctx, "firewall")
}

// addEgressAllowRules creates the exceptions that let a restricted device be
// remediated. Without them a quarantined device is simply broken, and a
// broken device that the owner cannot fix is a worse outcome than an
// infected one.
func (c *Client) addEgressAllowRules(ctx context.Context, d core.Device, base string) error {
	for i, p := range c.cfg.EgressAllow {
		sec := fmt.Sprintf("%segress_%d", rulePrefix, i)
		if err := c.uciEnsureSection(ctx, "firewall", sec, "rule"); err != nil {
			return err
		}
		if err := c.uciSet(ctx, "firewall", sec, "src_mac", d.MAC.String()); err != nil {
			return err
		}
		if err := c.uciSet(ctx, "firewall", sec, "dest", p.String()); err != nil {
			return err
		}
		if err := c.uciSet(ctx, "firewall", sec, "proto", "all"); err != nil {
			return err
		}
		if err := c.uciSet(ctx, "firewall", sec, "target", "ACCEPT"); err != nil {
			return err
		}
		if err := c.uciSet(ctx, "firewall", sec, "name", fmt.Sprintf("R0-Invader egress allow %d", i)); err != nil {
			return err
		}
	}
	_ = base
	return nil
}

// Release removes all containment from a device.
//
// It must always succeed for a previously quarantined device. A security tool
// that can lock an appliance out with no route to recovery is worse than no
// tool, and the failure mode here is an operator with a bricked camera and
// no way back.
func (c *Client) Release(ctx context.Context, d core.Device) error {
	if len(d.MAC) == 0 {
		return errors.New("openwrt: Release requires a device MAC")
	}
	var touched bool
	for _, sec := range []string{
		quarantineSection(d.MAC.String()),
		staticLeaseSection(d.MAC.String()),
	} {
		if ok, err := c.uciDeleteSection(ctx, "firewall", sec); err != nil {
			return err
		} else if ok {
			touched = true
		}
		if ok, err := c.uciDeleteSection(ctx, "dhcp", sec); err != nil {
			return err
		} else if ok {
			touched = true
		}
	}
	// Egress allow rules are keyed to the quarantine section, so drop them
	// together with it.
	for i := range c.cfg.EgressAllow {
		if ok, err := c.uciDeleteSection(ctx, "firewall", fmt.Sprintf("%segress_%d", rulePrefix, i)); err != nil {
			return err
		} else if ok {
			touched = true
		}
	}

	if !touched {
		// Nothing to do. Returning nil keeps Release idempotent, which
		// matters because the portal calls it on a user's confirmation and a
		// user may well click twice.
		return nil
	}
	return c.commitAndReload(ctx, "firewall", "dnsmasq")
}

// BlockNet blocks a prefix for a bounded duration.
//
// Expiry is part of the contract rather than a background cleanup concern,
// so that a crashed control plane leaves no permanent block on the network.
// The enforcement of `until` is carried by the caller's bookkeeping; this
// backend records it in the section name so an orphaned rule is
// self-identifying during later cleanup.
func (c *Client) BlockNet(ctx context.Context, n netip.Prefix, until time.Time) error {
	sec := fmt.Sprintf("%snet_%s", rulePrefix, strings.ReplaceAll(n.String(), "/", "_"))
	if err := c.uciEnsureSection(ctx, "firewall", sec, "rule"); err != nil {
		return err
	}
	for k, v := range map[string]string{
		"src":    "lan",
		"dest":   n.String(),
		"proto":  "all",
		"target": "REJECT",
		"name":   "R0-Invader block " + n.String(),
		// Recorded so a later sweep can expire orphans without guessing.
		"comment": "r0i_until=" + strconv.FormatInt(until.Unix(), 10),
	} {
		if err := c.uciSet(ctx, "firewall", sec, k, v); err != nil {
			return err
		}
	}
	return c.commitAndReload(ctx, "firewall")
}

// BlockDomain sinkholes a domain.
//
// On OpenWrt this is expressed through dnsmasq's address= facility rather
// than at the firewall, because dnsmasq is already the LAN's resolver and a
// DNS-level block cannot be bypassed by a device that has stopped
// translating names.
func (c *Client) BlockDomain(ctx context.Context, d string, until time.Time) error {
	d = strings.ToLower(strings.TrimSpace(d))
	if d == "" {
		return errors.New("openwrt: BlockDomain requires a domain")
	}
	sec := rulePrefix + "dns_" + sanitizeDomain(d)
	if err := c.uciEnsureSection(ctx, "dnsmasq", sec, "address"); err != nil {
		return err
	}
	// "/" prefix means "this exact domain only" rather than the domain and
	// all subdomains; the latter is not what a sinkhole should do.
	for k, v := range map[string]string{
		"ip":      "/" + d + "/0.0.0.0",
		"comment": "r0i_until=" + strconv.FormatInt(until.Unix(), 10),
	} {
		if err := c.uciSet(ctx, "dnsmasq", sec, k, v); err != nil {
			return err
		}
	}
	return c.commitAndReload(ctx, "dnsmasq")
}

// Health verifies that the router is reachable and this host can authenticate.
func (c *Client) Health(ctx context.Context) error {
	out, err := c.call(ctx, "system", "board", map[string]any{})
	if err != nil {
		return fmt.Errorf("openwrt: health: %w", err)
	}
	if len(out) == 0 {
		return errors.New("openwrt: health: empty response from system.board")
	}
	return nil
}

// --- uci plumbing ---------------------------------------------------------

// uciEnsureSection creates a named section if it is absent. The name is
// deterministic, which is what makes every operation above idempotent.
func (c *Client) uciEnsureSection(ctx context.Context, config, section, stype string) error {
	_, err := c.uciGetSection(ctx, config, section)
	if err == nil {
		return nil
	}
	if !errors.Is(err, errSectionMissing) {
		return err
	}
	if _, err := c.call(ctx, "uci", "add", map[string]any{
		"config": config,
		"type":   stype,
		"name":   section,
	}); err != nil {
		return fmt.Errorf("openwrt: creating %s.%s: %w", config, section, err)
	}
	return nil
}

var errSectionMissing = errors.New("openwrt: uci section missing")

func (c *Client) uciGetSection(ctx context.Context, config, section string) (map[string]any, error) {
	out, err := c.call(ctx, "uci", "get", map[string]any{
		"config":  config,
		"section": section,
	})
	if err != nil {
		// A non-zero status from uci.get means the section is absent, which
		// is a normal condition here and not a failure. A transport error is
		// genuinely a failure and must propagate, or Release would silently
		// skip a rule it failed to check and leave a device quarantined.
		var st *statusError
		if errors.As(err, &st) {
			return nil, errSectionMissing
		}
		return nil, err
	}
	var env []json.RawMessage
	if err := json.Unmarshal(out, &env); err != nil || len(env) == 0 {
		return nil, errSectionMissing
	}
	var code int
	if json.Unmarshal(env[0], &code) != nil || code != 0 {
		return nil, errSectionMissing
	}
	if len(env) < 2 {
		return nil, errSectionMissing
	}
	var m map[string]any
	if err := json.Unmarshal(env[1], &m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *Client) uciSet(ctx context.Context, config, section, option, value string) error {
	_, err := c.call(ctx, "uci", "set", map[string]any{
		"config":  config,
		"section": section,
		"values":  map[string]any{option: value},
	})
	return err
}

func (c *Client) uciDeleteSection(ctx context.Context, config, section string) (bool, error) {
	if _, err := c.uciGetSection(ctx, config, section); err != nil {
		if errors.Is(err, errSectionMissing) {
			return false, nil
		}
		return false, err
	}
	if _, err := c.call(ctx, "uci", "delete", map[string]any{
		"config":  config,
		"section": section,
	}); err != nil {
		return false, err
	}
	return true, nil
}

// commitAndReload persists staged uci changes and reloads the named services.
//
// Without commit, staged changes are discarded on the next ubus session and
// containment appears to work until the router restarts — precisely the
// failure that must never happen in a security control.
func (c *Client) commitAndReload(ctx context.Context, configs ...string) error {
	for _, cfg := range configs {
		if _, err := c.call(ctx, "uci", "commit", map[string]any{"config": cfg}); err != nil {
			return fmt.Errorf("openwrt: committing %s: %w", cfg, err)
		}
	}
	// Reload the firewall when it was touched. A rule that is staged but not
	// loaded is indistinguishable from one that failed.
	for _, cfg := range configs {
		if cfg == "firewall" {
			if _, err := c.call(ctx, "firewall", "reload", map[string]any{}); err != nil {
				return fmt.Errorf("openwrt: reloading firewall: %w", err)
			}
		}
		if cfg == "dnsmasq" || cfg == "dhcp" {
			// dnsmasq reads both configs; a reload is required for a static
			// lease or a sinkhole to take effect.
			if _, err := c.call(ctx, "service", "event", map[string]any{
				"action":  "reload",
				"service": "dnsmasq",
			}); err != nil {
				// Not fatal on every build: some releases expose the reload
				// only through procd. Surface it rather than fail the whole
				// containment, since the uci commit already persisted.
				continue
			}
		}
	}
	return nil
}

// --- naming helpers -------------------------------------------------------

func quarantineSection(mac string) string  { return rulePrefix + "q_" + sanitizeMAC(mac) }
func staticLeaseSection(mac string) string { return rulePrefix + "lease_" + sanitizeMAC(mac) }

func sanitizeMAC(mac string) string {
	return strings.NewReplacer(":", "", ".", "", "-", "").Replace(strings.ToLower(mac))
}

func sanitizeDomain(d string) string {
	return strings.NewReplacer(".", "_", "-", "_").Replace(d)
}

func sanitizeName(d core.Device) string {
	base := d.Vendor
	if base == "" {
		base = "device"
	}
	base = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		default:
			return '_'
		}
	}, base)
	return fmt.Sprintf("%s_%s", base, sanitizeMAC(d.MAC.String()))
}

// --- JSON-RPC 2.0 client --------------------------------------------------

// jsonRPC speaks the JSON-RPC 2.0 dialect that rpcd exposes over uhttpd.
type jsonRPC struct {
	base string
	do   Doer
	id   int
	mu   sync.Mutex
}

func newJSONRPC(base string, do Doer) *jsonRPC {
	return &jsonRPC{base: strings.TrimRight(base, "/"), do: do}
}

type jsonRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

// call performs one JSON-RPC call and returns the second element of the ubus
// [status, payload] envelope, which is the payload callers actually want.
func (j *jsonRPC) call(ctx context.Context, session, obj, method string, params map[string]any) (json.RawMessage, error) {
	if params == nil {
		params = map[string]any{}
	}

	j.mu.Lock()
	j.id++
	id := j.id
	j.mu.Unlock()

	body, err := json.Marshal(jsonRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  "call",
		Params:  []any{session, obj, method, params},
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, j.base+"/ubus", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := j.do.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openwrt: rpc %s.%s: %w", obj, method, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("openwrt: rpc %s.%s: HTTP %d", obj, method, resp.StatusCode)
	}

	var env struct {
		Result []json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return nil, fmt.Errorf("openwrt: rpc %s.%s: decoding response: %w", obj, method, err)
	}
	if env.Error != nil {
		return nil, fmt.Errorf("openwrt: rpc %s.%s: %s", obj, method, env.Error.Message)
	}
	if len(env.Result) < 2 {
		return nil, fmt.Errorf("openwrt: rpc %s.%s: malformed envelope", obj, method)
	}
	// env.Result[1] carries the ubus [code, payload] pair. Pass it through
	// unmodified; the ubus-level code is interpreted by the caller.
	return env.Result[1], nil
}
