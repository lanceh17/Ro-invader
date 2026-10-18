// Package opnsense implements act.Actuator against OPNsense's REST API.
//
// It drives the firewall through OPNsense's documented HTTP endpoints and
// never links or shells into the product. That keeps this package free of any
// derivative-work relationship with OPNsense (BSD-2-Clause, driven as a client),
// and it keeps the control plane free of a general-purpose remote execution
// channel, which SAFETY.md forbids outright.
//
// # Release targeted
//
// Verified against OPNsense core master as of 2026-10-18, which is the 25.7 /
// 26.1 development line. The specific endpoints and field names this package
// relies on were read out of the product source rather than assumed:
//
//   - Rule CRUD is the MVC "filter" model at /api/firewall/filter/*, *not* the
//     older add_rule/apply style. See FilterController.php, which extends
//     ApiMutableModelControllerBase and exposes addRule / setRule / delRule /
//     searchRule / apply.
//   - Rule field names come from Filter.xml (model version 1.0.9). Note that
//     they are the flattened names — `source_net`, `destination_net`,
//     `ipprotocol` — not the nested `source: {address: ...}` form that older
//     forum posts show. The nested form was superseded.
//   - Booleans are the strings "0" and "1", not JSON true/false.
//   - `source_net` / `destination_net` are multi-value fields accepting plain
//     CIDR as well as alias names.
//   - DNS overrides are Unbound host overrides under
//     /api/unbound/settings/*HostOverride, payload key "host".
//   - searchRecordsetBase reads `current` and `rowCount` from the POST body,
//     not the query string, and rowCount == -1 means "every record".
//
// Two consequences are load-bearing and are called out again where they appear:
//
//  1. The filter model is the Automation filter. Per the product's own
//     documentation ("only has knowledge of rules created within it") and
//     docs/ARCHITECTURE.md, it surfaces and manages only rules created through
//     this model. This is why every rule written here is created here and
//     namespaced, and why Release deletes by description rather than by
//     "whatever looks like a containment rule".
//
//  2. OPNsense has no API for firewall schedules. The `sched` field exists on
//     the rule model, but an OPNsense administrator confirms on the vendor
//     forum that the schedule pages remain static with no API behind them.
//     Expiry therefore cannot be expressed to the router. See BlockNet.
package opnsense

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

const (
	// descPrefix namespaces every firewall rule and every DNS override this
	// tool creates. OPNsense's firewall is shared operator state — the same
	// argument that applies to OpenWrt's uci config applies here — and
	// deleting something an operator wrote themselves would destroy their
	// setup. Release matches on this prefix and nothing else.
	descPrefix = "R0-Invader"

	// ruleTag is additionally written to the filter model's `tag` field,
	// which is the field OPNsense itself uses for tagging. Two markers are
	// deliberate: `tag` is what a human filtering the ruleset sees, and
	// `description` carries the kind and key needed to delete precisely.
	// The model's StrictTextField mask for `tag` permits only
	// [0-9a-zA-Z.,_-], so the value must stay inside that set.
	ruleTag = "r0i"

	// Description kind tokens. Each prefix identifies exactly what the object
	// is, which is what lets Release remove one device's containment without
	// touching another's, an IoC block, or an operator's rule.
	kindQuarantine = "q" // firewall rule, containment for one device
	kindNetBlock   = "n" // firewall rule, prefix block
	kindDomainSink = "d" // Unbound host override, DNS sinkhole
	kindAuthoritv  = "a" // Unbound host override, resolver identity pin

	// ruleTag is additionally written to the filter model's `tag` field,
	// which is the field OPNsense itself uses for tagging. We must check
	// both tag and description prefix in ownedRules so an operator's
	// similarly-prefixed but differently-tagged rule is never touched.
)

// Endpoints, all relative to BaseURL's /api root. Verified names, not guesses.
const (
	epApply       = "firewall/filter/apply"
	epAddRule     = "firewall/filter/addRule"
	epSetRule     = "firewall/filter/setRule"
	epDelRule     = "firewall/filter/delRule"
	epSearchRule  = "firewall/filter/searchRule"
	epHostAdd     = "unbound/settings/addHostOverride"
	epHostDel     = "unbound/settings/delHostOverride"
	epHostSearch  = "unbound/settings/searchHostOverride"
	epUnboundSync = "unbound/service/reconfigure"
)

// Sentinel errors. Auth failures are separated from transport failures because
// the two demand opposite responses: a transport error should be retried, an
// auth error should stop the control plane and page a human. Conflating them
// is how a security tool ends up retrying a revoked credential every thirty
// seconds forever.
var (
	// ErrAuth is a 401 from the API. On current OPNsense this means the
	// key/secret pair is wrong, has been revoked, or belongs to a user with
	// no API access. See ErrForbidden for the related privilege case.
	ErrAuth = errors.New("opnsense: authentication rejected")

	// ErrForbidden is a 403, meaning the credentials authenticated but the
	// owning user lacks the page privilege for the endpoint. Firewall
	// operations need the Firewall page privilege.
	//
	// Caveat worth knowing when reading logs: OPNsense releases through at
	// least 22.1 answered 401 for this case rather than 403, which RFC 7235
	// says it should not (opnsense/core#5749). Newer releases do return 403
	// for at least some endpoints (opnsense/core#9093). The message on
	// ErrAuth therefore names both possibilities rather than blaming the key
	// alone.
	ErrForbidden = errors.New("opnsense: insufficient API privileges for this endpoint")

	// ErrUnsupported reports an operation this backend cannot express
	// through OPNsense's API.
	ErrUnsupported = errors.New("opnsense: operation not supported by this backend")
)

// Doer is the HTTP transport seam. Injecting it is what lets the whole adapter
// be tested against a mock firewall, with no OPNsense device present and no
// network access at all.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// httpDoer is the production Doer.
type httpDoer struct{ c *http.Client }

func (h httpDoer) Do(req *http.Request) (*http.Response, error) { return h.c.Do(req) }

// newHTTPDoer builds the default transport.
//
// OPNsense presents a self-signed certificate out of the box, so the escape
// hatch exists. It is deliberately opt-in rather than default, because
// disabling verification defeats authentication: with it on, anything on the
// path can impersonate the firewall. A deployment that cares should leave it
// false and supply a Transport whose pool trusts the appliance certificate.
func newHTTPDoer(timeout time.Duration, insecure bool) Doer {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	tr := &http.Transport{
		MaxIdleConns:        4,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: timeout,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecure},
	}
	return httpDoer{c: &http.Client{Timeout: timeout, Transport: tr}}
}

// Config configures a Client.
type Config struct {
	// BaseURL is the appliance root, e.g. "https://192.168.1.1".
	BaseURL string
	// APIKey and APISecret are the credentials downloaded once when a key is
	// minted under System -> Access -> Users -> API keys. They are sent as
	// HTTP Basic auth with the key as the username.
	APIKey    string
	APISecret string
	// LANInterface names the interface quarantined traffic arrives on. It
	// defaults to "lan", which is OPNsense's own default and correct for the
	// overwhelming majority of deployments.
	LANInterface string
	// LANDomain is the suffix used for the resolver identity pin written by
	// Authoritative. It must be a syntactically valid Unbound domain.
	LANDomain string
	// PeerNets is the set of destinations a quarantined device may not reach:
	// its lateral-movement surface. It defaults to the private, CGNAT,
	// link-local and IETF-special ranges.
	//
	// Note what is deliberately absent: the appliance's own LAN address. pf
	// rules apply to the forwarding path, and traffic a device sends to the
	// firewall's own IP terminates locally and is matched by the input chain
	// instead. Blocking the peer ranges therefore leaves DNS, DHCP and the
	// remediation portal reachable, which is what keeps a quarantined device
	// fixable. Without that, containment would be indistinguishable from
	// bricking the device.
	PeerNets []netip.Prefix
	// EgressAllow is the set of destinations a walled-garden device may still
	// reach when RestrictEgress is set. It is expressed as an inverted match
	// (see rule.destination_not) rather than as a sequence of pass-then-block
	// rules, so that correctness does not depend on rule ordering.
	//
	// It defaults to the same private ranges, which under the peer rule above
	// means "local remediation only".
	EgressAllow []netip.Prefix
	// InsecureSkipVerify accepts the appliance's self-signed certificate.
	// See newHTTPDoer before turning this on.
	InsecureSkipVerify bool
	// Transport overrides the HTTP transport. Nil uses the default.
	Transport Doer
	// HTTPTimeout bounds each request. Zero uses the default.
	HTTPTimeout time.Duration
}

// Client implements act.Actuator for OPNsense.
type Client struct {
	cfg Config
	// mu serializes the read-modify-write cycles that create and reap rules.
	// Two workers quarantining different devices at the same instant would
	// otherwise each read a rowset, each decide the other's object is absent,
	// and each apply a ruleset missing one of the two devices' rules. The
	// last apply wins, and one device is silently uncontained.
	mu sync.Mutex
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("opnsense: BaseURL is required")
	}
	if cfg.APIKey == "" {
		return nil, errors.New("opnsense: APIKey is required")
	}
	if cfg.APISecret == "" {
		return nil, errors.New("opnsense: APISecret is required")
	}
	if cfg.LANInterface == "" {
		cfg.LANInterface = "lan"
	}
	if cfg.LANDomain == "" {
		cfg.LANDomain = "lan"
	}
	// Both allowlists are assigned before the config is captured into the
	// Client. Assigning them afterwards would apply to a local copy and leave
	// the foot-gun in place: a quarantine with no allowlist is a device that
	// cannot reach anything at all.
	if len(cfg.PeerNets) == 0 {
		cfg.PeerNets = defaultPeerNets()
	}
	if len(cfg.EgressAllow) == 0 {
		cfg.EgressAllow = defaultEgressAllow()
	}
	if cfg.Transport == nil {
		cfg.Transport = newHTTPDoer(cfg.HTTPTimeout, cfg.InsecureSkipVerify)
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return &Client{cfg: cfg}, nil
}

// defaultPeerNets is the lateral-movement surface: every range a compromised
// host on a consumer network would use to reach another host without
// traversing the internet. 100.64.0.0/10 is CGNAT and 169.254.0.0/16 is
// link-local, both of which appear in consumer IoT traffic and neither of
// which the public internet routes to.
func defaultPeerNets() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("fc00::/7"),
	}
}

func defaultEgressAllow() []netip.Prefix {
	// The private ranges, so that under RestrictEgress a device can still
	// reach the appliance's resolver and the remediation portal. Combined with
	// the peer rule this is the walled garden: local remediation only.
	return []netip.Prefix{
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
	}
}

// Name identifies this backend.
func (c *Client) Name() string { return "opnsense" }

// Authoritative pins this host's resolver view of the device.
//
// On OPNsense the local, always-available mechanism for making the resolver's
// identity stable is an Unbound host override: the appliance's own resolver
// then resolves the device to exactly the address this control plane believes
// it has. Identity is the prerequisite for both containment and remediation
// notification, so this is the same guarantee the OpenWrt adapter obtains from
// a MAC-keyed static lease, expressed through the API core actually exposes.
//
// Limitation, stated plainly: this declares the resolver's view. It does not
// configure DHCP, which on current OPNsense lives in the Kea or ISC plugin
// rather than in core, so a device that has never resolved through us is still
// discovered by observation rather than by lease.
func (c *Client) Authoritative(ctx context.Context, d core.Device) error {
	if len(d.MAC) == 0 || len(d.IPs) == 0 {
		return errors.New("opnsense: Authoritative requires a MAC and at least one IP")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	want := hostOverride{
		Enabled:     onOff(true),
		Hostname:    sanitizeLabel(d),
		Domain:      c.cfg.LANDomain,
		RR:          "A",
		Server:      d.IPs[0].Unmap().String(),
		AddPTR:      onOff(false),
		Description: descAuthoritative(d),
	}
	if err := c.upsertHost(ctx, want); err != nil {
		return err
	}
	return c.syncUnbound(ctx)
}

// Quarantine applies containment for a device.
//
// Both effects are expressed as single block rules rather than as a
// pass-allowlist followed by a catch-all block. That is a deliberate choice:
// with a pass rule, whether the block ever fires depends on the two rules
// being ordered correctly relative to each other, which is a property of a
// config the operator also edits. An inverted destination match has no such
// dependency.
//
// Peer blocking is source=device, destination=PeerNets.
//
// Restriction is source=device, destination=EgressAllow with destination_not
// set, which in pf is "to anything other than this list".
func (c *Client) Quarantine(ctx context.Context, d core.Device, p core.Policy) error {
	// Monitor is handled before any validation. The contract says it is a
	// no-op that must nonetheless succeed, and that holds even for a device
	// too malformed to identify: nothing could have been created for a
	// device we cannot name, so there is nothing to remove.
	if p.Name == core.ContainmentMonitor {
		if len(d.MAC) == 0 {
			return nil
		}
		return c.Release(ctx, d)
	}
	if len(d.IPs) == 0 {
		return errors.New("opnsense: Quarantine requires at least one IP")
	}

	srcs := make([]string, 0, len(d.IPs))
	for _, ip := range d.IPs {
		srcs = append(srcs, ip.Unmap().String())
	}

	var want []rule
	if p.BlockPeers {
		want = append(want, rule{
			Enabled:     onOff(true),
			Action:      "block",
			Quick:       onOff(true),
			Sequence:    "1",
			Interface:   []string{c.cfg.LANInterface},
			Direction:   "in",
			IPProtocol:  "inet46",
			Protocol:    "any",
			SourceNet:   srcs,
			DestNet:     prefixStrings(c.cfg.PeerNets),
			Description: descQuarantine(d, "peers"),
			Tag:         ruleTag,
		})
	}
	if p.RestrictEgress {
		want = append(want, rule{
			Enabled:     onOff(true),
			Action:      "block",
			Quick:       onOff(true),
			Sequence:    "2",
			Interface:   []string{c.cfg.LANInterface},
			Direction:   "in",
			IPProtocol:  "inet46",
			Protocol:    "any",
			SourceNet:   srcs,
			DestNot:     onOff(true),
			DestNet:     prefixStrings(c.cfg.EgressAllow),
			Description: descQuarantine(d, "egress"),
			Tag:         ruleTag,
		})
	}
	if len(want) == 0 {
		// A policy with neither flag set contains nothing; treat it as
		// monitor rather than writing a rule that does nothing.
		return c.Release(ctx, d)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	existing, err := c.ownedRules(ctx, d)
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	for i := range want {
		w := want[i]
		if err := c.upsertRule(ctx, w, existing); err != nil {
			return err
		}
		keep[w.Description] = true
	}
	// Drop any of this device's rules the current tier no longer calls for.
	// Without this, dropping from quarantined to restricted would leave the
	// egress restriction in force.
	for _, r := range existing {
		if keep[r.Description] {
			continue
		}
		if err := c.delRule(ctx, r.UUID); err != nil {
			return err
		}
	}
	return c.applyFilter(ctx)
}

// Release removes all containment and restores full access.
//
// It must always succeed for a previously quarantined device: a security tool
// that can lock an appliance out with no route to recovery is worse than no
// tool. Two properties carry that weight. First, only descriptions carrying
// this device's own namespace prefix are deleted, so an operator's rules and
// another device's containment are untouched. Second, every deletion is
// attempted even if an earlier one fails, so one stuck object cannot strand
// the rest of a device's containment in place.
func (c *Client) Release(ctx context.Context, d core.Device) error {
	if len(d.MAC) == 0 {
		return errors.New("opnsense: Release requires a device MAC")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	prefixes := []string{descQuarantinePrefix(d.MAC.String()), descAuthoritativePrefix(d.MAC.String())}

	var errs []error
	firewallTouched := false

	rules, err := c.ownedRules(ctx, d)
	if err != nil {
		errs = append(errs, err)
	}
	for _, r := range rules {
		if err := c.delRule(ctx, r.UUID); err != nil {
			errs = append(errs, err)
			continue
		}
		firewallTouched = true
	}

	hosts, err := c.ownedHosts(ctx, prefixes...)
	if err != nil {
		errs = append(errs, err)
	}
	dnsTouched := false
	for _, h := range hosts {
		if err := c.delHost(ctx, h.UUID); err != nil {
			errs = append(errs, err)
			continue
		}
		dnsTouched = true
	}

	// Apply only what was actually touched. Reconfiguring the resolver or
	// reloading the firewall on every no-op Release would make a user
	// double-clicking the portal's release button briefly interrupt their
	// whole network's DNS.
	if firewallTouched {
		if err := c.applyFilter(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if dnsTouched {
		if err := c.syncUnbound(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// BlockNet blocks a prefix for a bounded duration.
//
// # Expiry is not enforced by the router
//
// The contract says a crashed control plane must leave no permanent block. On
// OPNsense that cannot be satisfied through the API. The rule model does carry
// a `sched` field bound to a firewall schedule, but schedules live in the
// legacy static pages and an OPNsense administrator confirms on the vendor
// forum that there is no API behind them. There is no TTL field on a rule and
// no way to ask configd to expire one.
//
// So what this does instead: the requested expiry is recorded in the rule's
// own description as "until <unix>". That makes an orphaned block
// self-identifying to whoever reads the ruleset or runs ReapExpired. It is
// bookkeeping, not enforcement. The honest position is that a block created
// here outlives a dead control plane until something reaps it, and this
// package will not pretend otherwise by calling the description a deadline.
func (c *Client) BlockNet(ctx context.Context, n netip.Prefix, until time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	want := rule{
		Enabled:     onOff(true),
		Action:      "block",
		Quick:       onOff(true),
		Sequence:    "1",
		Interface:   []string{c.cfg.LANInterface},
		Direction:   "in",
		IPProtocol:  ipProtocolFor(n),
		Protocol:    "any",
		DestNet:     []string{n.String()},
		Description: descNetBlock(n, until),
		Tag:         ruleTag,
	}
	// The candidate list is the whole ruleset rather than one device's
	// subset: an IoC block is keyed by prefix, not by MAC, so the match has
	// to consider every rule this tool owns.
	all, err := c.listRules(ctx)
	if err != nil {
		return err
	}
	if err := c.upsertRule(ctx, want, all); err != nil {
		return err
	}
	return c.applyFilter(ctx)
}

// BlockDomain sinkholes a domain for a bounded duration.
//
// Expressed as an Unbound host override returning 0.0.0.0, which is OPNsense's
// idiomatic sinkhole and the mechanism a device that has stopped translating
// names cannot route around. PTR generation is switched off: a sinkhole is
// not a host and must not appear in reverse lookups.
//
// As with BlockNet, OPNsense cannot enforce the expiry; see that method.
func (c *Client) BlockDomain(ctx context.Context, d string, until time.Time) error {
	domain, err := normalizeDomain(d)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	want := hostOverride{
		Enabled: onOff(true),
		Domain:  domain,
		RR:      "A",
		// RFC 2606 TEST-NET-1 is not routable, so a client that ignores an
		// empty answer fails closed rather than reaching the real host.
		Server:      "192.0.2.1",
		TTL:         "60",
		AddPTR:      onOff(false),
		Description: descDomainSink(domain, until),
	}
	if err := c.upsertHost(ctx, want); err != nil {
		return err
	}
	return c.syncUnbound(ctx)
}

// Health verifies the appliance is reachable, that this host authenticates,
// and that the rule set can be read back.
//
// Reading the rows back is the part that matters. A firewall that accepted
// credentials and returned 200 to every write but never persisted them looks
// identical to a working one until an infected device reaches a peer, and the
// interface says a failing Health must block new containment rather than let
// it queue silently. A wrong API key, a missing page privilege and an
// unreachable appliance all surface here instead.
//
// Health is side-effect free. It writes nothing, so it is safe to call on a
// schedule, and its success never counts as evidence that a rule is active.
func (c *Client) Health(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	rules, err := c.listRules(ctx)
	if err != nil {
		return fmt.Errorf("opnsense: health: %w", err)
	}
	for _, r := range rules {
		if r.UUID == "" {
			return errors.New("opnsense: health: ruleset contains a rule with no uuid")
		}
	}
	if _, err := c.listHosts(ctx); err != nil {
		return fmt.Errorf("opnsense: health: %w", err)
	}
	return nil
}

// ReapExpired deletes this tool's blocks whose recorded deadline has passed.
//
// This is the compensating control for the limitation documented on BlockNet:
// the router will not expire anything, so something has to. It is deliberately
// a separate exported call rather than a background timer inside the client,
// for two reasons. A background goroutine would be the local timer the design
// is trying to avoid, and it would keep the client alive in tests. Making it
// the caller's to schedule keeps the duty visible: the control plane runs it,
// and if the control plane is down, nothing runs it.
func (c *Client) ReapExpired(ctx context.Context, now time.Time) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cutoff := now.Unix()
	n := 0
	var errs []error

	rules, err := c.listRules(ctx)
	if err != nil {
		errs = append(errs, err)
	}
	firewallTouched := false
	for _, r := range rules {
		if !strings.HasPrefix(r.Description, descPrefix+" ") || r.Tag != ruleTag {
			continue
		}
		until, ok := recordedUntil(r.Description)
		if !ok || until > cutoff {
			continue
		}
		if err := c.delRule(ctx, r.UUID); err != nil {
			errs = append(errs, err)
			continue
		}
		firewallTouched = true
		n++
	}

	hosts, err := c.listHosts(ctx)
	if err != nil {
		errs = append(errs, err)
	}
	dnsTouched := false
	for _, h := range hosts {
		if !strings.HasPrefix(h.Description, descPrefix+" ") {
			continue
		}
		until, ok := recordedUntil(h.Description)
		if !ok || until > cutoff {
			continue
		}
		if err := c.delHost(ctx, h.UUID); err != nil {
			errs = append(errs, err)
			continue
		}
		dnsTouched = true
		n++
	}

	if firewallTouched {
		if err := c.applyFilter(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if dnsTouched {
		if err := c.syncUnbound(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return n, errors.Join(errs...)
}

// --- rule and host plumbing -----------------------------------------------

// rule is one entry in the filter model. Field names and types follow
// Filter.xml; notably every boolean is the string "0" or "1".
type rule struct {
	Enabled     string   `json:"enabled"`
	Action      string   `json:"action"`
	Quick       string   `json:"quick"`
	Sequence    string   `json:"sequence"`
	Interface   []string `json:"interface"`
	Direction   string   `json:"direction"`
	IPProtocol  string   `json:"ipprotocol"`
	Protocol    string   `json:"protocol"`
	SourceNet   []string `json:"source_net"`
	SourceNot   string   `json:"source_not"`
	DestNet     []string `json:"destination_net"`
	DestNot     string   `json:"destination_not"`
	Description string   `json:"description"`
	Tag         string   `json:"tag"`
}

// hostOverride is one entry in Unbound's hosts.host array.
type hostOverride struct {
	Enabled     string `json:"enabled"`
	Hostname    string `json:"hostname"`
	Domain      string `json:"domain"`
	RR          string `json:"rr"`
	Server      string `json:"server"`
	TTL         string `json:"ttl"`
	AddPTR      string `json:"addptr"`
	Description string `json:"description"`
}

// rowset is the shape every OPNsense search endpoint returns.
type rowset struct {
	Total    int               `json:"total"`
	RowCount int               `json:"rowCount"`
	Current  int               `json:"current"`
	Rows     []json.RawMessage `json:"rows"`
}

type ruleRow struct {
	UUID        string `json:"uuid"`
	Description string `json:"description"`
	Tag         string `json:"tag"`
}

type hostRow struct {
	UUID        string `json:"uuid"`
	Description string `json:"description"`
}

// listRules reads back every rule in the automation filter.
//
// rowCount -1 asks for every record in one page. The response is then filtered
// locally on this tool's namespace rather than relying on the server-side
// searchPhrase: searchRecordsetBase splits the phrase on whitespace and
// applies it as clauses, and our descriptions contain spaces by design.
func (c *Client) listRules(ctx context.Context) ([]ruleRow, error) {
	var rs rowset
	if err := c.doJSON(ctx, http.MethodPost, epSearchRule, allRowsBody(), &rs); err != nil {
		return nil, err
	}
	out := make([]ruleRow, 0, len(rs.Rows))
	for _, raw := range rs.Rows {
		var r ruleRow
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("opnsense: %s: decoding row: %w", epSearchRule, err)
		}
		out = append(out, r)
	}
	return out, nil
}

func (c *Client) listHosts(ctx context.Context) ([]hostRow, error) {
	var rs rowset
	if err := c.doJSON(ctx, http.MethodPost, epHostSearch, allRowsBody(), &rs); err != nil {
		return nil, err
	}
	out := make([]hostRow, 0, len(rs.Rows))
	for _, raw := range rs.Rows {
		var h hostRow
		if err := json.Unmarshal(raw, &h); err != nil {
			return nil, fmt.Errorf("opnsense: %s: decoding row: %w", epHostSearch, err)
		}
		out = append(out, h)
	}
	return out, nil
}

// ownedRules returns this device's containment rules.
func (c *Client) ownedRules(ctx context.Context, d core.Device) ([]ruleRow, error) {
	if len(d.MAC) == 0 {
		return nil, nil
	}
	prefix := descQuarantinePrefix(d.MAC.String())
	all, err := c.listRules(ctx)
	if err != nil {
		return nil, err
	}
	var out []ruleRow
	for _, r := range all {
		if strings.HasPrefix(r.Description, prefix) && r.Tag == ruleTag {
			out = append(out, r)
		}
	}
	return out, nil
}

// ownedHosts returns the DNS overrides whose description starts with any of
// the supplied prefixes.
func (c *Client) ownedHosts(ctx context.Context, prefixes ...string) ([]hostRow, error) {
	all, err := c.listHosts(ctx)
	if err != nil {
		return nil, err
	}
	var out []hostRow
	for _, h := range all {
		for _, p := range prefixes {
			if strings.HasPrefix(h.Description, p) {
				out = append(out, h)
				break
			}
		}
	}
	return out, nil
}

// upsertRule creates or replaces the rule identified by want's description.
//
// Idempotency lives here. A second Quarantine for the same device finds the
// existing object and rewrites it in place rather than creating a duplicate,
// so the end state is identical to a single call. Matching is on objectKey
// rather than the full description so that re-blocking with a new deadline
// updates the existing rule instead of stranding the old one. If more than
// one match exists — a duplicate from a concurrent writer, or from a control
// plane that crashed between add and apply — the extras are deleted, because
// leaving them would mean the containment exists twice and Release would have
// to guess which copy is authoritative.
func (c *Client) upsertRule(ctx context.Context, want rule, candidates []ruleRow) error {
	key := objectKey(want.Description)
	var match *ruleRow
	var dupes []string
	for i := range candidates {
		if objectKey(candidates[i].Description) != key {
			continue
		}
		if match == nil {
			match = &candidates[i]
			continue
		}
		dupes = append(dupes, candidates[i].UUID)
	}

	if match == nil {
		var out struct {
			Result string `json:"result"`
			UUID   string `json:"uuid"`
		}
		if err := c.doJSON(ctx, http.MethodPost, epAddRule, map[string]any{"rule": want}, &out); err != nil {
			return fmt.Errorf("opnsense: adding rule %q: %w", want.Description, err)
		}
		if out.UUID == "" {
			return fmt.Errorf("opnsense: adding rule %q: API returned no uuid", want.Description)
		}
		return nil
	}

	if err := c.doJSON(ctx, http.MethodPost, epSetRule+"/"+match.UUID, map[string]any{"rule": want}, nil); err != nil {
		return fmt.Errorf("opnsense: updating rule %q: %w", want.Description, err)
	}
	for _, u := range dupes {
		if err := c.delRule(ctx, u); err != nil {
			return err
		}
	}
	return nil
}

// upsertHost is upsertRule's Unbound counterpart, matching on the same key.
func (c *Client) upsertHost(ctx context.Context, want hostOverride) error {
	all, err := c.listHosts(ctx)
	if err != nil {
		return err
	}
	key := objectKey(want.Description)
	var match *hostRow
	var dupes []string
	for i := range all {
		if objectKey(all[i].Description) != key {
			continue
		}
		if match == nil {
			match = &all[i]
			continue
		}
		dupes = append(dupes, all[i].UUID)
	}

	if match == nil {
		var out struct {
			Result string `json:"result"`
			UUID   string `json:"uuid"`
		}
		if err := c.doJSON(ctx, http.MethodPost, epHostAdd, map[string]any{"host": want}, &out); err != nil {
			return fmt.Errorf("opnsense: adding host override %q: %w", want.Description, err)
		}
		if out.UUID == "" {
			return fmt.Errorf("opnsense: adding host override %q: API returned no uuid", want.Description)
		}
		return nil
	}

	if err := c.doJSON(ctx, http.MethodPost, epHostDel+"/"+match.UUID, nil, nil); err == nil {
		// setHostOverride would also work; delete-then-add is used because it
		// is the one path that is unambiguous about the whole node being
		// replaced rather than merged, which matters for fields such as
		// addptr that a partial merge would leave stale.
		var out struct {
			Result string `json:"result"`
			UUID   string `json:"uuid"`
		}
		if err := c.doJSON(ctx, http.MethodPost, epHostAdd, map[string]any{"host": want}, &out); err != nil {
			return fmt.Errorf("opnsense: replacing host override %q: %w", want.Description, err)
		}
		if out.UUID == "" {
			return fmt.Errorf("opnsense: replacing host override %q: API returned no uuid", want.Description)
		}
	} else {
		// Fall back to a partial update when the delete is refused, which
		// happens when the override is referenced by an Unbound alias.
		if err := c.doJSON(ctx, http.MethodPost, "unbound/settings/setHostOverride/"+match.UUID, map[string]any{"host": want}, nil); err != nil {
			return fmt.Errorf("opnsense: updating host override %q: %w", want.Description, err)
		}
	}

	for _, u := range dupes {
		if err := c.delHost(ctx, u); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) delRule(ctx context.Context, uuid string) error {
	if err := c.doJSON(ctx, http.MethodPost, epDelRule+"/"+uuid, nil, nil); err != nil {
		return fmt.Errorf("opnsense: deleting rule %s: %w", uuid, err)
	}
	return nil
}

func (c *Client) delHost(ctx context.Context, uuid string) error {
	if err := c.doJSON(ctx, http.MethodPost, epHostDel+"/"+uuid, nil, nil); err != nil {
		return fmt.Errorf("opnsense: deleting host override %s: %w", uuid, err)
	}
	return nil
}

// applyFilter makes staged rules live. Without it a rule exists in the config
// and does nothing, which is indistinguishable from a rule that failed.
func (c *Client) applyFilter(ctx context.Context) error {
	var out struct {
		Status string `json:"status"`
	}
	if err := c.doJSON(ctx, http.MethodPost, epApply, nil, &out); err != nil {
		return fmt.Errorf("opnsense: applying filter: %w", err)
	}
	// applyAction answers {"status":"error"} with HTTP 200 when the request
	// was not a POST. Treating a non-ok status as success would make a
	// malformed call look like a successful reload.
	if out.Status != "" && out.Status != "ok" {
		return fmt.Errorf("opnsense: applying filter: appliance reported status %q", out.Status)
	}
	return nil
}

func (c *Client) syncUnbound(ctx context.Context) error {
	if err := c.doJSON(ctx, http.MethodPost, epUnboundSync, nil, nil); err != nil {
		return fmt.Errorf("opnsense: reconfiguring resolver: %w", err)
	}
	return nil
}

// --- transport ------------------------------------------------------------

// statusError is a non-2xx response. It is a distinct type from a transport
// error so callers can tell a rejected credential from an unreachable firewall.
type statusError struct {
	Method string
	Path   string
	Status int
	Body   string
}

func (e *statusError) Error() string {
	msg := fmt.Sprintf("opnsense: %s %s: HTTP %d", e.Method, e.Path, e.Status)
	switch e.Status {
	case http.StatusUnauthorized:
		return msg + " (API key/secret rejected; on older appliances this is also returned when the owning user lacks the page privilege)"
	case http.StatusForbidden:
		return msg + " (credentials valid but the owning user lacks the page privilege for this endpoint)"
	}
	if e.Body != "" {
		return msg + ": " + e.Body
	}
	return msg
}

// Is maps the two authentication-ish statuses onto sentinels so callers can
// branch with errors.Is without type-asserting.
func (e *statusError) Is(target error) bool {
	switch target {
	case ErrAuth:
		return e.Status == http.StatusUnauthorized
	case ErrForbidden:
		return e.Status == http.StatusForbidden
	}
	return false
}

// doJSON performs one API call and optionally decodes the response into out.
//
// A transport error returns an error that is neither ErrAuth nor ErrForbidden,
// which is the whole point: retrying an unreachable firewall is correct,
// retrying a revoked credential is not.
func (c *Client) doJSON(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("opnsense: %s %s: encoding request: %w", method, path, err)
		}
		rdr = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.cfg.BaseURL+"/api/"+path, rdr)
	if err != nil {
		return fmt.Errorf("opnsense: %s %s: %w", method, path, err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.SetBasicAuth(c.cfg.APIKey, c.cfg.APISecret)

	resp, err := c.cfg.Transport.Do(req)
	if err != nil {
		return fmt.Errorf("opnsense: %s %s: transport: %w", method, path, err)
	}
	if resp == nil {
		return fmt.Errorf("opnsense: %s %s: transport returned no response", method, path)
	}
	defer resp.Body.Close()

	// The body is read once and reused: it is needed both for the error text
	// and for decoding, and a non-2xx body usually carries the only
	// explanation available.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("opnsense: %s %s: reading response: %w", method, path, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &statusError{Method: method, Path: path, Status: resp.StatusCode, Body: snippet(raw)}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("opnsense: %s %s: decoding response: %w", method, path, err)
	}
	return nil
}

// snippet trims a response body down to something loggable.
func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	const max = 256
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// --- naming helpers -------------------------------------------------------

// Description layout: "<prefix> <kind> <key> [until <unix>]".
//
// The kind and key are what make deletion surgical. Release matches on
// "<prefix> q <mac> " and "<prefix> a <mac> ", which cannot collide with
// another device, an IoC block ("<prefix> n ...") or an operator's own rule.

func descQuarantinePrefix(mac string) string {
	return descPrefix + " " + kindQuarantine + " " + sanitizeMAC(mac) + " "
}
func descAuthoritativePrefix(mac string) string {
	return descPrefix + " " + kindAuthoritv + " " + sanitizeMAC(mac) + " "
}
func descQuarantine(d core.Device, kind string) string {
	return descQuarantinePrefix(d.MAC.String()) + kind
}
func descAuthoritative(d core.Device) string {
	return descAuthoritativePrefix(d.MAC.String()) + sanitizeLabel(d)
}
func descNetBlock(n netip.Prefix, until time.Time) string {
	return descPrefix + " " + kindNetBlock + " " + n.String() + untilSuffix(until)
}
func descDomainSink(domain string, until time.Time) string {
	suffix := untilSuffix(until)
	prefix := descPrefix + " " + kindDomainSink + " "
	maxDomain := 255 - len(prefix) - len(suffix)
	if len(domain) > maxDomain {
		domain = domain[:maxDomain]
	}
	return prefix + domain + suffix
}

func untilSuffix(until time.Time) string { return " until " + strconv.FormatInt(until.Unix(), 10) }

// objectKey strips the recorded deadline from a description, leaving the part
// that identifies *what* the object is rather than how long it should live.
//
// Matching on this key is what keeps re-blocking idempotent. Matching on the
// full description would treat "same prefix, later deadline" as a brand new
// object, so every repeated BlockNet call would leave another rule behind and
// Release would then have to delete all of them to restore access.
func objectKey(desc string) string {
	if i := strings.LastIndex(desc, " until "); i >= 0 {
		return desc[:i]
	}
	return desc
}

// recordedUntil recovers the deadline written by untilSuffix.
func recordedUntil(desc string) (int64, bool) {
	i := strings.LastIndex(desc, " until ")
	if i < 0 {
		return 0, false
	}
	n, err := strconv.ParseInt(desc[i+len(" until "):], 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// sanitizeLabel builds a Unbound-safe hostname from a device.
func sanitizeLabel(d core.Device) string {
	base := d.Vendor
	if base == "" {
		base = "device"
	}
	base = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		case r >= '0' && r <= '9', r == '-':
			return r
		default:
			return '-'
		}
	}, base)
	base = strings.Trim(base, "-")
	if base == "" {
		base = "device"
	}
	// Unbound hostnames are limited to 63 characters.
	const maxLabel = 40
	if len(base) > maxLabel {
		base = strings.TrimRight(base[:maxLabel], "-")
	}
	return base + "-" + sanitizeMAC(d.MAC.String())
}

func sanitizeMAC(mac string) string {
	return strings.NewReplacer(":", "", ".", "", "-", "").Replace(strings.ToLower(mac))
}

// normalizeDomain lowercases and validates a domain before it reaches the API.
// The model's domain mask would reject a malformed value anyway, but with a
// 200 and a validation body that no caller reads; catching it here turns a
// silently-ignored block into a returned error.
func normalizeDomain(d string) (string, error) {
	d = strings.ToLower(strings.Trim(strings.TrimSpace(d), "."))
	if d == "" {
		return "", errors.New("opnsense: BlockDomain requires a domain")
	}
	if len(d) > 253 {
		return "", errors.New("opnsense: BlockDomain requires a domain of at most 253 characters")
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("opnsense: BlockDomain: invalid domain %q", d)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("opnsense: BlockDomain: invalid domain %q", d)
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			default:
				return "", fmt.Errorf("opnsense: BlockDomain: invalid domain %q", d)
			}
		}
	}
	return d, nil
}

// prefixStrings renders prefixes for the API, preserving IPv6 form and any
// bits OPNsense requires the caller to have masked.
func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}

func ipProtocolFor(n netip.Prefix) string {
	if n.Addr().Is4() {
		return "inet"
	}
	return "inet6"
}

func onOff(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// allRowsBody asks a search endpoint for every record in one page.
func allRowsBody() map[string]any {
	return map[string]any{"current": 1, "rowCount": -1}
}
