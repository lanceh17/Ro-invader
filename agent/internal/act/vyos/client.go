// Package vyos implements act.Actuator against a VyOS router's HTTP API.
//
// # Version support
//
// VyOS 1.3 has no API of any kind: no HTTP, no REST, no RPC. The only way to
// drive a 1.3 router is the CLI, which means SSH, and SAFETY.md forbids the
// control plane from holding a remote execution channel. A 1.3 router is
// therefore out of scope rather than merely unreachable, and Health fails
// loudly on one instead of pretending to work. VyOS 1.4 (sagitta) introduced
// the operational-mode API this package speaks; 1.5 (circinus) keeps every
// endpoint used here and adds nothing this package depends on.
//
// # Endpoints
//
//	POST /show       operational-mode commands (read)
//	POST /retrieve   showConfig / returnValues / exists (read)
//	POST /configure  set / delete / comment (write)
//
// Every endpoint is POST-only and takes the API key in a form field named
// "key", never in a header. VyOS 1.5 additionally accepts an X-API-KEY header
// or a bearer JWT; this package uses neither, because a 1.4 router — the
// oldest release supported here — honours neither, and code that works only
// on the newest release is code that fails on the version most operators run.
//
// Responses are served as text/html despite carrying JSON. The body is parsed
// as JSON unconditionally and Content-Type is never consulted; a client that
// trusted the header would reject every successful response from the endpoint
// it exists to read.
//
// # API keys are full admin, and that is not fixable here
//
// `set service https api keys id <name> key <key>` is the minimal
// configuration for a working API, and every key it creates has full,
// identical, unrestricted permission on the system. There is no per-key scope,
// no read-only key, and no RBAC layer in 1.4 or 1.5. A key issued to this
// tool can therefore rewrite the operator's routing table, and "scope it down
// for the containment tool" is not an available mitigation.
//
// The mitigations that are available are the ones this package applies: the
// key is never logged, never echoed into an error, and never written into the
// router's own configuration; and every write this package performs is
// addressed to a node under the "R0I-" namespace described below, so a
// compromised control plane has to choose which operator-owned node to
// overwrite rather than being handed the whole router by default. Operators
// who need a hard boundary should run the API listener on a management
// interface and restrict it with `set service https allow-client address`.
//
// # Containment mechanism: nftables sets, not ipsets
//
// docs/ARCHITECTURE.md describes this adapter as "/configure with ipset
// groups". That was written against a VyOS whose firewall was iptables-based.
// VyOS 1.3 replaced the firewall with nftables and 1.4 has no ipset
// subsystem at all: `firewall/nftables.j2` renders every group as an nftables
// `set` with `flags interval`, and there is no configuration node anywhere in
// 1.4 that reaches an ipset. The intent of the architecture note is
// preserved exactly -- containment is expressed as membership of a named
// address set rather than as one rule per device -- but the set is reached
// through `set firewall group address-group`/`network-group`/`mac-group`,
// because that is the only node tree VyOS 1.4 actually has.
//
// # Walled garden
//
// VyOS 1.4 runs PowerDNS as its resolver and exposes per-domain forwarding
// under `set service dns forwarding domain <d> name-server <ip>`. A blocked
// domain is a domain forwarded to an address that answers nothing, which is
// what Config.SinkholeIP is for. The firewall also has a `domain-group` node
// that a rule can match on, but how a 1.4 domain-group is populated at packet
// level depends on VyOS's internal DNS interception, which this package does
// not rely on and could not verify against documentation. The resolver-level
// sinkhole is the mechanism implemented here because it is the one the 1.4
// documentation states plainly; the domain-group exists alongside it as
// durable, per-domain metadata carrying the expiry deadline.
//
// # Expiry is not enforced by the router
//
// BlockNet and BlockDomain are given a deadline, and the contract in
// actuator.go says a crashed control plane must leave no permanent block.
// VyOS 1.4 cannot honour that natively, and pretending otherwise would be
// worse than saying so:
//
//   - Firewall groups on 1.4 have no per-member timeout. `timeout` exists
//     only on a firewall rule's `add-address-to-group`, which populates a
//     dynamic group from a traffic match -- there is no way to place a
//     pre-loaded address in one and have the router expire it. Entries added
//     that way are documented to persist "until next reboot".
//   - Groups have one `description` for the whole set and no per-member
//     metadata, and 1.4 has no `include`, so one group cannot inherit
//     another's membership. A per-entry deadline therefore needs a per-entry
//     node.
//   - 1.4 has no task scheduler and no cron, so nothing can be arranged to
//     run the removal later.
//
// What this package does instead: the deadline is written into the router's
// own configuration, as the `description` of a per-entry node named after the
// thing it describes (`R0I-EXP-<prefix>`, `R0I-DOM-<domain>`). That record
// survives the control plane, is readable with `show`, and is what
// SweepExpired acts on. It is not the same thing as router-enforced expiry:
// a control plane that never comes back leaves the block in force. There is
// no local timer standing in for one, because a timer that dies with the
// process is the exact failure the contract was written to exclude. Release
// remains the recovery path, and it remains a single call that always
// succeeds.
//
// # Namespacing
//
// Every node this package creates lives under the "R0I-" prefix and nowhere
// else: the firewall chain R0I-CONTAIN, the groups R0I-PEERMAC, R0I-PEERIP,
// R0I-EGRMAC, R0I-EGRIP, R0I-ALLOW, R0I-BLOCK, and the per-entry R0I-EXP-* and
// R0I-DOM-* nodes. VyOS's configuration is shared state with the operator's,
// and deleting a rule this tool did not create would destroy their setup, so
// Release and SweepExpired only ever address paths under that prefix.
//
// The one exception is a single rule number in the base chain: `firewall
// ipv4 forward filter rule 9000` jumps into R0I-CONTAIN. VyOS evaluates base
// chain rules in ascending numeric order and has no privileged system band,
// so an operator rule numbered below 9000 that accepts the traffic takes
// precedence over this package's block. Containment is therefore only
// guaranteed to precede rules the operator numbers above 9000. That is a
// property of VyOS rather than of this adapter, and no choice of node name
// changes it.
package vyos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

// Namespacing and layout. See the package comment for why each of these is
// what it is.
const (
	// prefix marks every configuration node this tool creates. VyOS node
	// names are case sensitive, and the upper-case form stays legible in
	// `show` output next to an operator's mixed-case names.
	prefix = "R0I-"

	// containChain is the custom firewall chain holding every rule this
	// package writes. Custom chains exist in VyOS precisely so that a set of
	// related rules can be added and removed without touching the operator's
	// base chains beyond a single jump.
	containChain = prefix + "CONTAIN"

	// baseRuleNum is the single base-chain rule that jumps into containChain,
	// in `firewall ipv4 forward filter`. It is one number, fixed forever, so
	// no allocation scheme and no counter can collide with it.
	baseRuleNum = "9000"

	// dnsRuleNum is the NAT rule that redirects DNS to the router's own
	// resolver. NAT rules are a separate numbering space from firewall rules,
	// so the same number is free here.
	dnsRuleNum = "9000"

	// peerMACGroup and peerIPGroup hold the devices whose lateral movement is
	// blocked. A MAC match survives a DHCP change; an address match catches a
	// device the router forwards for but cannot see the link address of.
	// Both are used because neither alone is sufficient.
	peerMACGroup = prefix + "PEERMAC"
	peerIPGroup  = prefix + "PEERIP"

	// egrMACGroup and egrIPGroup hold the devices whose egress is restricted
	// to the walled garden described by allowGroup.
	egrMACGroup = prefix + "EGRMAC"
	egrIPGroup  = prefix + "EGRIP"

	// allowGroup is the walled garden itself: the prefixes a restricted device
	// may still reach, normally the RFC1918 space so that DNS, NTP and a
	// LAN-hosted remediation portal keep working.
	allowGroup = prefix + "ALLOW"

	// blockGroup is every prefix handed to BlockNet. One shared set rather
	// than one rule per prefix, which is what makes a blocklist of any size
	// cost a constant number of firewall rules.
	blockGroup = prefix + "BLOCK"

	// Rule numbers inside containChain. The chain is entirely this package's,
	// so these are a private numbering space with no operator collision.
	// Order matters: a device's allow rules must be evaluated before the
	// blanket drop that follows them.
	rulePeerMAC     = "10"
	rulePeerIP      = "11"
	ruleEgrAllowMAC = "20"
	ruleEgrAllowIP  = "21"
	ruleEgrDropMAC  = "22"
	ruleEgrDropIP   = "23"
	ruleBlock       = "30"

	// deadlineTag prefixes the machine-readable deadline written into a
	// per-entry node's description.
	deadlineTag = "r0i_until="
)

// Doer is the HTTP transport seam. Injecting it is what lets the whole
// adapter be tested against a mock router, with no VyOS device present and no
// listening socket in the test process.
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

const (
	// maxRequestBytes mirrors VyOS's own `service https request-body-size-limit`
	// default. The router rejects anything larger with an opaque 413, so the
	// same check is applied here where the error can name the cause.
	maxRequestBytes = 1 << 20

	// maxResponseBytes caps how much of a reply is read. A misconfigured
	// BaseURL -- a proxy answering with an endless stream, say -- becomes a
	// bounded read and an error rather than an out-of-memory kill of a process
	// whose whole job is to stay up and keep watching.
	maxResponseBytes = 8 << 20
)

// Config configures a Client.
type Config struct {
	// BaseURL is the router's API root, e.g. "https://192.168.1.1". A
	// trailing slash is stripped so paths can be appended without producing a
	// doubled separator.
	BaseURL string

	// APIKey authenticates every request. It is passed as the form field
	// VyOS 1.4 requires, never as a header, and is never logged or echoed
	// into an error.
	//
	// Every VyOS API key is full administrator with no scoping mechanism at
	// all. See the package comment: this credential can rewrite the
	// operator's routing, and there is no lesser key to issue instead.
	APIKey string

	// LANInterface is the interface managed devices sit behind, e.g. "eth1".
	// The DNS redirect installed by Authoritative is scoped to it so that
	// port-53 traffic arriving from anywhere else is not silently absorbed
	// into the router's resolver.
	LANInterface string

	// SinkholeIP is where BlockDomain points a blocked domain: an address on
	// the operator's own network that nothing answers, so the lookup fails
	// locally and the name does not resolve. Choosing it is the operator's
	// call, not this package's, because the right answer depends on which
	// addresses are live on their network.
	SinkholeIP netip.Addr

	// EgressAllow is the walled garden a restricted device may still reach.
	// Without it a quarantined device would be cut off entirely and could
	// never be remediated, which is a worse outcome than the infection.
	EgressAllow []netip.Prefix

	// Transport overrides the HTTP transport. Nil uses the default.
	Transport Doer

	// HTTPTimeout bounds each request. Zero uses a 10 second default.
	HTTPTimeout time.Duration
}

// Client implements act.Actuator for VyOS.
type Client struct {
	cfg Config
	do  Doer
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("vyos: BaseURL is required")
	}
	if cfg.APIKey == "" {
		// The key names the field so an operator reading a startup failure
		// knows which value to look for without reading this package.
		return nil, errors.New("vyos: APIKey is required")
	}
	if cfg.LANInterface == "" {
		return nil, errors.New("vyos: LANInterface is required")
	}
	if !cfg.SinkholeIP.IsValid() {
		return nil, errors.New("vyos: SinkholeIP is required")
	}
	// A router without a configured egress allowlist would, if asked to
	// restrict, cut the device off entirely. Default it before the config is
	// captured into the Client; assigning it afterwards would apply to a local
	// copy and leave the foot-gun in place.
	if len(cfg.EgressAllow) == 0 {
		cfg.EgressAllow = defaultEgressAllow()
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.Transport == nil {
		cfg.Transport = newHTTPDoer(cfg.HTTPTimeout)
	}
	return &Client{cfg: cfg, do: cfg.Transport}, nil
}

func defaultEgressAllow() []netip.Prefix {
	// The local networks, so that DNS and NTP keep working and the device can
	// reach a remediation portal hosted on the LAN.
	return []netip.Prefix{
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
	}
}

// Name identifies this backend.
func (c *Client) Name() string { return "vyos" }

// Authoritative points the LAN's DNS at the router's own resolver.
//
// This is load-bearing rather than cosmetic. In a passive-only design the
// resolver is the only guaranteed identity source: a device that does not
// resolve through the managed path is invisible, and both the walled garden
// and remediation notification depend on that one mechanism. A NAT redirect
// is used rather than a DHCP option because routers are frequently configured
// with static addressing, and a device that never received a DHCP lease can
// never have been given a resolver.
//
// The rule is installed once and is not per-device, because VyOS 1.4 NAT
// rules cannot reference an address group -- only literal addresses -- and
// one rule per device would need rule numbers this package has no way to
// allocate deterministically. Identity is not lost by that: the redirect
// preserves the source address, so the resolver still sees which device asked.
func (c *Client) Authoritative(ctx context.Context, d core.Device) error {
	if len(d.MAC) == 0 {
		return errors.New("vyos: Authoritative requires a device MAC")
	}
	// Written in dependency order; VyOS commits the whole batch once, so a
	// partially applied redirect is not a state this can be left in.
	return c.apply(ctx,
		setCmd("nat", "destination", "rule", dnsRuleNum, "description",
			"R0-Invader: authoritative resolver for "+describe(d)),
		setCmd("nat", "destination", "rule", dnsRuleNum, "inbound-interface", "name", c.cfg.LANInterface),
		setCmd("nat", "destination", "rule", dnsRuleNum, "protocol", "tcp_udp"),
		setCmd("nat", "destination", "rule", dnsRuleNum, "destination", "port", "53"),
		// "redirect" is VyOS's DNAT-to-localhost form, so the query lands on
		// whichever local address the device addressed rather than on a
		// hard-coded one.
		setCmd("nat", "destination", "rule", dnsRuleNum, "translation", "redirect", "port", "53"),
	)
}

// Quarantine applies a containment policy to the device.
//
// The whole desired state is written on every call rather than a diff against
// it. VyOS `set` is idempotent, so a redundant apply costs one commit and
// leaves the same configuration behind -- which is exactly the property the
// actuator interface demands of a repeated call, and it removes any chance of
// a policy change being half-applied because an earlier call failed midway.
func (c *Client) Quarantine(ctx context.Context, d core.Device, p core.Policy) error {
	if len(d.MAC) == 0 {
		return errors.New("vyos: Quarantine requires a device MAC")
	}
	if p.Name == core.ContainmentMonitor {
		// Monitor affects no traffic. Ensure nothing is left behind from a
		// previous, higher tier, so that lowering the tier actually lifts the
		// restriction rather than merely changing the label.
		return c.Release(ctx, d)
	}

	mac := d.MAC.String()
	ips := ipv4s(d)

	cmds := c.containChainCmds()
	cmds = append(cmds, c.allowGroupCmds()...)

	// Membership is expressed as group membership rather than as one rule per
	// device, so a thousand quarantined devices cost the same six firewall
	// rules as one.
	if p.BlockPeers {
		cmds = append(cmds, setCmd(append(fwGroup("mac-group"), peerMACGroup, "mac-address", mac)...))
		for _, ip := range ips {
			cmds = append(cmds, setCmd(append(fwGroup("address-group"), peerIPGroup, "address", ip)...))
		}
	}
	if p.RestrictEgress {
		cmds = append(cmds, setCmd(append(fwGroup("mac-group"), egrMACGroup, "mac-address", mac)...))
		for _, ip := range ips {
			cmds = append(cmds, setCmd(append(fwGroup("address-group"), egrIPGroup, "address", ip)...))
		}
	}
	return c.apply(ctx, cmds...)
}

// containChainCmds writes the chain and every rule in it.
//
// The rules are written unconditionally so that an operator who edited one of
// them by hand gets it restored on the next apply. VyOS has no privileged
// system band in the base chain, so this package's blocks are reachable only
// by rules the operator has numbered above baseRuleNum; see the package
// comment.
func (c *Client) containChainCmds() []apiOp {
	return []apiOp{
		setCmd("firewall", "ipv4", "name", containChain, "description",
			"R0-Invader containment; do not edit, rewritten on every apply"),
		// A custom chain's default action is drop when unset. Returning is
		// what keeps this chain from becoming the place where the operator's
		// forwarded traffic dies.
		setCmd("firewall", "ipv4", "name", containChain, "default-action", "return"),

		setCmd("firewall", "ipv4", "name", containChain, "rule", rulePeerMAC, "description", "r0i peer block (mac)"),
		setCmd("firewall", "ipv4", "name", containChain, "rule", rulePeerMAC, "action", "drop"),
		setCmd("firewall", "ipv4", "name", containChain, "rule", rulePeerMAC, "source", "group", "mac-group", peerMACGroup),

		setCmd("firewall", "ipv4", "name", containChain, "rule", rulePeerIP, "description", "r0i peer block (address)"),
		setCmd("firewall", "ipv4", "name", containChain, "rule", rulePeerIP, "action", "drop"),
		setCmd("firewall", "ipv4", "name", containChain, "rule", rulePeerIP, "source", "group", "address-group", peerIPGroup),

		// Egress restriction is an allowlist expressed positively: accept
		// anything reaching the walled garden, then drop whatever is left.
		// The negated form -- "destination group network-group !R0I-ALLOW" --
		// would be a single rule, but whether VyOS's config parser accepts a
		// "!" prefix sent through the API is not something this package can
		// verify without a device, and getting it wrong is a firewall that
		// silently blocks remediation.
		setCmd("firewall", "ipv4", "name", containChain, "rule", ruleEgrAllowMAC, "description", "r0i egress allow (mac)"),
		setCmd("firewall", "ipv4", "name", containChain, "rule", ruleEgrAllowMAC, "action", "accept"),
		setCmd("firewall", "ipv4", "name", containChain, "rule", ruleEgrAllowMAC, "source", "group", "mac-group", egrMACGroup),
		setCmd("firewall", "ipv4", "name", containChain, "rule", ruleEgrAllowMAC, "destination", "group", "network-group", allowGroup),

		setCmd("firewall", "ipv4", "name", containChain, "rule", ruleEgrAllowIP, "description", "r0i egress allow (address)"),
		setCmd("firewall", "ipv4", "name", containChain, "rule", ruleEgrAllowIP, "action", "accept"),
		setCmd("firewall", "ipv4", "name", containChain, "rule", ruleEgrAllowIP, "source", "group", "address-group", egrIPGroup),
		setCmd("firewall", "ipv4", "name", containChain, "rule", ruleEgrAllowIP, "destination", "group", "network-group", allowGroup),

		setCmd("firewall", "ipv4", "name", containChain, "rule", ruleEgrDropMAC, "description", "r0i egress restrict (mac)"),
		setCmd("firewall", "ipv4", "name", containChain, "rule", ruleEgrDropMAC, "action", "drop"),
		setCmd("firewall", "ipv4", "name", containChain, "rule", ruleEgrDropMAC, "source", "group", "mac-group", egrMACGroup),

		setCmd("firewall", "ipv4", "name", containChain, "rule", ruleEgrDropIP, "description", "r0i egress restrict (address)"),
		setCmd("firewall", "ipv4", "name", containChain, "rule", ruleEgrDropIP, "action", "drop"),
		setCmd("firewall", "ipv4", "name", containChain, "rule", ruleEgrDropIP, "source", "group", "address-group", egrIPGroup),

		setCmd("firewall", "ipv4", "name", containChain, "rule", ruleBlock, "description", "r0i blocked prefix"),
		setCmd("firewall", "ipv4", "name", containChain, "rule", ruleBlock, "action", "drop"),
		setCmd("firewall", "ipv4", "name", containChain, "rule", ruleBlock, "destination", "group", "network-group", blockGroup),

		setCmd("firewall", "ipv4", "forward", "filter", "rule", baseRuleNum, "description",
			"R0-Invader: enter "+containChain),
		setCmd("firewall", "ipv4", "forward", "filter", "rule", baseRuleNum, "action", "jump"),
		setCmd("firewall", "ipv4", "forward", "filter", "rule", baseRuleNum, "jump-target", containChain),
	}
}

// allowGroupCmds writes the walled garden. It is written on every Quarantine,
// not only when egress is restricted, so the groups the chain's egress rules
// reference always exist. A rule pointing at an undefined group is a commit
// VyOS rejects, which would take the peer block down with it.
func (c *Client) allowGroupCmds() []apiOp {
	cmds := make([]apiOp, 0, len(c.cfg.EgressAllow))
	for _, p := range c.cfg.EgressAllow {
		cmds = append(cmds, setCmd(append(fwGroup("network-group"), allowGroup, "network", p.String())...))
	}
	return cmds
}

// Release removes all containment from a device.
//
// It must always succeed for a previously quarantined device. A security tool
// that can lock an appliance out with no route to recovery is worse than no
// tool, and the failure mode here is an operator with a bricked camera and no
// way back.
//
// Only this device's own members are removed. The chain, the base-chain jump
// and the groups themselves are left in place: other devices are probably
// still quarantined, and a release must not lift their containment as a side
// effect. With the device's members gone, no rule in the chain matches it.
//
// Presence is checked before each delete rather than deleting blindly. VyOS
// 1.4 accepts a delete of an absent path and reports success without doing
// anything, while `set service https api strict` makes the same request fail;
// checking first is the one behaviour that is correct under both settings.
func (c *Client) Release(ctx context.Context, d core.Device) error {
	if len(d.MAC) == 0 {
		return errors.New("vyos: Release requires a device MAC")
	}

	targets := [][]string{
		append(fwGroup("mac-group"), peerMACGroup, "mac-address", d.MAC.String()),
		append(fwGroup("mac-group"), egrMACGroup, "mac-address", d.MAC.String()),
	}
	for _, ip := range ipv4s(d) {
		targets = append(targets,
			append(fwGroup("address-group"), peerIPGroup, "address", ip),
			append(fwGroup("address-group"), egrIPGroup, "address", ip),
		)
	}

	var cmds []apiOp
	for _, path := range targets {
		ok, err := c.exists(ctx, path...)
		if err != nil {
			return err
		}
		if ok {
			cmds = append(cmds, delCmd(path...))
		}
	}
	if len(cmds) == 0 {
		// Nothing to do. Returning nil keeps Release idempotent, which matters
		// because the portal calls it on a user's confirmation and a user may
		// well click twice.
		return nil
	}
	return c.apply(ctx, cmds...)
}

// BlockNet blocks a prefix for a bounded duration.
//
// The prefix goes into a shared network group, so any number of blocks cost
// one firewall rule. The deadline goes into a separate per-prefix node's
// description, because a 1.4 group has one description for the whole set and
// no per-member metadata: see the package comment on why expiry is recorded
// rather than enforced.
func (c *Client) BlockNet(ctx context.Context, n netip.Prefix, until time.Time) error {
	cmds := c.containChainCmds()
	cmds = append(cmds,
		setCmd(append(fwGroup("network-group"), blockGroup, "network", n.String())...),
		setCmd(append(fwGroup("network-group"), deadlinePrefixGroup(n), "network", n.String())...),
		setCmd(append(fwGroup("network-group"), deadlinePrefixGroup(n), "description", deadline(until))...),
	)
	return c.apply(ctx, cmds...)
}

// BlockDomain sinkholes a domain for a bounded duration.
//
// The sinkhole is a per-domain forwarding rule on the router's own resolver:
// the domain resolves, forwards nowhere, and fails. Blocking at the resolver
// rather than at the firewall means the decision is made where the name is,
// so a device that has stopped trusting the firewall's port 53 answer still
// cannot resolve the name.
func (c *Client) BlockDomain(ctx context.Context, d string, until time.Time) error {
	domain := strings.ToLower(strings.TrimSpace(d))
	if domain == "" {
		return errors.New("vyos: BlockDomain requires a domain")
	}
	return c.apply(ctx,
		setCmd("service", "dns", "forwarding", "domain", domain, "name-server", c.cfg.SinkholeIP.String()),
		setCmd(append(fwGroup("domain-group"), deadlineDomainGroup(domain), "address", domain)...),
		setCmd(append(fwGroup("domain-group"), deadlineDomainGroup(domain), "description", deadline(until))...),
	)
}

// Health verifies that the router is reachable, that this key is accepted, and
// that this package can read back the chain it owns.
//
// A failing Health must block new containment actions rather than queueing
// them silently, so every one of those three is checked: a router that is up
// but whose API was disabled, or whose key was rotated, would otherwise look
// exactly like a router that accepted the rules.
func (c *Client) Health(ctx context.Context) error {
	enabled, err := c.exists(ctx, "service", "https", "api")
	if err != nil {
		return fmt.Errorf("vyos: health: %w", err)
	}
	if !enabled {
		return errors.New("vyos: health: service https api is not configured on the router")
	}

	// Reading our own chain back is the readback half of the contract. An
	// absent chain is not a failure: it means nothing has been quarantined
	// yet, and Health is called before the first action as often as after one.
	if _, err := c.showConfig(ctx, "firewall", "ipv4", "name", containChain); err != nil {
		var ae *apiError
		if errors.As(err, &ae) && ae.Missing {
			return nil
		}
		return fmt.Errorf("vyos: health: reading back %s: %w", containChain, err)
	}
	return nil
}

// SweepExpired removes blocks whose deadline has passed and returns what it
// released.
//
// It exists because VyOS 1.4 cannot expire a block on its own. Calling it is
// what makes `until` mean anything on this backend, and it is deliberately an
// explicit call rather than a background goroutine: a timer living inside the
// control plane dies with the control plane, which is precisely the failure
// the `until` contract was written to rule out. An operator who wants blocks
// to lapse without the control plane can call it on a schedule from outside
// this process.
//
// Nothing under the namespace is touched unless its recorded deadline has
// passed; a node whose description carries no deadline, or carries one this
// package cannot parse, is left alone and counted in `kept`.
func (c *Client) SweepExpired(ctx context.Context, now time.Time) (released, kept []string, err error) {
	nets, err := c.showConfig(ctx, "firewall", "group", "network-group")
	if err != nil {
		var ae *apiError
		if !errors.As(err, &ae) || !ae.Missing {
			return nil, nil, fmt.Errorf("vyos: sweep: reading network groups: %w", err)
		}
	}
	doms, err := c.showConfig(ctx, "firewall", "group", "domain-group")
	if err != nil {
		var ae *apiError
		if !errors.As(err, &ae) || !ae.Missing {
			return nil, nil, fmt.Errorf("vyos: sweep: reading domain groups: %w", err)
		}
	}

	var cmds []apiOp
	for name, node := range childNodes(nets, deadlinePrefixPrefix) {
		n, ok := node.(map[string]any)
		if !ok {
			continue
		}
		expired, ok := pastDeadline(n, now)
		if !ok {
			kept = append(kept, name)
			continue
		}
		if !expired {
			continue
		}
		for _, p := range leafStrings(n, "network") {
			cmds = append(cmds,
				delCmd(append(fwGroup("network-group"), blockGroup, "network", p)...),
				delCmd(append(fwGroup("network-group"), name)...),
			)
			released = append(released, p)
		}
		if len(leafStrings(n, "network")) == 0 {
			cmds = append(cmds, delCmd(append(fwGroup("network-group"), name)...))
			released = append(released, name)
		}
	}

	for name, node := range childNodes(doms, deadlineDomainPrefix) {
		n, ok := node.(map[string]any)
		if !ok {
			continue
		}
		expired, ok := pastDeadline(n, now)
		if !ok {
			kept = append(kept, name)
			continue
		}
		if !expired {
			continue
		}
		domains := leafStrings(n, "address")
		if len(domains) == 0 {
			domains = []string{name}
		}
		for _, domain := range domains {
			cmds = append(cmds,
				delCmd("service", "dns", "forwarding", "domain", domain),
				delCmd(append(fwGroup("domain-group"), name)...),
			)
			released = append(released, domain)
		}
	}

	if len(cmds) > 0 {
		if err := c.apply(ctx, cmds...); err != nil {
			return nil, nil, fmt.Errorf("vyos: sweep: %w", err)
		}
	}
	return released, kept, nil
}

// --- VyOS API plumbing ------------------------------------------------------

// apiOp is one element of an API request document. /configure and /retrieve
// share the {op, path} shape.
type apiOp struct {
	Op   string   `json:"op"`
	Path []string `json:"path"`
}

func setCmd(path ...string) apiOp { return apiOp{Op: "set", Path: path} }
func delCmd(path ...string) apiOp { return apiOp{Op: "delete", Path: path} }

// setPath is setCmd for a path assembled from parts. The path is copied rather
// than appended to in place: the caller's slice comes from fwGroup, and
// writing past its length would hand a later caller a value with the wrong
// contents in it.
func setPath(path []string, value string) apiOp {
	full := make([]string, 0, len(path)+1)
	full = append(full, path...)
	return apiOp{Op: "set", Path: append(full, value)}
}

// delPath is delCmd for an assembled path.
func delPath(path []string) apiOp {
	full := make([]string, len(path))
	copy(full, path)
	return apiOp{Op: "delete", Path: full}
}

// apiEnvelope is the reply shape. Every endpoint answers with it, whether the
// outcome is a success or a refusal.
//
// Error is kept as raw JSON rather than typed because VyOS does not keep the
// error shape stable across 1.4 and 1.5: some builds return a bare string,
// others an object carrying a message. Assuming either shape means printing
// the useless literal "null" for the other, and the error body is the one
// part of the response an operator actually needs to read.
//
// Data is raw too, because it is a string for /show, an object for
// showConfig, a boolean for exists and null for /configure.
type apiEnvelope struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   json.RawMessage `json:"error"`
}

// apiError is a VyOS-level refusal: a 2xx response carrying success:false. It
// is distinct from a transport failure so a caller can tell "the router said
// no" from "the router did not answer" -- the first is not worth retrying,
// the second is.
type apiError struct {
	Endpoint string
	Op       string
	Path     string
	Detail   string
	// Missing reports that the router said the configuration path is not
	// there. It is the difference between "release nothing" and "release
	// failed", and it is also what makes Release safe under
	// `set service https api strict`.
	Missing bool
}

func (e *apiError) Error() string {
	return fmt.Sprintf("vyos: %s %s %s: %s", e.Endpoint, e.Op, e.Path, e.Detail)
}

// apply writes configuration.
//
// Every command in one Actuator call goes out as a single request because
// /configure commits each request it processes. On a firewall commit that
// means one nftables ruleset regeneration instead of a dozen, and it removes
// the half-applied state a failure between requests would otherwise leave
// behind.
func (c *Client) apply(ctx context.Context, cmds ...apiOp) error {
	if len(cmds) == 0 {
		return nil
	}
	_, err := c.post(ctx, "/configure", cmds)
	return err
}

// showConfig reads a configuration subtree.
func (c *Client) showConfig(ctx context.Context, path ...string) (map[string]any, error) {
	raw, err := c.post(ctx, "/retrieve", apiOp{Op: "showConfig", Path: path})
	if err != nil {
		return nil, err
	}
	var node map[string]any
	if err := json.Unmarshal(raw, &node); err != nil {
		return nil, fmt.Errorf("vyos: reading %s: decoding response: %w", strings.Join(path, " "), err)
	}
	return node, nil
}

// exists reports whether a configuration path is present.
func (c *Client) exists(ctx context.Context, path ...string) (bool, error) {
	raw, err := c.post(ctx, "/retrieve", apiOp{Op: "exists", Path: path})
	if err != nil {
		return false, err
	}
	var ok bool
	if err := json.Unmarshal(raw, &ok); err != nil {
		return false, fmt.Errorf("vyos: checking %s: decoding response: %w", strings.Join(path, " "), err)
	}
	return ok, nil
}

// post performs one API request and returns the envelope's data field.
func (c *Client) post(ctx context.Context, endpoint string, doc any) (json.RawMessage, error) {
	body, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("vyos: encoding %s request: %w", endpoint, err)
	}
	if len(body) > maxRequestBytes {
		return nil, fmt.Errorf("vyos: %s request is %d bytes, over the %d byte cap",
			endpoint, len(body), maxRequestBytes)
	}

	// Form-encoded, not JSON: on 1.4 the API key is a form field and nothing
	// else. The header and bearer forms that 1.5 also accepts are not used,
	// because a 1.4 router honours neither.
	form := url.Values{"key": {c.cfg.APIKey}, "data": {string(body)}}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.do.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vyos: %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("vyos: %s: reading response: %w", endpoint, err)
	}

	// The status is checked before the envelope is trusted, and it names
	// resp.Status rather than the bare code: "503 Service Unavailable" tells an
	// operator the router is busy, where "503" tells them only that something
	// they own returned a number they have seen before.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("vyos: %s: HTTP %s", endpoint, statusText(resp))
	}

	var env apiEnvelope
	// Parsed regardless of Content-Type. VyOS serves this JSON as text/html,
	// and a client that dispatched on the header would reject every successful
	// response from the endpoint it exists to read.
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("vyos: %s: decoding response: %w", endpoint, err)
	}
	if env.Success {
		return env.Data, nil
	}

	detail := strings.TrimSpace(string(env.Error))
	if detail == "" || detail == "null" {
		detail = "request rejected by the router with no error detail"
	}
	path := ""
	if o, ok := doc.(apiOp); ok {
		path = strings.Join(o.Path, " ")
	} else if ops, ok := doc.([]apiOp); ok && len(ops) > 0 {
		path = ops[0].Op + " " + strings.Join(ops[0].Path, " ")
	}
	return nil, &apiError{
		Endpoint: endpoint,
		Op:       opOf(doc),
		Path:     path,
		Detail:   detail,
		Missing:  looksMissing(detail),
	}
}

func opOf(doc any) string {
	switch d := doc.(type) {
	case apiOp:
		return d.Op
	case []apiOp:
		if len(d) > 0 {
			return d[0].Op
		}
	}
	return ""
}

// looksMissing classifies VyOS's "there is nothing there" wording.
//
// The strings differ between releases and between operations, so this is a
// best-effort match over the phrasings VyOS is known to use rather than a
// structured code. Callers that must be certain -- Release, above all --
// check existence first and do not depend on it.
func looksMissing(detail string) bool {
	d := strings.ToLower(detail)
	for _, s := range []string{"is empty", "does not exist", "not found", "no such"} {
		if strings.Contains(d, s) {
			return true
		}
	}
	return false
}

// statusText renders a response status for an error message. A hand-built
// response -- from a custom Doer, or a test double -- may leave Status empty,
// so the numeric code is the fallback rather than the primary.
func statusText(resp *http.Response) string {
	if resp.Status != "" {
		return resp.Status
	}
	return strconv.Itoa(resp.StatusCode)
}

// --- naming helpers ---------------------------------------------------------

func fwGroup(kind string) []string { return []string{"firewall", "group", kind} }

const (
	deadlinePrefixTag = "EXP"
	deadlineDomainTag = "DOM"
)

// deadlinePrefixPrefix and deadlineDomainPrefix are the per-entry metadata
// nodes SweepExpired scans for. They are prefixes rather than exact names
// because the name carries the identity of the entry.
var (
	deadlinePrefixPrefix = prefix + deadlinePrefixTag + "-"
	deadlineDomainPrefix = prefix + deadlineDomainTag + "-"
)

func deadlinePrefixGroup(n netip.Prefix) string {
	return deadlinePrefixPrefix + slug(n.String())
}

func deadlineDomainGroup(domain string) string {
	return deadlineDomainPrefix + slug(domain)
}

// deadline renders `until` as the description this package records.
//
// A zero time means "no deadline", which is recorded as 0 and left alone by
// SweepExpired rather than being treated as already expired: an operator who
// asks for a permanent block gets one.
func deadline(until time.Time) string {
	if until.IsZero() {
		return deadlineTag + "0"
	}
	return deadlineTag + strconv.FormatInt(until.Unix(), 10)
}

// sanitizeMAC reduces a hardware address to the hexadecimal form VyOS group
// values and this package's node names both accept.
func sanitizeMAC(mac string) string {
	return strings.NewReplacer(":", "", ".", "", "-", "").Replace(strings.ToLower(mac))
}

// slug renders an arbitrary identity as a VyOS node-name fragment.
//
// It keeps a readable prefix and appends a hash, because the readable form
// alone is ambiguous: "a.b_c" and "a_b.c" both reduce to the same characters,
// and two block entries collapsing onto one node name would mean one of them
// silently inherited the other's deadline.
func slug(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	readable := b.String()
	if len(readable) > 40 {
		readable = readable[:40]
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return fmt.Sprintf("%s_%08x", readable, h.Sum32())
}

// describe renders a device as a human-readable label for a rule description.
// Descriptions are free text on the router, so this is for an operator reading
// `show`, and it is not used to build any node name.
func describe(d core.Device) string {
	base := d.Vendor
	if base == "" {
		base = "device"
	}
	var b strings.Builder
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == ' ', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return fmt.Sprintf("%s %s", b.String(), sanitizeMAC(d.MAC.String()))
}

// ipv4s returns the device's IPv4 addresses, deduplicated and in the order
// they were reported.
//
// Only IPv4: the chain this package writes is `firewall ipv4`, and a device
// reachable over IPv6 alone is not contained by it. That is a known gap of
// this backend rather than a deliberate choice, and it is why the MAC-based
// rules exist -- the router sees the link address regardless of which
// address family carried the packet.
func ipv4s(d core.Device) []string {
	seen := make(map[string]bool, len(d.IPs))
	out := make([]string, 0, len(d.IPs))
	for _, ip := range d.IPs {
		ip = ip.Unmap()
		if !ip.Is4() {
			continue
		}
		s := ip.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// childNodes returns the named children of a configuration node.
func childNodes(node map[string]any, want string) map[string]any {
	out := make(map[string]any)
	for k, v := range node {
		if !strings.HasPrefix(k, want) {
			continue
		}
		if child, ok := v.(map[string]any); ok {
			out[k] = child
		}
	}
	return out
}

// leafStrings reads a leaf that VyOS may store as one value or as a list.
// Both shapes are real: a single value is a bare string until a second one is
// added, and code that assumed one or the other breaks the first time a
// device has two addresses.
func leafStrings(node map[string]any, leaf string) []string {
	switch v := node[leaf].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// pastDeadline reports whether a per-entry node's deadline has passed.
//
// The second result is false when there is no deadline this package can read,
// which is the caller's cue to leave the entry alone: a node without a
// deadline is one this tool did not write, or one an operator edited, and
// deleting it because a field was missing would be exactly the kind of
// collateral damage the namespace exists to prevent.
func pastDeadline(node map[string]any, now time.Time) (expired, ok bool) {
	descs := leafStrings(node, "description")
	if len(descs) == 0 {
		return false, false
	}
	for _, d := range descs {
		v, found := strings.CutPrefix(d, deadlineTag)
		if !found {
			continue
		}
		secs, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return false, false
		}
		if secs <= 0 {
			// "No deadline" by construction: never swept.
			return false, true
		}
		return now.Unix() >= secs, true
	}
	return false, false
}
