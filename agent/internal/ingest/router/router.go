// Package router learns which MAC owns which IP address by reading the
// network's own inventory tables — DHCP leases and ARP/neighbour entries —
// from the router over its HTTP API.
//
// This is what makes attribution live. suricata.Attributor is otherwise
// satisfied from a static JSON file, which is fine in a lab and wrong in
// production: addresses move, devices appear, and a stale table means a
// detector that fires correctly and names the wrong device. Quarantining the
// wrong camera because a DHCP lease was reused is a worse outcome than
// quarantining none. The router already holds the mapping and will state it
// if asked through its documented API.
//
// Passive by construction, and that is structural rather than aspirational.
// Every request here is an HTTP read of state the router offers; nothing in
// this package sends a packet to a host, and nothing in it can cause the
// router to execute anything. On OpenWrt specifically the lease database is
// fetched with ubus `file read` and never `file exec`, because `file exec`
// is a general-purpose remote command channel — the exact capability
// SAFETY.md rules out — while reading one fixed path is not.
//
// Nothing here imports the actuator package. A reader of router state must
// stay usable on a network where this tool holds no rights to enforce
// anything, and coupling ingestion to enforcement would make that impossible
// to express.
//
// Vendors differ enough in their wire formats that each gets its own Source,
// but they converge on the same Lease, so everything above this layer — the
// Client, the attributor contract, the test harness — is vendor-agnostic.
package router

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
	"github.com/lanceh17/Ro-invader/agent/internal/ingest/suricata"
)

// Lease is one IP-to-MAC binding discovered on the network.
//
// A lease is a statement about who is at an address right now, not a claim
// about a device: the same MAC legitimately holds several addresses across
// DHCP renewals, IPv4 and IPv6, and each of them is a separate lease.
type Lease struct {
	// MAC is the device's hardware address, always six bytes and always in
	// net.HardwareAddr's canonical form. Every vendor's spelling is
	// normalized on the way in by NormalizeMAC, so two backends reporting
	// the same device agree on one key instead of producing two entries.
	MAC net.HardwareAddr
	// IP is the address the binding was observed at. It is unmapped, so an
	// IPv4-mapped IPv6 address is stored as the IPv4 address it is, and
	// therefore matches what Suricata reports for the same host.
	IP netip.Addr
	// Hostname is the name the device announced over DHCP and may be empty:
	// most embedded hardware sends none, and dnsmasq writes a literal "*"
	// for those. An empty hostname is normal data, not a parse failure.
	Hostname string
	// Vendor is an OUI-derived manufacturer hint, carried only by backends
	// that publish one (OPNsense resolves it from its own MAC database).
	// Empty means unknown — it is never guessed from the first bytes of the
	// address, because a wrong vendor label is worse than none.
	Vendor string
}

// Source reads leases from one vendor backend.
//
// A Source is deliberately minimal. It knows one vendor's wire format and
// nothing about merging, attribution, or the poll cycle, which keeps the
// per-vendor code testable against fixtures with no network anywhere in the
// picture, and lets a new vendor be added without touching the Client.
//
// Leases returns an empty slice and a nil error when the router is healthy
// but has nothing to say. "No leases" is a normal condition on a small
// network; treating it as a failure would make every poll cycle log an
// error for a quiet network.
type Source interface {
	Name() string
	Leases(ctx context.Context) ([]Lease, error)
}

// Doer is the HTTP transport seam.
//
// Injecting it is what lets the whole package be tested against a mock
// router with no device present. It is the same shape as the actuator
// package's Doer rather than a shared type: the two must be able to fail
// independently, because an ingester that could not be tested without an
// actuator would drag enforcement concerns into read-only code.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// httpDoer is the production Doer.
type httpDoer struct{ c *http.Client }

func (h httpDoer) Do(req *http.Request) (*http.Response, error) { return h.c.Do(req) }

// defaultHTTPTimeout bounds one request to a router.
//
// Routers are embedded devices with little memory and a CPU already busy
// serving the LAN. A request that never answers would otherwise hold the
// poll cycle open, and because the poll cycle is what keeps attribution
// current, a stuck request does not merely waste a goroutine — it freezes
// the device table for as long as it hangs.
const defaultHTTPTimeout = 10 * time.Second

func newHTTPDoer(timeout time.Duration) Doer {
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	return httpDoer{c: &http.Client{Timeout: timeout}}
}

// maxBody caps how much of a router response is read.
//
// The largest thing this package fetches is a dnsmasq lease database, which
// runs to a few hundred kilobytes on a large network. The cap turns a
// misconfigured BaseURL — a proxy answering with an endless stream, say —
// into a bounded read and an error rather than an out-of-memory kill of a
// process whose whole job is to stay up and keep watching.
const maxBody = 8 << 20

// Config configures a Client and the default sources built from it.
//
// The same Config serves every vendor constructor because they share these
// fields; each reads only the subset it needs. Username and Password carry
// OpenWrt's ubus credentials and, together, OPNsense's API key/secret pair.
// Token carries the standalone credential: VyOS's apikey, or OPNsense's API
// key.
type Config struct {
	// BaseURL is the router's HTTP API root, e.g. "http://192.168.1.1". It is
	// required, and a trailing slash is stripped so paths can be appended
	// without producing a doubled separator.
	BaseURL string
	// Username authenticates against OpenWrt's ubus session API.
	Username string
	// Password is the OpenWrt password, or the secret half of OPNsense's
	// API key/secret pair.
	Password string
	// Token is the vendor API key: VyOS's apikey, or OPNsense's API key.
	Token string
	// Transport overrides the HTTP transport. Nil uses a default client
	// bounded by HTTPTimeout.
	Transport Doer
	// HTTPTimeout bounds each request. Zero uses a 10 second default.
	HTTPTimeout time.Duration
	// Sources are the backends Poll reads. When empty, New builds a single
	// OpenWrt source from BaseURL, Username and Password — the common case
	// of one router on one vendor — so the simplest deployment configures
	// three fields and nothing else.
	Sources []Source
}

// Client accumulates leases from every configured source and answers
// suricata.Attributor.
//
// It is safe for concurrent use: the ingest loop calls MACFor from the hot
// path for every event while the poll loop is rebuilding the table behind it.
// The read lock is taken per lookup and the write lock per poll, so a
// contended MACFor blocks only other MACFor calls, never the poll that feeds
// them.
type Client struct {
	cfg     Config
	sources []Source

	mu      sync.RWMutex
	macOf   map[netip.Addr]net.HardwareAddr
	devices map[string]*deviceAcc
}

// deviceAcc accumulates everything one MAC has been seen to hold.
//
// It exists because a router reports addresses, not devices. Ten leases for
// ten addresses on one device is one device with ten addresses, and a table
// that treats them as ten devices would show an operator a dozen phantom
// entries for a single laptop.
type deviceAcc struct {
	mac       net.HardwareAddr
	ips       map[netip.Addr]struct{}
	hostnames map[string]struct{}
	vendor    string
	firstSeen time.Time
	lastSeen  time.Time
}

// The whole reason this package exists is to satisfy Attributor from live
// router state rather than a static file, so the relationship is asserted at
// compile time: if either signature moves, the build fails here rather than
// in whichever caller was supposed to notice.
var _ suricata.Attributor = (*Client)(nil)

// New validates cfg and returns a Client.
//
// Validation happens here rather than at first use because a missing BaseURL
// is an operator configuration mistake, and the moment to report it is
// startup — where the message can still be read — rather than the first
// poll, where it becomes one log line among thousands.
func New(cfg Config) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("router: BaseURL is required")
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")

	sources := cfg.Sources
	if len(sources) == 0 {
		// Default to the one backend that needs nothing but the fields this
		// Config already requires. An explicit empty Sources is a
		// programming error rather than a configuration choice, so there is
		// nothing to preserve here.
		src, err := NewOpenWrt(cfg)
		if err != nil {
			return nil, err
		}
		sources = []Source{src}
	}

	return &Client{
		cfg: cfg,
		// Copied rather than aliased: Config is passed by value but its
		// slice header is shared, and a caller that appended to it after New
		// returned would be racing with every Poll.
		sources: slices.Clone(sources),
		macOf:   map[netip.Addr]net.HardwareAddr{},
		devices: map[string]*deviceAcc{},
	}, nil
}

// Poll refreshes the table from every configured source.
//
// Every source is polled even after one has failed, and a failure never
// removes what was learned before. That combination is the whole contract:
// a single router rebooting mid-cycle would otherwise empty the device
// table, and every detector downstream treats an unattributable event as
// nothing to see. An inventory that blinks out for one cycle is worse than
// one that is briefly stale, because the failure is invisible — there are no
// alerts, just an absence.
//
// The first error is returned so a caller can log or alert on it, but the
// leases from the sources that did answer have already been merged when it
// comes back.
func (c *Client) Poll(ctx context.Context) error {
	var firstErr error
	collected := make([]Lease, 0, 64)

	for _, src := range c.sources {
		if src == nil {
			continue
		}
		leases, err := src.Leases(ctx)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("router: %s: %w", src.Name(), err)
			}
			continue
		}
		collected = append(collected, leases...)
	}

	// Merged even when every source failed: with nothing to merge this is a
	// no-op, which is precisely the point.
	c.merge(collected)
	return firstErr
}

// merge folds freshly observed leases into the table.
//
// Nothing is ever removed. A lease that expired on the router, or an address
// that moved, simply stops being re-observed; deleting on absence would mean
// one failed poll silently blinded attribution for every device the router
// had ever mentioned. Stale entries cost a misattribution only for addresses
// nobody re-claims, and that self-corrects the moment the rightful owner is
// seen again.
//
// Within one poll the first backend to claim an address wins, so two
// sources disagreeing at the same instant resolve the same way every time
// rather than by iteration order. Across polls the newer observation always
// wins, because a DHCP lease genuinely does move: holding the older binding
// would attribute one device's traffic to another indefinitely, and
// misattribution in a control plane is how the wrong device gets quarantined.
func (c *Client) merge(leases []Lease) {
	if len(leases) == 0 {
		return
	}
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	seen := make(map[netip.Addr]struct{}, len(leases))
	for _, l := range leases {
		// A Source is an interface any caller can implement, so its output
		// is validated here rather than trusted. len(MAC) == 6 is the same
		// rule NormalizeMAC applies; this is the belt to its braces.
		if len(l.MAC) != 6 || !l.IP.IsValid() {
			continue
		}
		ip := l.IP.Unmap()
		if _, dup := seen[ip]; dup {
			continue
		}
		seen[ip] = struct{}{}

		// Copied on ingest. A Source is free to reuse the backing array of
		// the Lease it returns, and sharing it would let that Source rewrite
		// attribution for every event already in flight.
		mac := copyMAC(l.MAC)
		c.macOf[ip] = mac

		key := mac.String()
		d := c.devices[key]
		if d == nil {
			d = &deviceAcc{
				mac:       mac,
				ips:       map[netip.Addr]struct{}{},
				hostnames: map[string]struct{}{},
				firstSeen: now,
			}
			c.devices[key] = d
		}
		d.lastSeen = now
		d.ips[ip] = struct{}{}

		if h := strings.TrimSpace(l.Hostname); h != "" && h != "*" {
			d.hostnames[h] = struct{}{}
		}
		// Last vendor to speak wins within a device. A MAC's OUI is fixed,
		// so a genuine disagreement means one backend guessed badly, and
		// the poll order decides rather than the map's iteration order.
		if v := strings.TrimSpace(l.Vendor); v != "" {
			d.vendor = v
		}
	}
}

// MACFor implements the suricata.Attributor contract: resolve an address to
// the device that owns it.
//
// The semantics and signature match inventory.Inventory.MACFor exactly,
// including the defensive copy. That copy is not ceremony — the table is
// rebuilt on every poll, and a caller that sorted, truncated, or zeroed the
// slice it was handed would corrupt attribution for every other event
// already inside the ingest pipeline.
func (c *Client) MACFor(ip netip.Addr) (net.HardwareAddr, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	mac, ok := c.macOf[ip.Unmap()]
	if !ok {
		return nil, false
	}
	return copyMAC(mac), true
}

// Devices returns every device the routers have told us about, one entry per
// MAC, ordered by MAC so the result is stable across calls.
//
// A router knows addresses, not people. Class is left as core.ClassUnknown
// and risk is untouched, because only the risk engine's view of a device
// carries a classification — assigning one here would let an ungated guess
// weight a risk score. Vendor and the announced hostnames ride along because
// they are what an operator recognizes in the portal: on a network where
// most devices send no hostname, the ones that do are the ones worth naming.
func (c *Client) Devices() []core.Device {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]core.Device, 0, len(c.devices))
	for _, d := range c.devices {
		dev := core.Device{
			MAC:       copyMAC(d.mac),
			Class:     core.ClassUnknown,
			Vendor:    d.vendor,
			FirstSeen: d.firstSeen,
			LastSeen:  d.lastSeen,
		}
		// netip.Addr is a struct rather than an ordered builtin, so the
		// comparison has to be supplied explicitly — and ordering the
		// addresses is what keeps Devices() stable across polls.
		dev.IPs = slices.SortedFunc(maps.Keys(d.ips), netip.Addr.Compare)
		for _, h := range slices.Sorted(maps.Keys(d.hostnames)) {
			dev.Notes = append(dev.Notes, "hostname: "+h)
		}
		out = append(out, dev)
	}
	slices.SortFunc(out, func(a, b core.Device) int {
		return strings.Compare(a.MAC.String(), b.MAC.String())
	})
	return out
}

// Len reports how many distinct devices the routers have identified. It
// counts MACs, not addresses, so a dual-stack device counts once.
func (c *Client) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.devices)
}

// copyMAC duplicates a hardware address. Every value that crosses the
// package boundary is copied rather than shared.
func copyMAC(m net.HardwareAddr) net.HardwareAddr {
	out := make(net.HardwareAddr, len(m))
	copy(out, m)
	return out
}

// NormalizeMAC parses the MAC spellings routers publish into the canonical
// six-byte form everything downstream keys on.
//
// Three spellings occur in practice and all of them must land on the same
// key, or one device appears in the table three times and its own traffic
// is attributed to whichever spelling was seen last:
//
//	"aa:bb:cc:dd:ee:ff"   IEEE, used by VyOS and OPNsense
//	"AA-BB-CC-DD-EE-FF"   Windows registry export
//	"aabbccddeeff"        bare hex, what dnsmasq's lease file writes
//
// An eight-byte EUI-64 address is rejected rather than truncated. Nothing in
// this project keys on one, and truncating would produce a MAC that matches
// no device at all — a silent misattribution, which is strictly worse than
// admitting the row was not understood.
func NormalizeMAC(s string) (net.HardwareAddr, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}

	if !strings.ContainsAny(s, ":-.") {
		// Bare hex, OpenWrt's spelling. Hand-rolled rather than dotted into
		// colon form first, because that would round-trip every byte through
		// string formatting on the hottest parse path in the package.
		if len(s) != 12 {
			return nil, false
		}
		out := make(net.HardwareAddr, 6)
		for i := 0; i < 6; i++ {
			b, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
			if err != nil {
				return nil, false
			}
			out[i] = byte(b)
		}
		return out, true
	}

	// net.ParseMAC already handles the colon and dash forms case-insensitively.
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		return nil, false
	}
	return hw, true
}

// newLease validates one raw vendor row and returns the canonical Lease.
//
// Every backend funnels its rows through here so that normalization and
// rejection live in exactly one place. The bool is false for a row that
// cannot be trusted — an address that does not parse, or a MAC in a shape we
// refuse — and the caller skips that row. One malformed row must never fail
// a whole pull: a single torn line in a lease file would otherwise blind
// attribution for every other device on the network, which costs far more
// than losing the one row we could not read.
func newLease(macRaw, ipRaw, hostname string) (Lease, bool) {
	mac, ok := NormalizeMAC(macRaw)
	if !ok {
		return Lease{}, false
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(ipRaw))
	if err != nil {
		return Lease{}, false
	}
	host := strings.TrimSpace(hostname)
	if host == "*" {
		// dnsmasq's placeholder for "this client sent no hostname", which is
		// most embedded hardware. Carrying it forward would put a literal
		// asterisk in the operator's portal.
		host = ""
	}
	return Lease{MAC: mac, IP: ip.Unmap(), Hostname: host}, true
}

// --- transport helpers -----------------------------------------------------

// doRequest performs one round trip and returns the body, capped at maxBody.
//
// The status check happens before the body is trusted, and it names
// resp.Status rather than the numeric code alone: "401 Unauthorized" tells an
// operator whether to go fix a credential, whereas "401" tells them only
// that something they own returned a number they have already seen.
func doRequest(do Doer, req *http.Request) ([]byte, error) {
	resp, err := do.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errors.New("unexpected status " + statusText(resp))
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	return raw, nil
}

// statusText renders a response status for an error message. A hand-built
// response — from a custom Doer, or a test double — may leave Status empty,
// so the numeric code is the fallback rather than the primary.
func statusText(resp *http.Response) string {
	if resp.Status != "" {
		return resp.Status
	}
	return strconv.Itoa(resp.StatusCode)
}
