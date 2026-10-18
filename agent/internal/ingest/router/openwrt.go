package router

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"
)

// --- OpenWrt: ubus constants -----------------------------------------------

// defaultSession is the all-zero session id ubus accepts before
// authentication. ubus has no unauthenticated call at all, so logging in is
// bootstrapped by presenting this placeholder.
const defaultSession = "00000000000000000000000000000000"

// ubusLoginTimeoutSeconds is the session lifetime requested at login. An hour
// outlasts any realistic poll cycle, so a running agent re-authenticates only
// when it restarts, and it is short enough that a leaked session id expires
// before it is worth using.
const ubusLoginTimeoutSeconds = 3600

// ubusPermissionDenied is UBUS_STATUS_PERMISSION_DENIED.
//
// On this endpoint it means the session aged out far more often than it means
// the operator lacks rights, and the difference decides what to do about it:
// one is recovered by re-authenticating, the other never is. Collapsing the
// two would turn a routine hourly session expiry into a permanent outage of
// attribution.
const ubusPermissionDenied = 6

// dhcpLeasePath is where dnsmasq keeps its IPv4 lease database on OpenWrt.
// It is under /tmp because it is derived state, rebuilt from memory on
// boot; nothing this package does is persisted back to it.
const dhcpLeasePath = "/tmp/dhcp.leases"

// --- OpenWrt: source -------------------------------------------------------

// OpenWrtConfig-free: the vendor constructors take the shared Config, because
// every backend needs the same four things from it — where the router is, who
// we are, and how to talk to it.

var _ Source = (*openWrtSource)(nil)

// openWrtSource reads leases from an OpenWrt router's rpcd JSON-RPC
// endpoint.
//
// Its own ubus client rather than the actuator's: an ingester must not
// import the package that writes firewall rules, so that reading router state
// remains usable on a network where this tool holds no rights to change
// anything. Duplicating ninety lines of transport is a cheap price for that
// separation.
type openWrtSource struct {
	cfg Config
	rpc *ubusClient

	mu   sync.Mutex
	sess string
}

// NewOpenWrt returns a Source backed by an OpenWrt router's ubus API.
func NewOpenWrt(cfg Config) (Source, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("router: BaseURL is required")
	}
	if cfg.Username == "" {
		return nil, errors.New("router: Username is required for the OpenWrt ubus API")
	}
	if cfg.Transport == nil {
		cfg.Transport = newHTTPDoer(cfg.HTTPTimeout)
	}
	return &openWrtSource{
		cfg: cfg,
		rpc: newUbusClient(cfg.BaseURL, cfg.Transport),
	}, nil
}

// Name identifies this backend in logs and in Poll's error wrapping.
func (s *openWrtSource) Name() string { return "openwrt" }

// Leases reads the router's IPv4 and IPv6 lease tables and returns both.
//
// The two calls are independent and one failing does not discard the other:
// rpcd ACLs routinely permit `dhcp ipv6leases` while withholding `file read`,
// and losing the whole source over one of two calls would mean a network
// that has IPv6 disabled also loses its IPv4 inventory — for no reason
// related to the call that failed.
//
// An error is returned only when neither call yielded anything, because a
// caller handed both leases and an error has no way to judge which of the two
// it should trust.
func (s *openWrtSource) Leases(ctx context.Context) ([]Lease, error) {
	v4, v4err := s.ipv4Leases(ctx)
	v6, v6err := s.ipv6Leases(ctx)

	out := make([]Lease, 0, len(v4)+len(v6))
	out = append(out, v4...)
	out = append(out, v6...)
	if len(out) > 0 {
		return out, nil
	}
	if v4err != nil {
		return nil, v4err
	}
	if v6err != nil {
		return nil, v6err
	}
	return out, nil
}

// ipv4Leases reads dnsmasq's lease database.
//
// It deliberately does not call `dhcp ipv4leases`. On stock OpenWrt that
// ubus method reads odhcpd, which is the router advertisement and DHCPv6
// server and is usually not configured to hold IPv4 leases at all: it
// answers with an empty set while dnsmasq, the actual IPv4 server, holds
// every lease on the network. Believing the ubus method would produce a
// perfectly well-formed, permanently empty inventory — the kind of bug that
// presents as "the tool works, there is just nothing on my network".
//
// The file is fetched with ubus `file read` and never `file exec`. `file
// exec` is a general-purpose remote command channel: it would let this
// process run anything at all on the router, which is the single capability
// SAFETY.md rules out unconditionally, and which would turn a passive
// inventory reader into a remote control primitive. Reading one fixed path
// cannot do that.
func (s *openWrtSource) ipv4Leases(ctx context.Context) ([]Lease, error) {
	out, err := s.call(ctx, "file", "read", map[string]any{"path": dhcpLeasePath})
	if err != nil {
		return nil, fmt.Errorf("openwrt: reading %s: %w", dhcpLeasePath, err)
	}

	var payload struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		return nil, fmt.Errorf("openwrt: decoding %s: %w", dhcpLeasePath, err)
	}
	return parseOpenWrtLeases([]byte(payload.Data))
}

// ipv6Leases reads odhcpd's DHCPv6 lease table through ubus, which — unlike
// the IPv4 case — is exactly the right call: odhcpd is the server that holds
// these leases.
func (s *openWrtSource) ipv6Leases(ctx context.Context) ([]Lease, error) {
	out, err := s.call(ctx, "dhcp", "ipv6leases", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("openwrt: dhcp ipv6leases: %w", err)
	}
	return parseOpenWrtIPv6Leases(out)
}

// --- OpenWrt: session plumbing ---------------------------------------------

// session returns a usable ubus session id, logging in if there is not one
// already.
//
// The mutex makes the acquisition path safe against concurrent pollers
// racing to log in, which matters because a burst of them would otherwise
// each mint their own session and leave the earlier ones alive until timeout
// on a device with a small process table.
func (s *openWrtSource) session(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sess != "" {
		return s.sess, nil
	}

	out, err := s.rpc.call(ctx, defaultSession, "session", "login", map[string]any{
		"username": s.cfg.Username,
		"password": s.cfg.Password,
		"timeout":  ubusLoginTimeoutSeconds,
	})
	if err != nil {
		return "", fmt.Errorf("openwrt: login: %w; check Username and Password", err)
	}

	var payload struct {
		Session string `json:"ubus_rpc_session"`
	}
	if err := json.Unmarshal(out, &payload); err != nil || payload.Session == "" {
		return "", errors.New("openwrt: login returned no ubus_rpc_session; check Username and Password")
	}
	s.sess = payload.Session
	return s.sess, nil
}

// call performs one authenticated ubus call, re-authenticating once if the
// session has expired.
//
// The retry is bounded to a single attempt deliberately. ubus reports status
// 6 for both an aged-out session and genuinely insufficient rights;
// re-authenticating fixes the first and not the second, so an unbounded
// retry against the second becomes a login loop hammering the router for as
// long as the misconfiguration lasts.
func (s *openWrtSource) call(ctx context.Context, obj, method string, args map[string]any) (json.RawMessage, error) {
	sess, err := s.session(ctx)
	if err != nil {
		return nil, err
	}

	out, err := s.rpc.call(ctx, sess, obj, method, args)

	var st *ubusStatusError
	if errors.As(err, &st) && st.Code == ubusPermissionDenied {
		s.mu.Lock()
		s.sess = ""
		s.mu.Unlock()

		// Re-login can itself fail — an expired session is not the only
		// reason to be here — so its error is surfaced rather than swallowed
		// in favour of the original, which would name the wrong cause.
		fresh, lerr := s.session(ctx)
		if lerr != nil {
			return nil, lerr
		}
		return s.rpc.call(ctx, fresh, obj, method, args)
	}
	return out, err
}

// ubusStatusError is a non-zero ubus status.
//
// It is a distinct type because a ubus-level rejection and a transport
// failure call for opposite responses: "no such object" will never succeed on
// retry and should be reported as a misconfiguration, while a refused
// connection probably will succeed thirty seconds later and should not raise
// an alert at all.
type ubusStatusError struct {
	Obj, Method string
	Code        int
}

func (e *ubusStatusError) Error() string {
	return fmt.Sprintf("ubus %s.%s returned status %d", e.Obj, e.Method, e.Code)
}

// --- OpenWrt: ubus client --------------------------------------------------

// ubusClient speaks the JSON-RPC 2.0 dialect rpcd exposes on uhttpd's /ubus
// endpoint.
type ubusClient struct {
	base string
	do   Doer
	id   int
	mu   sync.Mutex
}

func newUbusClient(base string, do Doer) *ubusClient {
	return &ubusClient{base: strings.TrimRight(base, "/"), do: do}
}

type ubusRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type ubusResponse struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	// Result is always the [status, payload] array, even when the status is
	// non-zero. rpcd does not use the JSON-RPC "error" member for ubus-level
	// failures, so a parser that reads only "error" would report success on
	// a call that was refused.
	Result []json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// call performs one ubus call and returns the payload, which is element 1 of
// the [status, payload] envelope.
func (u *ubusClient) call(ctx context.Context, session, obj, method string, args map[string]any) (json.RawMessage, error) {
	if args == nil {
		args = map[string]any{}
	}

	u.mu.Lock()
	u.id++
	id := u.id
	u.mu.Unlock()

	body, err := json.Marshal(ubusRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  "call",
		Params:  []any{session, obj, method, args},
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.base+"/ubus", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	raw, err := doRequest(u.do, req)
	if err != nil {
		return nil, fmt.Errorf("ubus %s.%s: %w", obj, method, err)
	}

	var env ubusResponse
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("ubus %s.%s: decoding response: %w", obj, method, err)
	}
	if env.Error != nil {
		return nil, fmt.Errorf("ubus %s.%s: %s", obj, method, env.Error.Message)
	}
	if len(env.Result) == 0 {
		return nil, fmt.Errorf("ubus %s.%s: malformed envelope: no result array", obj, method)
	}

	// Status first, always. The array form is used for errors too, so a
	// caller that only looked at the payload would happily decode a failure
	// as an empty — but successful — lease table.
	var code int
	if err := json.Unmarshal(env.Result[0], &code); err != nil {
		return nil, fmt.Errorf("ubus %s.%s: malformed status element", obj, method)
	}
	if code != 0 {
		return nil, &ubusStatusError{Obj: obj, Method: method, Code: code}
	}
	if len(env.Result) < 2 {
		return nil, fmt.Errorf("ubus %s.%s: envelope carries no payload", obj, method)
	}
	return env.Result[1], nil
}

// --- OpenWrt: parsers ------------------------------------------------------

// parseOpenWrtLeases parses a dnsmasq lease database: one binding per line,
// as "<expiry-epoch> <mac> <ip> <hostname> <client-id>", with "#" comment
// lines and with hostname and client-id written as "*" when the client
// announced neither.
//
// The mac field is bare hex with no separators, which is why every row goes
// through NormalizeMAC rather than net.ParseMAC directly — one normalization
// rule for all three vendor spellings, in one place.
//
// A row that does not parse is skipped rather than fatal. The lease file is
// a plain text database that dnsmasq rewrites in place on a device with no
// transactional write and no crash-consistency guarantees, so a torn or
// hand-edited line is an ordinary occurrence. Refusing the whole file over
// one of them would cost every other lease on the network — the single worst
// outcome available to this function.
//
// The error return covers one case only: a payload that is not valid UTF-8.
// That means we did not read a lease file at all — a wrong BaseURL, a
// truncated transfer, an HTML page — and treating its bytes as lease rows
// would invent devices that are not on the network.
func parseOpenWrtLeases(raw []byte) ([]Lease, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("openwrt: lease file is not valid UTF-8, so it is not a lease file")
	}

	var out []Lease
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		f := strings.Fields(line)
		// Expiry, MAC and IP are the fields that matter. Hostname and
		// client-id are absent on some dnsmasq builds, so they are read
		// defensively rather than indexed directly.
		if len(f) < 3 {
			continue
		}
		host := ""
		if len(f) > 3 {
			host = f[3]
		}

		l, ok := newLease(f[1], f[2], host)
		if !ok {
			continue
		}
		out = append(out, l)
	}
	return out, nil
}

// openWrtIPv6 is the dhcp ipv6leases payload, nested by interface.
type openWrtIPv6 struct {
	Device map[string]struct {
		Leases []openWrtIPv6Lease `json:"leases"`
	} `json:"device"`
}

type openWrtIPv6Lease struct {
	MAC      string `json:"mac"`
	Hostname string `json:"hostname"`
	Addrs    []struct {
		Address string `json:"address"`
	} `json:"ipv6-addr"`
}

// parseOpenWrtIPv6Leases flattens odhcpd's per-interface, per-lease,
// per-address tree into one flat lease list.
//
// Every address in every lease is taken, not just the first. A dual-stack
// device routinely holds several SLAAC and DHCPv6 addresses at once, and
// dropping the rest would leave exactly the addresses Suricata actually sees
// traffic from un-attributable — the failure this whole package exists to
// prevent.
func parseOpenWrtIPv6Leases(raw []byte) ([]Lease, error) {
	var payload openWrtIPv6
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("openwrt: parsing dhcp ipv6leases: %w", err)
	}

	var out []Lease
	// Sorted rather than ranged over directly: map iteration is randomized,
	// and a Source that returns its leases in a different order on every
	// poll makes every downstream test flaky for no reason.
	for _, iface := range slices.Sorted(maps.Keys(payload.Device)) {
		for _, lease := range payload.Device[iface].Leases {
			for _, addr := range lease.Addrs {
				// odhcpd publishes a bare address here, but a prefix
				// length or a zone suffix would make the whole lease
				// unreadable, so anything after the address is dropped.
				text := addr.Address
				if i := strings.IndexAny(text, "/%"); i >= 0 {
					text = text[:i]
				}
				l, ok := newLease(lease.MAC, text, lease.Hostname)
				if !ok {
					continue
				}
				out = append(out, l)
			}
		}
	}
	return out, nil
}
