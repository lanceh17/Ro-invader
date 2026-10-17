package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// Action is what the resolver does with an accepted query.
type Action int

const (
	// ActionForward relays the query to the upstream resolver unchanged.
	ActionForward Action = iota
	// ActionSinkhole answers with the portal address. This is the walled
	// garden's enforcement and notification in one step.
	ActionSinkhole
	// ActionNXDomain refuses the name as nonexistent.
	ActionNXDomain
	// ActionRefused declines to answer at all, which is what policy dictates
	// for a query that should not be encouraged.
	ActionRefused
)

// String names the action for logs and reason codes.
func (a Action) String() string {
	switch a {
	case ActionForward:
		return "forward"
	case ActionSinkhole:
		return "sinkhole"
	case ActionNXDomain:
		return "nxdomain"
	case ActionRefused:
		return "refused"
	default:
		return "unknown"
	}
}

// Decision is the policy's verdict for one query.
type Decision struct {
	Action Action
	// Reason is rendered into logs and, for a quarantined device, into the
	// remediation page it is being sent to.
	Reason string
}

// forwarder relays a raw query to the upstream resolver and returns its
// response. It is a field rather than a hard-wired call so that tests can
// exercise the whole Handle path without a reachable upstream or an open
// socket.
type forwarder func(query []byte) ([]byte, error)

// Config configures a Server.
type Config struct {
	// ListenAddr is the UDP address to bind, e.g. ":53".
	ListenAddr string
	// Upstream is the resolver to forward to, e.g. "8.8.8.8:53".
	Upstream string
	// Portal is the address quarantined devices are pointed at. It must be
	// this host's remediation page.
	Portal netip.Addr
	// Garden lists the domains a quarantined device may still resolve, which
	// is what makes remediation possible. Without it a contained device could
	// never reach its vendor's firmware server and would be broken
	// permanently.
	Garden []string

	// Quarantined reports whether the device at ip is currently contained.
	// It is injected rather than owned, because containment state lives in
	// the risk engine and the actuator, not here.
	Quarantined func(ip netip.Addr) bool

	// OnQuery, when non-nil, is called for every accepted query. It is the
	// seam through which queries become NormalizedEvents and feed the
	// detection pipeline: the resolver is the identity source, and this is
	// how that identity reaches the detectors.
	OnQuery func(source netip.Addr, name string, action Action)

	// Timeout bounds one upstream round trip. Zero uses the default.
	Timeout time.Duration

	// Ready, when non-nil, is called once the socket is bound, with the
	// actual address. It exists so tests (and a supervisor that wants the
	// real port when ListenAddr used :0) can discover the bound port.
	Ready func(addr net.Addr)
}

// Server is the authoritative resolver. It answers queries and, in doing so,
// both enumerates the network (identity) and contains it (walled garden).
type Server struct {
	cfg     Config
	forward forwarder
}

// New validates cfg and returns a Server.
func New(cfg Config) (*Server, error) {
	if cfg.Upstream == "" {
		return nil, errors.New("dns: Upstream is required")
	}
	if !cfg.Portal.IsValid() {
		return nil, errors.New("dns: Portal is required")
	}
	if cfg.Quarantined == nil {
		// A nil check would otherwise panic mid-query on a live network.
		cfg.Quarantined = func(netip.Addr) bool { return false }
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	s := &Server{cfg: cfg}
	s.forward = s.upstreamForward
	return s, nil
}

// Decide applies the walled-garden policy.
//
// It is exported and pure so that the policy can be tested exhaustively
// without a socket, and so that the remediation portal can ask "why would
// this device be sinkholed?" and get the same answer the resolver would.
//
// The policy is deliberately asymmetric. A quarantined device keeps the names
// that can fix it and loses everything else; an uncontained device keeps
// everything except names the operator has explicitly blocked. Containment is
// the exceptional path, not the default.
func (c Config) Decide(name string, quarantined bool) Decision {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))

	if name == "" {
		// A root or empty query has no name to policy against. Forwarding it
		// is harmless (it is the priming query) and refusing it would break
		// stubs that send it at startup.
		return Decision{Action: ActionForward, Reason: "root query"}
	}

	if !quarantined {
		// Uncontained devices resolve freely. Blocklists are the operator's
		// to configure; none is the safe default.
		return Decision{Action: ActionForward, Reason: "device not contained"}
	}

	// Contained: allow only the names that let the device be fixed.
	if matchesAny(name, c.Garden) {
		return Decision{
			Action: ActionForward,
			Reason: "walled-garden exception (" + name + ")",
		}
	}

	// Everything else resolves to the portal. This is simultaneously the
	// restriction and the notification: the device asked for a name and was
	// answered with the page that explains why.
	return Decision{
		Action: ActionSinkhole,
		Reason: "contained device sinkholed to remediation portal",
	}
}

// matchesAny reports whether name equals or is a subdomain of any suffix.
// Suffix matching is what lets an operator list "vendor.example" and cover
// "patch.vendor.example" without enumerating every host.
func matchesAny(name string, suffixes []string) bool {
	for _, s := range suffixes {
		s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
		if s == "" {
			continue
		}
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	return false
}

// Handle processes one raw query payload from source and returns the response
// bytes to send back, or nil when there is nothing to answer.
//
// It is separated from the socket so that the entire path — parse, attribute,
// decide, respond, forward — is testable with no listener and no upstream.
func (s *Server) Handle(payload []byte, source netip.Addr) []byte {
	q, err := ParseQuery(payload)
	if err != nil {
		// Malformed input is answered, not ignored. A silent drop makes a
		// broken stub retry forever; FORMERR tells it to stop.
		return BuildFormErr(payload)
	}

	question, ok := q.FirstQuestion()
	if !ok {
		// RFC 1035: a message that advertises no question section is
		// malformed, and the answer to a malformed message is FORMERR. There
		// is nothing to build a REFUSED from, since a response echoes the
		// question it is answering.
		return BuildFormErr(payload)
	}

	quarantined := s.cfg.Quarantined(source)
	decision := s.cfg.Decide(question.Name, quarantined)

	if s.cfg.OnQuery != nil {
		s.cfg.OnQuery(source, question.Name, decision.Action)
	}

	switch decision.Action {
	case ActionSinkhole:
		out, err := BuildSinkhole(q, s.cfg.Portal)
		if err != nil {
			return BuildFormErr(payload)
		}
		return out

	case ActionNXDomain:
		out, err := BuildNXDomain(q)
		if err != nil {
			return BuildFormErr(payload)
		}
		return out

	case ActionRefused:
		out, err := BuildRefused(q)
		if err != nil {
			return BuildFormErr(payload)
		}
		return out

	default: // ActionForward
		upstream, err := s.forward(payload)
		if err != nil {
			// The upstream is unreachable. SERVFAIL is the honest answer;
			// pretending the name does not exist would send the stub down a
			// wrong path.
			return buildServFail(q)
		}
		return PatchRelay(upstream, q.ID, q.RD)
	}
}

// buildServFail reports a server failure, which is what a resolver returns
// when it cannot obtain an answer.
func buildServFail(q Msg) []byte {
	out, err := BuildResponse(q, 2 /* SERVFAIL */, nil) //nolint:mnd // RCode 2 is SERVFAIL
	if err != nil {
		return BuildFormErr(nil)
	}
	return out
}

// upstreamForward performs the actual UDP round trip to the upstream resolver.
func (s *Server) upstreamForward(query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", s.cfg.Upstream, s.cfg.Timeout)
	if err != nil {
		return nil, fmt.Errorf("dns: dialing upstream %s: %w", s.cfg.Upstream, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(s.cfg.Timeout)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("dns: writing to upstream: %w", err)
	}

	// A DNS response can be up to 64 KiB over TCP; over UDP the practical
	// maximum with EDNS is 4 KiB, but a generous buffer costs nothing and
	// avoids truncating an unusual-but-valid reply.
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("dns: reading from upstream: %w", err)
	}
	return buf[:n], nil
}

// ListenAndServe runs the resolver until ctx is cancelled.
//
// It binds a UDP socket and answers queries. That is a listening service, not
// an active probe: the resolver never initiates a connection to a managed
// device, which is the boundary SAFETY.md draws. Forwarding to the upstream
// resolver is ordinary recursive resolution, not traffic to a managed device.
func (s *Server) ListenAndServe(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("dns: resolving %s: %w", s.cfg.ListenAddr, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("dns: listening on %s: %w", s.cfg.ListenAddr, err)
	}
	defer conn.Close()

	if s.cfg.Ready != nil {
		s.cfg.Ready(conn.LocalAddr())
	}

	// Close the socket when the context ends, which unblocks the read
	// below. Without this the goroutine would hang forever on a cancelled
	// context.
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	buf := make([]byte, 4096)
	for {
		n, client, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				// Closed by cancellation; a normal shutdown, not an error.
				return nil
			}
			// A transient read error must not kill the resolver for the whole
			// network. Log and continue.
			continue
		}

		// Copy the payload: the buffer is reused on the next read, and the
		// handler holds onto the bytes while forwarding.
		payload := make([]byte, n)
		copy(payload, buf[:n])

		source, _ := netip.AddrFromSlice(client.IP)
		source = source.Unmap()

		resp := s.Handle(payload, source)
		if resp == nil {
			continue
		}
		_, _ = conn.WriteToUDP(resp, client)
	}
}
