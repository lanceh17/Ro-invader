// Package suricata ingests Suricata's EVE JSON output and converts it into
// core.NormalizedEvent values.
//
// Suricata runs as a subprocess, never linked. It is GPL-2.0 and linking it
// would make the whole binary a derivative work; see SAFETY.md. Consuming its
// JSON output over a pipe is both the legal boundary and the correct
// architecture, because it isolates crashes and lets Suricata be upgraded
// without rebuilding this binary.
package suricata

import (
	"encoding/json"
	"net"
	"net/netip"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

// Attributor resolves a LAN-side IP to the device that owns it.
//
// EVE records carry no MAC address, so this is the only path from telemetry
// to a device identity. It is satisfied in practice by the router inventory
// ingester, which learns IP-to-MAC bindings from DHCP leases and ARP tables.
type Attributor interface {
	MACFor(ip netip.Addr) (net.HardwareAddr, bool)
}

// MapAttributor is the trivial implementation: a static IP-to-MAC table.
type MapAttributor map[netip.Addr]net.HardwareAddr

// MACFor implements Attributor.
func (m MapAttributor) MACFor(ip netip.Addr) (net.HardwareAddr, bool) {
	mac, ok := m[ip.Unmap()]
	return mac, ok
}

// Record is a decoded EVE JSON line.
//
// Event-specific payloads are optional pointers. An event type we do not care
// about still decodes into the common fields and produces nothing, which is
// cheaper and more robust than enumerating every type Suricata can emit.
type Record struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`

	SrcIP    string `json:"src_ip"`
	SrcPort  uint16 `json:"src_port"`
	DestIP   string `json:"dest_ip"`
	DestPort uint16 `json:"dest_port"`
	Proto    string `json:"proto"`

	Flow *flowPayload `json:"flow,omitempty"`
	DNS  *dnsPayload  `json:"dns,omitempty"`
	TLS  *tlsPayload  `json:"tls,omitempty"`
	SSH  *sshPayload  `json:"ssh,omitempty"`
	HTTP *httpPayload `json:"http,omitempty"`
}

type flowPayload struct {
	PktsToServer  int64   `json:"pkts_toserver"`
	PktsToClient  int64   `json:"pkts_toclient"`
	BytesToServer int64   `json:"bytes_toserver"`
	BytesToClient int64   `json:"bytes_toclient"`
	Age           float64 `json:"age"`
	Start         string  `json:"start"`
}

type dnsPayload struct {
	// Type is "query" or "answer". Both matter: a query reveals intent
	// before any connection succeeds, which is why DNS is the primary
	// sensor in a passive-only design.
	Type    string      `json:"type"`
	RRName  string      `json:"rrname"`
	RRType  string      `json:"rrtype"`
	Answers []dnsAnswer `json:"answers"`
}

type dnsAnswer struct {
	RRName string `json:"rrname"`
	RRType string `json:"rrtype"`
	TTL    int    `json:"ttl"`
	Addr   string `json:"addr"`
	CName  string `json:"cname"`
}

type tlsPayload struct {
	SNI     string `json:"sni"`
	Version string `json:"version"`
}

type sshPayload struct {
	Auth *sshAuth `json:"auth,omitempty"`
}

type sshAuth struct {
	Success  bool   `json:"success"`
	Username string `json:"username"`
	Method   string `json:"method"`
	// Direction is "to_server" or "to_client". Only server-side
	// authentication is interesting to us.
	Direction string `json:"direction"`
}

type httpPayload struct {
	Hostname string `json:"hostname"`
	URL      string `json:"url"`
	// Length is the response body length in bytes. A large one is the
	// closest EVE gets to a weight-transfer indicator.
	Length int64 `json:"length"`
}

// ParseTimestamp decodes Suricata's timestamp format, which varies by
// configuration: fractional seconds may or may not be present, and the
// timezone may be an offset or the literal "Z".
//
// Suricata's default is a numeric offset with microseconds, e.g.
// "2026-10-17T12:00:00.000000+0000". The zero value is returned rather than
// an error for an unparsable timestamp, so a single malformed record cannot
// stall the ingest loop; the caller treats a zero time as "unknown".
func ParseTimestamp(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	layouts := []string{
		"2006-01-02T15:04:05.000000-0700",
		"2006-01-02T15:04:05.000000Z07:00",
		"2006-01-02T15:04:05.000000",
		"2006-01-02T15:04:05-0700",
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02T15:04:05",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// Normalize converts a decoded EVE record into a NormalizedEvent.
//
// The second return is false when the record cannot produce a useful event:
// an unrecognized type, an unparseable address pair, or a flow whose two ends
// are both on-link or both off-link, which makes attribution ambiguous. A
// false here is normal and expected, not an error condition.
func Normalize(r Record, attr Attributor) (core.NormalizedEvent, bool) {
	src, okSrc := parseEndpoint(r.SrcIP, r.SrcPort)
	dst, okDst := parseEndpoint(r.DestIP, r.DestPort)
	if !okSrc || !okDst {
		return core.NormalizedEvent{}, false
	}

	ts := ParseTimestamp(r.Timestamp)

	e := core.NormalizedEvent{
		Time: ts,
		Src:  src,
		Dst:  dst,
		Raw:  map[string]any{"event_type": r.EventType},
	}

	switch r.EventType {
	case "flow":
		e.Kind = core.EventFlow
		if r.Flow != nil {
			e.Bytes = r.Flow.BytesToServer + r.Flow.BytesToClient
			// Suricata reports flow age in seconds as a float.
			e.Duration = time.Duration(r.Flow.Age * float64(time.Second))
		}

	case "dns":
		if r.DNS == nil {
			return core.NormalizedEvent{}, false
		}
		e.QueryName = r.DNS.RRName
		switch r.DNS.Type {
		case "query":
			e.Kind = core.EventDNSQuery
		case "answer":
			e.Kind = core.EventDNSAnswer
		default:
			return core.NormalizedEvent{}, false
		}

	case "tls":
		e.Kind = core.EventTLS
		if r.TLS != nil {
			e.SNI = r.TLS.SNI
		}

	case "ssh":
		// Only authenticated events carry an auth block; an SSH connection
		// record without one is not an authentication attempt.
		if r.SSH == nil || r.SSH.Auth == nil {
			return core.NormalizedEvent{}, false
		}
		// Inbound SSH attempts have the device as the destination, which is
		// what a credential-reuse fan-out detector needs.
		if r.SSH.Auth.Direction == "to_client" {
			return core.NormalizedEvent{}, false
		}
		e.Kind = core.EventSSHAuth
		e.AuthUser = r.SSH.Auth.Username
		e.Raw["auth_success"] = r.SSH.Auth.Success
		e.Raw["auth_method"] = r.SSH.Auth.Method

	case "http":
		e.Kind = core.EventFlow
		if r.HTTP != nil {
			e.Bytes = r.HTTP.Length
			if e.Dst.Host == "" {
				e.Dst.Host = r.HTTP.Hostname
			}
		}

	default:
		return core.NormalizedEvent{}, false
	}

	// Attribute to a device. Each event type declares which endpoint is the
	// device of interest; for bidirectional aggregates we ask LANSide, which
	// refuses to guess when both ends are on-link or both off-link.
	//
	// A false here means the event cannot be tied to a device we manage, and
	// dropping it is correct: an unattributable event cannot raise a signal,
	// and retaining it would only add noise to the pipeline.
	lan, ok := attribution(r, e)
	if !ok {
		return core.NormalizedEvent{}, false
	}
	// An off-link initiator is not a device on the network we manage.
	if !core.IsLAN(lan.IP) {
		return core.NormalizedEvent{}, false
	}
	// A nil attributor means no inventory is available yet. The event is
	// still valid telemetry; it simply carries no identity, which every
	// detector treats as unattributable. Guarding here keeps a missing
	// inventory from panicking the ingest loop.
	if attr != nil {
		e.DeviceMAC, _ = attr.MACFor(lan.IP)
	}

	return e, true
}

// attribution returns the endpoint an event should be attributed to.
//
// DNS and SSH authentication carry explicit directionality in their payloads,
// which matters because both ends of those flows are routinely on-link (the
// LAN's own resolver, and the device being targeted), leaving LANSide with
// nothing to choose between. For bidirectional aggregates there is no such
// signal, so LANSide decides and reports ambiguity rather than guessing.
func attribution(r Record, e core.NormalizedEvent) (core.Endpoint, bool) {
	switch r.EventType {
	case "dns":
		// The querier is the device of interest. A query is emitted by the
		// client; an answer is emitted by the server, so the client is the
		// destination of the answer.
		if r.DNS != nil && r.DNS.Type == "answer" {
			return e.Dst, true
		}
		return e.Src, true
	case "ssh":
		// Normalize has already rejected anything lacking an auth block or
		// carrying direction "to_client", so a surviving SSH event is an
		// inbound attempt and src is its initiator.
		return e.Src, true
	default:
		// flow, tls, http: bidirectional, no single initiator in the record.
		return core.LANSide(e.Src, e.Dst)
	}
}

func parseEndpoint(ip string, port uint16) (core.Endpoint, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return core.Endpoint{}, false
	}
	return core.Endpoint{IP: addr.Unmap(), Port: port}, true
}

// UnmarshalRecord decodes a single EVE JSON line. It is separate from
// Normalize so that callers can decode, log, and re-emit without losing
// fidelity, which matters when debugging a rule that is not firing.
func UnmarshalRecord(line []byte) (Record, bool) {
	var r Record
	if err := json.Unmarshal(line, &r); err != nil {
		return Record{}, false
	}
	if r.EventType == "" {
		return Record{}, false
	}
	return r, true
}
