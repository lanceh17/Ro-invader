package router

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// VyOS's operational-mode /show HTTP endpoint arrived in 1.4. VyOS 1.3 has no
// API of any kind — not a hidden one, not an undocumented one — so a 1.3
// router is unsupported rather than merely unreachable, and this backend
// reports that by failing its calls instead of pretending to work. 1.5 kept
// the endpoint and extended the paths used here, so both 1.4 and 1.5 are
// expected to answer.
//
// The endpoint is authenticated with an API key generated in
// operational mode (`set service api ...`) and passed as a form field. The
// key is a credential, so it is named through an environment variable in
// every error that mentions it: an operator who sees the variable name in the
// failure has somewhere to go, and one who sees only "Token is required" has
// to go looking through this package first.

const vyosAPIKeyEnv = "R0_VYOS_APIKEY"

var _ Source = (*vyosSource)(nil)

// vyosSource reads DHCP leases and the ARP table from a VyOS router.
type vyosSource struct {
	cfg Config
}

// NewVyOS returns a Source backed by a VyOS router's /show endpoint.
func NewVyOS(cfg Config) (Source, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("router: BaseURL is required")
	}
	if cfg.Token == "" {
		return nil, errors.New("router: Token is required for the VyOS API; set " + vyosAPIKeyEnv)
	}
	if cfg.Transport == nil {
		cfg.Transport = newHTTPDoer(cfg.HTTPTimeout)
	}
	return &vyosSource{cfg: cfg}, nil
}

func (s *vyosSource) Name() string { return "vyos" }

// Leases reads both the DHCP lease table and the ARP table.
//
// Both are attempted independently and a failure in one does not discard the
// other. A router can be configured with static addressing on one LAN and
// DHCP on another, in which case the half that is empty is not the half the
// operator cares about.
func (s *vyosSource) Leases(ctx context.Context) ([]Lease, error) {
	leaseText, leaseErr := s.show(ctx, "dhcp", "server", "leases")
	arpText, arpErr := s.show(ctx, "arp")

	var leases, arp []Lease
	if len(leaseText) > 0 {
		leases = parseVyOSLeases(leaseText)
	}
	if len(arpText) > 0 {
		arp = parseVyOSARP(arpText)
	}

	out := make([]Lease, 0, len(leases)+len(arp))
	out = append(out, leases...)
	out = append(out, arp...)
	if len(out) > 0 {
		return out, nil
	}
	if leaseErr != nil {
		return nil, leaseErr
	}
	if arpErr != nil {
		return nil, arpErr
	}
	return out, nil
}

// vyosRequest is the JSON document VyOS expects inside the form's data field.
type vyosRequest struct {
	Op   string   `json:"op"`
	Path []string `json:"path"`
}

// vyosEnvelope is the /show response.
//
// Error is kept as raw JSON rather than typed, because VyOS does not keep the
// error shape stable across 1.4 and 1.5: some builds return a bare string,
// others an object carrying a message. Assuming either shape means printing
// the useless literal "<nil>" for the other, and the error body is the one
// part of the response an operator actually needs to read.
type vyosEnvelope struct {
	Success bool            `json:"success"`
	Data    string          `json:"data"`
	Error   json.RawMessage `json:"error"`
}

// show issues one operational-mode command and returns its plain-text output.
func (s *vyosSource) show(ctx context.Context, path ...string) (string, error) {
	op := strings.Join(path, " ")

	data, err := json.Marshal(vyosRequest{Op: "show", Path: path})
	if err != nil {
		return "", fmt.Errorf("vyos: encoding %s: %w", op, err)
	}

	// Form-encoded, not JSON: /show takes the API key in a form field named
	// "key" and the command document in a form field named "data".
	form := url.Values{"key": {s.cfg.Token}, "data": {string(data)}}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.BaseURL+"/show", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	raw, err := doRequest(s.cfg.Transport, req)
	if err != nil {
		return "", fmt.Errorf("vyos: show %s: %w", op, err)
	}
	return parseVyOSEnvelope(raw)
}

// parseVyOSEnvelope unwraps the /show response and returns its text payload.
//
// VyOS serves this JSON as text/html — an accurate description of the
// endpoint's history and a standing trap for anyone who dispatches on
// Content-Type. The body is parsed as JSON unconditionally and the header is
// never consulted; a client that trusted the header would reject every
// successful response from the endpoint it exists to read.
func parseVyOSEnvelope(raw []byte) (string, error) {
	var env vyosEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", fmt.Errorf("vyos: decoding response: %w", err)
	}
	if env.Success {
		return env.Data, nil
	}

	msg := strings.TrimSpace(string(env.Error))
	if msg == "" || msg == "null" {
		msg = "request rejected by the router with no error detail"
	}
	return "", fmt.Errorf("vyos: show failed: %s", msg)
}

// --- VyOS: plain-text table parsing ----------------------------------------

// splitColumns splits one row of a VyOS table.
//
// VyOS aligns columns with padding spaces rather than delimiting them, so
// collapsing runs of whitespace is the only way to read the output. Anything
// that depended on exact column widths would break the first time a value
// grew a character, which on a lease table is every time a hostname is set.
func splitColumns(line string) []string {
	return strings.Fields(line)
}

// isRuleRow reports whether a line carries no data: a blank line, or the
// "----  ----" underline VyOS prints beneath a header.
//
// It earns its own predicate because the underline is the one line in these
// tables that looks like data and is not — every field of it fails to parse
// as an address. Naming the case makes the skip in each row loop read as a
// decision rather than as a side effect of the address check happening to
// catch it.
func isRuleRow(line string) bool {
	return strings.Trim(strings.TrimSpace(line), "- \t") == ""
}

// vyosLeaseFixedFields is how many whitespace-separated fields precede the
// hostname column of `show dhcp server leases`.
//
// It is nine, not eight, because two of the eight visible columns are
// timestamps printed as "2023/05/11 13:08:50" and therefore occupy two
// fields each:
//
//	192.168.0.30  00:50:79:66:68:05  active  2023/05/11 13:08:50  2023/05/12 13:08:50  23:59:16  DHCPTun100  VPCS
//	[0]           [1]                [2]     [3] [4]           [5] [6]           [7]        [8]         [9:]
//
// Parsing from the left at fixed offsets is safe precisely because the table
// is whitespace-aligned: such a table cannot represent an empty column in
// the middle, so no value can ever shift left into a neighbour's slot.
const vyosLeaseFixedFields = 9

// parseVyOSLeases reads the DHCP lease table.
//
// It returns no error. Every way this can go wrong — a header row, the dash
// underline, a row whose address will not parse, a router with no leases at
// all — is an empty result rather than a failure, and a plain-text table has
// no envelope whose malformation is worth distinguishing from "nothing to
// report".
func parseVyOSLeases(text string) []Lease {
	var out []Lease
	for _, line := range strings.Split(text, "\n") {
		if isRuleRow(line) {
			continue
		}
		f := splitColumns(line)
		if len(f) < vyosLeaseFixedFields {
			continue
		}

		// The hostname is the last column and is empty for most devices on a
		// home network, so it is whatever remains after the fixed fields
		// rather than a field at a fixed index. Reading it positionally
		// would put the DHCP pool name in front of devices that sent no name
		// at all, which is worse than leaving it blank.
		l, ok := newLease(f[1], f[0], strings.Join(f[vyosLeaseFixedFields:], " "))
		if !ok {
			continue
		}
		out = append(out, l)
	}
	return out
}

// vyosARPFields is the column count of `show arp`: address, interface, link
// layer address, state. Unlike the lease table, none of these values contains
// a space, so a fixed left-to-right split is exact.
const vyosARPFields = 4

// parseVyOSARP reads the neighbour table.
//
// An unresolved entry is reported with "(incomplete)" in place of the link
// layer address; that fails MAC parsing and is skipped, which is correct —
// there is no identity to record until the router has resolved one.
func parseVyOSARP(text string) []Lease {
	var out []Lease
	for _, line := range strings.Split(text, "\n") {
		if isRuleRow(line) {
			continue
		}
		f := splitColumns(line)
		if len(f) < vyosARPFields {
			continue
		}
		l, ok := newLease(f[2], f[0], "")
		if !ok {
			continue
		}
		out = append(out, l)
	}
	return out
}
