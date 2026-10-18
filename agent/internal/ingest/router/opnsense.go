package router

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// OPNsense's API credentials are a key/secret pair, generated under
// System > Access > Users > API keys. Both halves are named through
// environment variables in the errors that mention them: the operator who
// sees the variable name has somewhere to go, and the one who sees only a
// field name has to read this package to find out which half is missing.
const (
	opnSenseKeyEnv    = "R0_OPNSENSE_APIKEY"
	opnSenseSecretEnv = "R0_OPNSENSE_APISECRET"
)

// The two rowset endpoints this backend reads. Both are the paged-table
// widget OPNsense's own UI uses, which is the documented way to enumerate a
// list rather than the individual-object API — the latter needs one call per
// device, which on a large network is thousands of round trips per poll.
const (
	opnSenseLeaseEndpoint = "/api/dhcpv4/leases/search_lease"
	opnSenseARPEndpoint   = "/api/diagnostics/interface/search_arp"
)

var _ Source = (*opnSenseSource)(nil)

// opnSenseSource reads DHCPv4 leases and the ARP table from an OPNsense
// firewall.
type opnSenseSource struct {
	cfg Config
}

// NewOPNsense returns a Source backed by an OPNsense firewall's API.
func NewOPNsense(cfg Config) (Source, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("router: BaseURL is required")
	}
	if cfg.Token == "" {
		return nil, errors.New("router: Token is required for the OPNsense API; set " + opnSenseKeyEnv)
	}
	if cfg.Password == "" {
		// Password carries the API secret here: it is the second half of the
		// key/secret pair OPNsense authenticates with, and the message says so
		// so the operator is not left hunting for a password field.
		return nil, errors.New("router: Password is required for the OPNsense API (it carries the API secret); set " + opnSenseSecretEnv)
	}
	if cfg.Transport == nil {
		cfg.Transport = newHTTPDoer(cfg.HTTPTimeout)
	}
	return &opnSenseSource{cfg: cfg}, nil
}

func (s *opnSenseSource) Name() string { return "opnsense" }

// Leases reads the DHCPv4 lease table and the ARP table, merging both into
// one list.
//
// Both are fetched independently and one failing does not discard the other:
// on an OPNsense box the two are enabled independently, and a firewall with
// DHCP server off still has a full neighbour table worth reading.
func (s *opnSenseSource) Leases(ctx context.Context) ([]Lease, error) {
	leaseRaw, leaseErr := s.fetch(ctx, opnSenseLeaseEndpoint, opnSenseQuery("address"))
	arpRaw, arpErr := s.fetch(ctx, opnSenseARPEndpoint, opnSenseQuery(""))

	var leases, arp []Lease
	if len(leaseRaw) > 0 {
		var err error
		if leases, err = parseOPNsenseLeases(leaseRaw); err != nil {
			leaseErr = err
			leases = nil
		}
	}
	if len(arpRaw) > 0 {
		var err error
		if arp, err = parseOPNsenseARP(arpRaw); err != nil {
			arpErr = err
			arp = nil
		}
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

// opnSenseQuery builds the paged-rowset query.
//
// rowCount=-1 is OPNsense's "no limit" sentinel and is the whole reason this
// endpoint is used: walking pages instead would silently drop the tail of a
// large network's table, and the devices that get dropped are the ones added
// most recently — the newly deployed cameras, which are exactly the devices
// worth watching.
//
// A sort column is supplied only where one is known to exist. OPNsense
// rejects a sort on a column the table does not have, so the ARP table —
// which names its address column differently — is asked for unsorted.
func opnSenseQuery(sortColumn string) url.Values {
	q := url.Values{
		"current":      {"1"},
		"rowCount":     {"-1"},
		"searchPhrase": {""},
	}
	if sortColumn != "" {
		q.Set("sort[column]", sortColumn)
		q.Set("sort[direction]", "asc")
	}
	return q
}

// fetch performs one authenticated GET and returns the raw body.
func (s *opnSenseSource) fetch(ctx context.Context, endpoint string, q url.Values) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.BaseURL+endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	// HTTP basic auth, carrying the API key as the user and the API secret as
	// the password — that is the shape OPNsense's key/secret pair uses, not
	// a login account's password.
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(s.cfg.Token+":"+s.cfg.Password)))
	// Without this, OPNsense renders its login page instead of JSON and the
	// response parses as garbage — a failure that looks like a format change
	// rather than a missing header.
	req.Header.Set("Accept", "application/json")

	raw, err := doRequest(s.cfg.Transport, req)
	if err != nil {
		return nil, fmt.Errorf("opnsense: GET %s: %w", endpoint, err)
	}
	return raw, nil
}

// --- OPNsense: wire shapes -------------------------------------------------

// opnSenseRowset is the envelope both paged endpoints return.
type opnSenseRowset struct {
	Total    int               `json:"total"`
	RowCount int               `json:"rowCount"`
	Current  int               `json:"current"`
	Rows     []json.RawMessage `json:"rows"`
}

// opnSenseLease is one DHCPv4 lease row.
//
// Starts and Ends are "Y/m/d H:i:s" strings, not epoch integers. Reading
// them as numbers does not fail — it yields a plausible-looking date in 1970
// — so they are typed as strings here and then ignored. This package answers
// "who is at this address", not "for how long": a lease's own lifetime is
// the router's business, and tracking it would only create a second, worse
// source of truth about when a device left.
type opnSenseLease struct {
	Address  string `json:"address"`
	MAC      string `json:"mac"`
	Hostname string `json:"hostname"`
	State    string `json:"state"`
	Status   string `json:"status"`
	Type     string `json:"type"`
	Man      string `json:"man"`
	Starts   string `json:"starts"`
	Ends     string `json:"ends"`
}

// opnSenseARP is one neighbour-table row.
//
// Expired is the field that decides whether a row means anything: a stale
// entry names an address that has since been handed to somebody else. The
// remaining fields are decoded but unused — they are here so the shape this
// package is written against is visible in one place, and a future field
// addition is a visible diff rather than a silent no-op.
type opnSenseARP struct {
	IP            string `json:"ip"`
	MAC           string `json:"mac"`
	Interface     string `json:"intf"`
	InterfaceDesc string `json:"intf_description"`
	Expired       bool   `json:"expired"`
	Expires       string `json:"expires"`
	Permanent     bool   `json:"permanent"`
	Type          string `json:"type"`
	Manufacturer  string `json:"manufacturer"`
	Hostname      string `json:"hostname"`
}

// --- OPNsense: parsers -----------------------------------------------------

// parseOPNsenseLeases reads a lease rowset.
//
// Rows are decoded individually rather than as a typed array so that one row
// OPNsense has extended with a field of an incompatible type cannot cost the
// other rows. A malformed row is dropped; a malformed envelope is an error,
// because that means the response is not a rowset at all.
func parseOPNsenseLeases(raw []byte) ([]Lease, error) {
	var rs opnSenseRowset
	if err := json.Unmarshal(raw, &rs); err != nil {
		return nil, fmt.Errorf("opnsense: parsing lease rowset: %w", err)
	}

	out := make([]Lease, 0, len(rs.Rows))
	for _, row := range rs.Rows {
		var w opnSenseLease
		if err := json.Unmarshal(row, &w); err != nil {
			continue
		}
		// A lease with no MAC is a reservation or a stale row with the
		// hardware address cleared. There is no identity to record, and
		// inventing one from the address would attribute that address's
		// traffic to a device nobody has ever seen.
		l, ok := newLease(w.MAC, w.Address, w.Hostname)
		if !ok {
			continue
		}
		out = append(out, l)
	}
	return out, nil
}

// parseOPNsenseARP reads a neighbour rowset.
func parseOPNsenseARP(raw []byte) ([]Lease, error) {
	var rs opnSenseRowset
	if err := json.Unmarshal(raw, &rs); err != nil {
		return nil, fmt.Errorf("opnsense: parsing arp rowset: %w", err)
	}

	out := make([]Lease, 0, len(rs.Rows))
	for _, row := range rs.Rows {
		var w opnSenseARP
		if err := json.Unmarshal(row, &w); err != nil {
			continue
		}
		// An expired entry names an address that has since been reassigned.
		// Attributing it would blame whatever device holds the address now
		// for traffic its predecessor generated — which in this system means
		// quarantining the wrong device on the strength of stale bookkeeping.
		if w.Expired {
			continue
		}
		l, ok := newLease(w.MAC, w.IP, w.Hostname)
		if !ok {
			continue
		}
		// OPNsense resolves the OUI itself, so the manufacturer comes from a
		// real MAC database rather than a guess at the first three bytes.
		l.Vendor = strings.TrimSpace(w.Manufacturer)
		out = append(out, l)
	}
	return out, nil
}
