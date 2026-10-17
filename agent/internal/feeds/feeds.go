// Package feeds pulls threat-intelligence feeds and parses them into items
// the normalize layer turns into indicators of compromise.
//
// The split is deliberate: a puller knows one provider's wire format and
// nothing about TTLs, confidence policy, or blocking; normalize knows those
// and nothing about HTTP. Tests exercise the parsers against recorded
// provider fixtures, never against the live endpoints, so a provider outage
// or format change fails one clearly-named test instead of the suite.
//
// SAFETY.md section 4 constrains which feeds may be built at all: raw
// upstream feeds over GPL-licensed aggregators, no Feodo Tracker, and no
// feed whose license or commercial terms the project cannot meet.
package feeds

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Kind classifies what an item's value refers to.
type Kind string

const (
	// KindDomain is a DNS name. Policy answers queries for it (and its
	// subdomains) with NXDOMAIN.
	KindDomain Kind = "domain"
	// KindIP is an IP address. It is stored for provenance and future
	// firewall-level policy; DNS-side blocking works on names.
	KindIP Kind = "ip"
	// KindCVE is a vulnerability identifier from CISA's Known Exploited
	// Vulnerabilities catalog. Nothing blocks on it yet; it exists so the
	// inventory can join devices to known-exploited products later.
	KindCVE Kind = "cve"
)

// Item is one indicator exactly as a feed published it, after the feed's own
// wire-format quirks (ip:port suffixes, URL wrappers) have been resolved to a
// canonical value, but before cross-feed normalization.
type Item struct {
	// Value is the canonical indicator: a lowercase domain without a
	// trailing dot, a bare IP address, or an uppercase CVE identifier.
	Value string
	Kind  Kind
	// Feed names the puller that produced the item, for provenance.
	Feed string
	// Confidence is the feed's own 0-100 estimate, or a documented default
	// when the feed publishes none.
	Confidence int
	// Tags are the feed's labels (malware family, vendor, product). They
	// ride along so policy and the portal can say what an indicator is.
	Tags []string
	// FirstSeen is the feed's first-seen timestamp when it publishes one.
	FirstSeen time.Time
}

// Puller fetches and parses one feed. A Pull either returns items or an
// error; a feed that is up but currently has nothing returns an empty slice
// and a nil error, because "no results" is not a failure.
type Puller interface {
	Name() string
	Pull(ctx context.Context) ([]Item, error)
}

// maxBody caps how much of a feed response is read. The largest feed here
// (CISA KEV) is a couple of megabytes; the cap turns a hostile or broken
// endpoint into an error instead of an out-of-memory kill.
const maxBody = 16 << 20

// defaultTimeout bounds one feed round trip. Feed pulls sit on their own
// goroutine, but an endpoint that accepts the connection and never answers
// must not hold the pull cycle open forever.
const defaultTimeout = 30 * time.Second

func newClient() *http.Client {
	return &http.Client{Timeout: defaultTimeout}
}

// get issues a GET with the optional Auth-Key header abuse.ch requires on
// ThreatFox, URLhaus, and SSLBL endpoints.
func get(ctx context.Context, client *http.Client, endpoint, authKey string) ([]byte, error) {
	return fetch(ctx, client, http.MethodGet, endpoint, authKey, nil)
}

// post issues a POST carrying body as JSON with the optional Auth-Key header.
func post(ctx context.Context, client *http.Client, endpoint, authKey string, body []byte) ([]byte, error) {
	return fetch(ctx, client, http.MethodPost, endpoint, authKey, body)
}

func fetch(ctx context.Context, client *http.Client, method, endpoint, authKey string, body []byte) ([]byte, error) {
	if endpoint == "" {
		return nil, errors.New("feeds: no endpoint configured")
	}
	var rd io.Reader
	if body != nil {
		rd = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, rd)
	if err != nil {
		return nil, fmt.Errorf("feeds: building request for %s: %w", endpoint, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authKey != "" {
		req.Header.Set("Auth-Key", authKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, endpoint, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("%s %s: reading response: %w", method, endpoint, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s %s: unexpected status %s", method, endpoint, resp.Status)
	}
	return raw, nil
}

// canonicalDomain lowercases a name and strips the trailing root dot. Empty
// results and values that are not name-shaped are rejected so one malformed
// feed row cannot poison the store with a value no query will ever equal.
func canonicalDomain(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if s == "" || strings.ContainsAny(s, " /\\") || !strings.Contains(s, ".") {
		return "", false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return "", false
	}
	return s, true
}

// canonicalIP parses a bare address, rejecting anything with a port still
// attached: feeds publish "1.2.3.4:443" and the store keys on the address.
func canonicalIP(s string) (string, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return "", false
	}
	return addr.Unmap().String(), true
}

// hostFromURL extracts the hostname from a URL-valued indicator, classifying
// it as an address or a name. URLhaus and ThreatFox both publish full URLs;
// DNS policy can only answer on the host part.
func hostFromURL(raw string) (string, Kind, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return "", "", false
	}
	if ip, ok := canonicalIP(u.Hostname()); ok {
		return ip, KindIP, true
	}
	if name, ok := canonicalDomain(u.Hostname()); ok {
		return name, KindDomain, true
	}
	return "", "", false
}
