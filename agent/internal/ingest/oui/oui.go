// Package oui resolves a MAC address to the organization IEEE registered its
// first three bytes to.
//
// This is the last step in naming a device. The inventory file and the
// router's lease tables answer "which device is at this address"; only this
// answers "what made it", and without that an operator reads a quarantine
// notice that names an address instead of a manufacturer.
// router.Lease.Vendor already carries an OUI-derived hint where the backend
// publishes one -- OPNsense resolves it from its own MAC database -- but
// OpenWrt and VyOS publish no manufacturer field at all, so on those backends
// the name is simply absent today.
//
// The registry is fetched at runtime and is never vendored into this
// repository. SAFETY.md section 4 records the licensing position: the IEEE
// database is published data, distinct from the GPL tools that redistribute
// it, so consuming it creates no derivative. Fetching rather than shipping
// also keeps a 6.3 MB data file out of the tree and means an operator gets
// the registry as it stands today rather than as it stood when this was
// built.
//
// Only MA-L assignments are supported, and the reason is the registry's shape
// rather than a simplification. Verified against the live listing on
// 2026-10-18: the MA-L file holds 40,347 assignment records, every prefix six
// hex digits wide, while MA-M (28-bit) and MA-S (36-bit) assignments live in
// separate files at /oui28/mam.txt and /oui36/oui36.txt. Answering from all
// three would mean a MAC's vendor could be claimed by two overlapping key
// spaces -- a 24-bit MA-L assignment contains every 28-bit MA-M assignment
// inside it -- so it would need longest-prefix resolution to keep the more
// specific answer, at the cost of three downloads instead of one. Since a
// wrong vendor label is worse than none (router.Lease.Vendor says exactly
// that), a prefix this package cannot resolve returns false rather than a
// guess, and rows this package does not understand are skipped rather than
// misfiled.
//
// Nothing here is wired into the r0-guard binary yet; see the seam note on
// Lookup for where it would attach and why that call belongs to whoever owns
// the daemon's outbound-request posture rather than to this package.
package oui

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// DefaultEndpoint is the IEEE Registration Authority's MA-L public listing.
//
// The host is standards-oui.ieee.org, which is not the standards-ieee.org host
// the older wp-content upload path lived on; that name no longer resolves in
// DNS, so a URL carrying it fails before any HTTP is attempted and presents as
// a network fault rather than as a stale address.
//
// Verified 2026-10-18 against the live endpoint:
//
//	Content-Type:     text/plain; charset=UTF-8
//	Content-Length:   6625656
//	Accept-Ranges:    bytes
//
// The listing is served as plain text rather than gzipped, and is around 6.3 MB
// uncompressed. There is no gzip code here because none is needed: Go's HTTP
// transport requests gzip on its own and transparently inflates the response,
// so an endpoint that started compressing would keep working untouched.
const DefaultEndpoint = "https://standards-oui.ieee.org/oui/oui.txt"

// prefixLen is the width of an MA-L assignment: three octets, or six hex
// digits, of the low-order bits IEEE assigns to an organization.
const prefixLen = 3

// hexTag marks the line that carries an assignment in IEEE's listing.
//
// Each record is written twice, once per notation, and only one of the two is
// an assignment:
//
//	28-6F-B9   (hex)		Nokia Shanghai Bell Co., Ltd.
//	286FB9     (base 16)		Nokia Shanghai Bell Co., Ltd.
//				No.388 Ning Qiao Road,Jin Qiao Pudong Shanghai
//				Shanghai     201206
//				CN
//
// Keying on this marker rather than on "starts with six hex digits" is what
// keeps the base-16 line, which spells the same prefix without dashes, from
// being read as a second assignment under the same key. Everything else in a
// record -- the header, the address lines, the country line, the blank
// separators -- is legitimately not an assignment and is skipped.
var hexTag = []byte("(hex)")

// maxBody caps how much of the registry response is read.
//
// The listing is 6.3 MB today and grows by roughly ten kilobytes a day, so a
// cap that rejected the real file would also reject every future one. 16 MB is
// the same ceiling the feed pullers use and leaves years of headroom over a
// 6.3 MB file, while still turning a hostile or broken endpoint into an error
// instead of an out-of-memory kill of a process whose whole job is to stay up
// and keep watching.
const maxBody = 16 << 20

// defaultHTTPTimeout bounds one registry download.
//
// Longer than the router client's ten seconds, and deliberately so: a router
// is on the LAN and answers in milliseconds, whereas this is a multi-megabyte
// fetch from a public site whose queueing this tool has no control over. The
// cost of a generous timeout is a slow failure; the cost of a tight one is a
// load that never completes on a slow link, and therefore a table that never
// populates.
const defaultHTTPTimeout = 30 * time.Second

// Flag bits in the first octet of a MAC, from IEEE Std 802.
//
// Both are checked before any lookup, because a match would otherwise be a
// fabrication:
//
//   - multicast: a group address names a set of listeners, not a device.
//   - locally administered: the manufacturer bit the device's own maker set,
//     not an organization IEEE assigned. The low three bytes of such an
//     address are arbitrary, so any prefix they happen to match is a
//     coincidence. This is what a randomized Wi-Fi address looks like, and
//     labelling one "Apple" because the bytes lined up is exactly the kind of
//     confident wrong answer this project exists to avoid.
const (
	multicast           byte = 0x01
	locallyAdministered byte = 0x02
)

// Config configures a Store.
//
// Endpoint exists so tests can point the loader at a fixture server, and so an
// operator who mirrors the registry somewhere reachable can use their copy
// instead of the public site. It is the one field most likely to be overridden
// and the only one that changes where the bytes come from.
type Config struct {
	// Endpoint is the registry listing to fetch. Empty uses DefaultEndpoint.
	Endpoint string
	// HTTPTimeout bounds the download. Zero uses a 30 second default.
	HTTPTimeout time.Duration
}

// Store holds one snapshot of the registry and answers vendor lookups from it.
//
// It is safe for concurrent use. Lookups take the read lock, and a load
// publishes a finished table under the write lock, so a lookup running while
// the registry is being replaced sees either the whole old table or the whole
// new one, never a half-built map. The replacement is built entirely outside
// the lock, so the write lock is held for one map assignment rather than for
// the length of the parse.
//
// The lock is what makes that ordering safe rather than merely lucky. A caller
// that fetches on a background goroutine while the ingest path is resolving
// devices is exactly how every other table in this daemon works -- feedLoop
// and routerLoop both rebuild behind the hot path -- and without the lock that
// is a concurrent map read and write, which takes the whole process down
// rather than returning a wrong answer.
type Store struct {
	cfg     Config
	client  *http.Client
	mu      sync.RWMutex
	vendors map[[prefixLen]byte]string
}

// New validates cfg and returns an empty Store.
//
// The returned table is empty rather than populated, so a run that never loads
// still comes up and answers every lookup with false. That is the honest
// answer for a table holding no data, and it is the shape
// normalize.NewStore returns: one code path serves both cases.
func New(cfg Config) (*Store, error) {
	if cfg.Endpoint == "" {
		cfg.Endpoint = DefaultEndpoint
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = defaultHTTPTimeout
	}
	// Validated here rather than at first load, so a mistyped endpoint is
	// reported at startup where the operator can still read it. url.Parse
	// accepts a great deal that is not a fetchable URL, so the scheme is
	// checked as well: without it "example.com/oui.txt" parses cleanly and
	// then fails inside the HTTP client with a complaint about an unsupported
	// protocol scheme, which says nothing about the field that was wrong.
	u, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("oui: Endpoint %q: %w", cfg.Endpoint, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("oui: Endpoint %q must be an http or https URL, got scheme %q", cfg.Endpoint, u.Scheme)
	}

	return &Store{
		cfg:     cfg,
		client:  &http.Client{Timeout: cfg.HTTPTimeout},
		vendors: map[[prefixLen]byte]string{},
	}, nil
}

// Load fetches the registry and replaces the table with what it holds.
//
// A failed load leaves the previous table in place. Deleting on failure is the
// wrong direction for a table this one: every device whose vendor came from it
// would silently become unknown, and the disappearance would look exactly like
// a network full of hardware IEEE has never heard of. The caller gets the
// error and keeps the data.
func (s *Store) Load(ctx context.Context) error {
	raw, err := s.fetch(ctx)
	if err == nil {
		err = s.set(raw)
	}
	if err != nil {
		return fmt.Errorf("oui: GET %s: %w", s.cfg.Endpoint, err)
	}
	return nil
}

// set parses a listing and publishes it as the table.
//
// An empty parse is an error and the table is left untouched. It is what a
// captive portal, an intercepting proxy, or an error body behind a 200
// produces, and swapping that in would empty a good table while reporting
// success.
//
// The replacement is swapped in whole rather than merged into, and under the
// write lock for the assignment alone: the parse happens outside it, so a
// lookup arriving mid-load takes the read lock and sees the complete previous
// table rather than waiting out forty thousand lines of parsing. Merging would
// also be wrong on content -- a reassigned OUI is published as a new record
// and the old one stops appearing, so merging keeps answering for an
// organization the registry no longer lists.
func (s *Store) set(raw []byte) error {
	vendors := parse(raw)
	if len(vendors) == 0 {
		return fmt.Errorf("no assignments found in %d bytes of response", len(raw))
	}

	s.mu.Lock()
	s.vendors = vendors
	s.mu.Unlock()
	return nil
}

// Lookup returns the organization registered to mac's OUI, and whether one was
// found.
//
// Matching is on a byte boundary by construction rather than by string
// handling: the table is keyed on the three octets themselves, so there is no
// textual search to get wrong. An address held as a bare three-byte OUI
// resolves, and a six-byte address resolves through the same three leading
// bytes, while an address that merely contains the same digits further along
// does not.
//
// An address shorter than the prefix, nil, multicast, or locally administered
// returns false, as does a prefix the registry does not list -- including every
// MA-M and MA-S assignment; see the package comment for why that is a refusal
// rather than a gap.
//
// The vendor string comes back verbatim as IEEE publishes it, embedded
// non-ASCII spacing included, because sanitizing it here would be a second
// sanitizer disagreeing with the first. Consumers needing a token-safe form
// already have one: act/openwrt builds set names through sanitizeName and the
// portal escapes its own output.
//
// This is the seam for wiring, and there is exactly one good place for it.
// deviceTable.Get in cmd/r0-guard is the single funnel every described device
// passes through -- the resolver, the detectors, the containment predicate, the
// audit lines and the portal page all resolve through it -- so filling the
// vendor there, and only where the inventory's own Vendor is empty, enriches
// all of them at once while leaving an operator's labelling authoritative. A
// device only the router has seen is the case that gains most, and it is the
// one ROADMAP.md already calls out as having no vendor at all.
//
// What this package will not decide for you is whether `serve` should make
// that request at all. Doing so adds an outbound destination that SAFETY.md
// section 1 does not currently enumerate -- the router you administer, and the
// named threat feeds -- and puts a value fetched from the public internet one
// step from act/openwrt's sanitizeName, which builds nftables set names from
// d.Vendor and pushes them to the router. That is a posture decision for
// whoever owns it, not a mechanical one, so the package ships complete and
// unwired rather than half-wired.
func (s *Store) Lookup(mac net.HardwareAddr) (string, bool) {
	if len(mac) < prefixLen {
		return "", false
	}
	if mac[0]&(multicast|locallyAdministered) != 0 {
		return "", false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Array key, not mac.String(). Formatting an address allocates and
	// interns a string on the hot path, and a map keyed on three bytes is
	// allocation-free and structurally unable to collide across spellings.
	vendor, ok := s.vendors[[prefixLen]byte{mac[0], mac[1], mac[2]}]
	return vendor, ok
}

// Len reports how many OUI assignments the current table holds, which is the
// number a startup log line should report.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.vendors)
}

// fetch performs one GET and returns the body, bounded by maxBody.
//
// The bound is checked rather than silently imposed. io.LimitReader stops at
// the cap without complaining, so a response over the limit arrives looking
// like a complete one -- and for a listing of records, a truncated file parses
// cleanly into a table that is merely missing its tail, with no signal that
// anything was dropped. Reading one byte past the cap turns that into an error
// the caller can see, which is the difference between "loaded 40,000 vendors"
// and "loaded 40,000 vendors, out of a 40 MB file".
func (s *Store) fetch(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.Endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Status before body: a 404 body is an error page, and parsing it would
	// either fail obscurely or -- worse, under an intercepting proxy that
	// answers everything with 200 -- succeed on garbage. resp.Status rather
	// than the bare code, because "404 Not Found" tells an operator what to go
	// and fix and "404" tells them only that a number they have seen before
	// came back.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	if len(raw) > maxBody {
		return nil, fmt.Errorf("response exceeds the %d byte cap", maxBody)
	}
	return raw, nil
}

// parse reads a registry listing into a table.
//
// Bad lines are skipped, never fatal. The listing is regenerated daily by a
// batch job and is mostly not assignments -- header, separators, base-16
// restatements, addresses, country codes -- so the parser ignores almost
// everything and keys only on the one line shape that carries an organization.
// A single malformed row must not cost the other 40,346.
//
// Where one OUI appears more than once the first record wins. The listing
// retains historical rows and 08-00-30 appears three times, and "first wins"
// makes the table reproducible rather than dependent on which duplicate the
// parser happened to reach last.
func parse(raw []byte) map[[prefixLen]byte]string {
	vendors := make(map[[prefixLen]byte]string, 4096)
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		key, org, ok := parseAssignment(line)
		if !ok {
			continue
		}
		if _, seen := vendors[key]; !seen {
			vendors[key] = org
		}
	}
	return vendors
}

// parseAssignment reads one line of the listing.
//
// It returns false for every line that is not an assignment, which is the
// majority of the file. The organization is taken from the same line as the
// prefix and trimmed of the fixed-width padding between the two columns; the
// trailing carriage return of the listing's CRLF endings goes with it.
func parseAssignment(line []byte) ([prefixLen]byte, string, bool) {
	var key [prefixLen]byte

	i := bytes.Index(line, hexTag)
	if i < 0 {
		return key, "", false
	}

	// The prefix is the first whitespace-delimited field, which is everything
	// before the padding ahead of the tag. Taking that field rather than
	// trimming the whole head means junk in front of the prefix fails
	// parsePrefix on the junk instead of being quietly rescued by it.
	end := 0
	for end < len(line) && line[end] != ' ' && line[end] != '\t' {
		end++
	}
	key, ok := parsePrefix(line[:end])
	if !ok {
		return key, "", false
	}

	org := bytes.TrimSpace(line[i+len(hexTag):])
	if len(org) == 0 {
		return key, "", false
	}
	return key, string(org), true
}

// parsePrefix reads one assignment prefix into three bytes.
//
// The listing writes them dashed, XX-XX-XX, and dashes are tolerated between
// bytes so the undashed form the same record restates in base 16 would land on
// the same key if it were ever read. Everything else is refused, including a
// prefix of the wrong width: the registry issues only 24-bit MA-L
// assignments, so a seven- or nine-digit field is MA-M or MA-S data arriving
// in the wrong file, and rounding it to the nearest 24-bit key would name
// whoever holds the OUI that happens to contain it.
//
// Case needs no normalization because neither alphabet is ever preferred: both
// are accepted, so "28-6f-b9" and "28-6F-B9" produce the same three bytes.
func parsePrefix(s []byte) ([prefixLen]byte, bool) {
	var key [prefixLen]byte
	n := 0 // hex digits consumed so far

	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '-' {
			// A separator is only legal on a byte boundary. One inside a byte
			// means the field is not a prefix at all.
			if n%2 != 0 {
				return key, false
			}
			continue
		}
		v, ok := hexValue(c)
		if !ok {
			return key, false
		}
		if n/2 >= prefixLen {
			return key, false
		}
		if n%2 == 0 {
			key[n/2] = v << 4
		} else {
			key[n/2] |= v
		}
		n++
	}
	if n != prefixLen*2 {
		return key, false
	}
	return key, true
}

func hexValue(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
