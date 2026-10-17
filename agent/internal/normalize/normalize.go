// Package normalize turns feed items into indicators of compromise with an
// explicit TTL, a confidence estimate, and provenance, and holds them in a
// store the resolver's policy can consult on every query.
//
// The layer boundary matches ARCHITECTURE.md: feeds know wire formats and
// nothing about policy; normalize knows TTL, confidence, and matching and
// nothing about HTTP; the resolver knows neither and is handed a predicate.
package normalize

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/feeds"
)

// IoC is one canonical indicator, ready for policy.
type IoC struct {
	// Value is the canonical indicator: a lowercase domain, a bare IP
	// address, or a CVE identifier.
	Value string
	Kind  feeds.Kind
	// Confidence is the merged 0-100 estimate. The highest confidence any
	// contributing feed published wins: agreement is already merged in,
	// disagreement resolves to the braver claim because the operator can
	// gate with -ioc-min-confidence rather than have the store silently
	// average two feeds' opinions.
	Confidence int
	// Feeds names every feed that published this indicator since the last
	// refresh of each. Provenance is what the audit log and the portal
	// show when policy acts on the value.
	Feeds []string
	// Tags are the merged labels (malware family, vendor, product).
	Tags []string
	// FirstSeen is the earliest first-seen any contributing feed reported.
	FirstSeen time.Time
	// Expires is when this snapshot goes stale. Feeds re-publish what is
	// still live, so a value that stops appearing ages out on its own.
	Expires time.Time
}

// Normalize converts one feed's items into indicators that expire ttl after
// now. Duplicates within the batch are merged: confidence takes the maximum,
// provenance and tags union, and FirstSeen keeps the earliest reported
// value. The result is sorted by kind and value so tests and audit diffs are
// deterministic.
func Normalize(items []feeds.Item, now time.Time, ttl time.Duration) []IoC {
	merged := make(map[string]*IoC, len(items))
	for _, it := range items {
		if it.Value == "" {
			continue
		}
		key := string(it.Kind) + "\x00" + it.Value
		conf := clampConfidence(it.Confidence)
		if cur, ok := merged[key]; ok {
			if conf > cur.Confidence {
				cur.Confidence = conf
			}
			cur.Feeds = union(cur.Feeds, []string{it.Feed})
			cur.Tags = union(cur.Tags, it.Tags)
			if !it.FirstSeen.IsZero() && (cur.FirstSeen.IsZero() || it.FirstSeen.Before(cur.FirstSeen)) {
				cur.FirstSeen = it.FirstSeen
			}
			continue
		}
		ioc := &IoC{
			Value:      it.Value,
			Kind:       it.Kind,
			Confidence: conf,
			Feeds:      union(nil, []string{it.Feed}),
			Tags:       union(nil, it.Tags),
			FirstSeen:  it.FirstSeen,
			Expires:    now.Add(ttl),
		}
		merged[key] = ioc
	}

	out := make([]IoC, 0, len(merged))
	for _, ioc := range merged {
		out = append(out, *ioc)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Value < out[j].Value
	})
	return out
}

// union appends the members of add to base that are not already present,
// preserving first-seen order and lowercasing tag comparisons so "Mirai" and
// "mirai" from two feeds do not both survive.
func union(base, add []string) []string {
	for _, a := range add {
		if a == "" {
			continue
		}
		found := false
		for _, b := range base {
			if strings.EqualFold(a, b) {
				found = true
				break
			}
		}
		if !found {
			base = append(base, a)
		}
	}
	return base
}

func clampConfidence(c int) int {
	if c < 0 {
		return 0
	}
	if c > 100 {
		return 100
	}
	return c
}

// Store holds the latest snapshot of every enabled feed and answers domain
// lookups for policy. It is safe for concurrent use: the pull loop replaces
// whole feeds while the resolver matches on every query.
//
// Snapshots replace per feed rather than accumulating, so a value the feed
// stops publishing disappears at the next refresh instead of living forever,
// and a feed that is turned off leaves at most one snapshot behind.
type Store struct {
	mu            sync.RWMutex
	snapshots     map[string][]IoC
	minConfidence int
}

// NewStore returns an empty store. minConfidence gates matching, not
// storage: low-confidence indicators are kept for provenance and future
// consumers but do not act until the operator lowers the gate.
func NewStore(minConfidence int) *Store {
	return &Store{
		snapshots:     make(map[string][]IoC),
		minConfidence: clampConfidence(minConfidence),
	}
}

// Replace swaps in the latest snapshot for one feed. The batch is assumed
// already normalized (same TTL across the batch, values canonical); items
// that expired before arrival are still stored and simply never match.
func (s *Store) Replace(feed string, iocs []IoC) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshots[feed] = iocs
}

// Prune drops entries whose expiry has passed from every snapshot, bounding
// memory when a feed stops being refreshed. The store keeps working with no
// entries: nothing matches, and policy falls through to its defaults.
func (s *Store) Prune(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, iocs := range s.snapshots {
		kept := iocs[:0]
		for _, ioc := range iocs {
			if ioc.Expires.After(now) {
				kept = append(kept, ioc)
			}
		}
		s.snapshots[name] = kept
	}
}

// Count returns the number of unexpired indicators across all feeds.
func (s *Store) Count(now time.Time) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, iocs := range s.snapshots {
		for _, ioc := range iocs {
			if ioc.Expires.After(now) {
				n++
			}
		}
	}
	return n
}

// CountFeed returns the number of unexpired indicators from one feed, which
// is what a startup or refresh log line reports per feed.
func (s *Store) CountFeed(feed string, now time.Time) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, ioc := range s.snapshots[feed] {
		if ioc.Expires.After(now) {
			n++
		}
	}
	return n
}

// Match reports the highest-confidence unexpired domain indicator that
// covers name: an exact match or a label-boundary subdomain match, gated by
// the store's minimum confidence.
//
// Only domain indicators participate. IP indicators are stored for
// provenance and future firewall-level policy; CVE indicators join against
// inventory. Reverse-zone queries are not matched — that is a deliberate
// v0.1 limit, not an oversight, and nothing in DNS policy can act on a PTR
// answer yet anyway.
func (s *Store) Match(name string, now time.Time) (IoC, bool) {
	name = canonicalName(name)
	if name == "" {
		return IoC{}, false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	best := IoC{}
	bestOK := false
	bestExact := false
	for _, iocs := range s.snapshots {
		for _, ioc := range iocs {
			if ioc.Kind != feeds.KindDomain || ioc.Confidence < s.minConfidence {
				continue
			}
			if !ioc.Expires.After(now) {
				continue
			}
			exact := name == ioc.Value
			if !exact && !strings.HasSuffix(name, "."+ioc.Value) {
				continue
			}
			if betterMatch(ioc, exact, best, bestOK, bestExact) {
				best, bestOK, bestExact = ioc, true, exact
			}
		}
	}
	return best, bestOK
}

// betterMatch orders candidate matches: exact beats suffix, then higher
// confidence, so the indicator reported in the audit is the one the operator
// would point at first.
func betterMatch(cand IoC, candExact bool, best IoC, hasBest, bestExact bool) bool {
	if !hasBest {
		return true
	}
	if candExact != bestExact {
		return candExact
	}
	return cand.Confidence > best.Confidence
}

// canonicalName lowercases and trims the root dot, mirroring what the
// resolver passes down so a caller using Store directly gets the same
// answers the resolver would.
func canonicalName(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}
