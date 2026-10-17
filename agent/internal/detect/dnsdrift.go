package detect

import (
	"strings"
	"sync"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

// DefaultDNSDriftMinBaseline is the number of prior attributed queries a device
// must have before it can "deviate" from anything. It is the value published in
// DETECTION.md's tuning block. A device seen for the first time cannot deviate
// from a baseline that does not exist, which is what R8 is for.
const DefaultDNSDriftMinBaseline = 100

// DefaultDNSDriftCategories maps a category name to the domain suffixes in it.
//
// Categories are configuration, not code, exactly as DETECTION.md requires:
// this is a conservative starting point an operator extends, not a detection
// truth. It reuses the model-host suffixes rather than restating them, so the
// two detectors cannot drift apart as hosting providers change.
var DefaultDNSDriftCategories = map[string][]string{
	"model_host": DefaultModelHostSuffixes,
}

// DNSDriftDetector implements signal R7: a device's first-ever DNS query to a
// domain in a configured category, once that device has an established query
// baseline.
//
// This is the one detector in the package that is not a pure function of a
// single event, and the deviation is deliberate rather than an oversight.
// "First-ever contact with a category" is a temporal property: no single
// NormalizedEvent can carry it, because the same query is news on one device
// and background noise on another that has done it for months. So the detector
// owns the per-device baseline that the property requires.
//
// What it does NOT do is what keeps it in the spirit of the package: it performs
// no I/O, reads no clock, and touches no global state. Its state is instance-
// scoped and guarded by a mutex, so it is safe to call from a concurrent ingest
// loop and is still exercisable in a test with no resolver and no hardware —
// you feed it a sequence of events, which is all any caller does.
//
// It is a [core.SignalReplicationRequired] signal and, per DETECTION.md's
// corroboration table, one that must never act alone: "R7 alone — log, do not
// act." The risk engine enforces that, because R7 always reports as a single
// signal kind no matter how many times it fires.
type DNSDriftDetector struct {
	mu sync.Mutex

	// minBaseline is the number of prior attributed queries required before a
	// first contact counts as drift.
	minBaseline int
	// categories is the category name to domain-suffix table.
	categories map[string][]string

	// total counts every attributed query per device, which is the baseline.
	total map[string]int
	// contacted records, per device, the categories it has already resolved,
	// so that only the first contact can fire.
	contacted map[string]map[string]bool
}

// NewDNSDriftDetector returns a detector firing on first contact with a
// category once the device has minBaseline prior queries.
//
// A non-positive minBaseline falls back to DefaultDNSDriftMinBaseline, and a
// nil categories map falls back to DefaultDNSDriftCategories. Both fallbacks
// exist because a zero-valued detector would otherwise record every category as
// contacted on a device's very first query and then never fire at all — a
// silent, invisible failure on the signal most specific to passive-only
// operation.
func NewDNSDriftDetector(minBaseline int, categories map[string][]string) *DNSDriftDetector {
	if minBaseline <= 0 {
		minBaseline = DefaultDNSDriftMinBaseline
	}
	if categories == nil {
		categories = DefaultDNSDriftCategories
	}

	// Normalize once at construction so Evaluate does no allocation per query.
	norm := make(map[string][]string, len(categories))
	for cat, suffixes := range categories {
		clean := make([]string, 0, len(suffixes))
		for _, s := range suffixes {
			s = strings.ToLower(strings.TrimSpace(s))
			s = strings.TrimPrefix(s, "*.")
			s = strings.TrimSuffix(s, ".")
			if s == "" {
				continue
			}
			clean = append(clean, s)
		}
		if len(clean) == 0 {
			continue
		}
		norm[strings.ToLower(strings.TrimSpace(cat))] = clean
	}

	return &DNSDriftDetector{
		minBaseline: minBaseline,
		categories:  norm,
		total:       map[string]int{},
		contacted:   map[string]map[string]bool{},
	}
}

// Kind identifies this detector's signal.
func (d *DNSDriftDetector) Kind() core.SignalKind { return core.SignalDNSDrift }

// Evaluate records the query against the device's baseline and, when the query
// is the device's first to a configured category and the baseline is
// established, reports drift.
//
// Every attributed query advances the baseline, including ones to categories
// this detector does not watch; a baseline is a measure of how much we have
// seen from a device, not of how anomalous it has been.
func (d *DNSDriftDetector) Evaluate(e core.NormalizedEvent) []core.Signal {
	// Without a device there is no baseline to deviate from, so there is
	// nothing to report and nothing to record.
	if len(e.DeviceMAC) == 0 {
		return nil
	}
	// R7 is sourced from our own resolver's query log, so the question name is
	// the only field that can carry the category. SNI is accepted as a
	// fallback for events normalized from TLS that also carry a name.
	host := firstNonEmpty(e.QueryName, e.SNI)
	if host == "" {
		return nil
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))

	d.mu.Lock()
	defer d.mu.Unlock()

	mac := e.DeviceMAC.String()

	// The baseline is what existed BEFORE this query. Checking first and
	// incrementing after is what makes the rule read as DETECTION.md states
	// it: "at least N prior queries."
	prior := d.total[mac]
	d.total[mac] = prior + 1

	cat := d.categoryFor(host)
	if cat == "" {
		// Not a category we watch, but it still counts toward the baseline.
		return nil
	}

	if d.contacted[mac] == nil {
		d.contacted[mac] = map[string]bool{}
	}
	firstContact := !d.contacted[mac][cat]
	// Mark the category contacted even when this query is too early to fire.
	// The contact already happened, so it is no longer "first-ever" later; a
	// device that resolved a model host on its first query ever cannot be
	// handed an R7 for it once it has 100 queries. That device's story is R8,
	// not R7.
	d.contacted[mac][cat] = true

	if !firstContact || prior < d.minBaseline {
		return nil
	}

	return []core.Signal{{
		Kind:      core.SignalDNSDrift,
		Class:     core.SignalReplicationRequired,
		DeviceMAC: e.DeviceMAC,
		// Weight sits near R2 because this is the same underlying contact,
		// but confidence is lower: a first contact is a state transition, not
		// proof of transfer, and its false positives (a new app, a firmware
		// update) are exactly the everyday events DETECTION.md names.
		Weight:     25,
		Confidence: 0.5,
		Reason:     "device resolved a " + cat + " domain for the first time (" + host + ")",
		Evidence: map[string]any{
			"host":             host,
			"category":         cat,
			"baseline_queries": prior,
			"min_baseline":     d.minBaseline,
		},
	}}
}

// categoryFor returns the first category containing host, or "".
func (d *DNSDriftDetector) categoryFor(host string) string {
	for cat, suffixes := range d.categories {
		for _, s := range suffixes {
			if host == s || strings.HasSuffix(host, "."+s) {
				return cat
			}
		}
	}
	return ""
}

// Baseline returns how many attributed queries a device has accumulated. It
// exists for tests and for the remediation portal, which may want to show a
// user how established a device's history is before it deviated.
func (d *DNSDriftDetector) Baseline(mac core.Device) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.total[mac.MAC.String()]
}
