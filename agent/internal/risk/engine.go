// Package risk accumulates detector signals into a per-device risk score and
// selects a containment tier.
//
// This is the component that turns observations into decisions, and it is
// where the design's bias toward not acting lives. Three properties are
// enforced here rather than left to callers, because each of them is the
// difference between a tool a homeowner runs and a tool that bricks their
// living room:
//
//  1. Scores decay. A device's history fades on a half-life rather than
//     accumulating forever, so a single bad afternoon does not follow a
//     device for the rest of its life.
//  2. Corroboration is required by default. A lone weak signal never
//     produces an action; escalating needs either two independent signal
//     kinds or one of the high-confidence combinations named in DETECTION.md.
//  3. Device class weights the score. The same signal means something very
//     different on a security camera than on a developer workstation, and
//     only this component holds the Device, so the weighting belongs here.
//
// The engine is pure with respect to the network: it reads no clock of its
// own unless configured to, performs no I/O, and issues no containment. The
// caller decides what to do with an Assessment.
package risk

import (
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

// Config holds the tunable parameters. The defaults are the values published
// in DETECTION.md, which derive them from the measured propagation timing in
// the source research: reaching half of a 33-host flat network took about
// five days, which is what makes conservative thresholds viable. A slow
// adversary gives a defender room to require higher confidence before acting.
type Config struct {
	// HalfLife is the decay horizon. A signal's contribution halves once per
	// half-life, so a device must be consistently anomalous to escalate
	// rather than merely having been anomalous once.
	HalfLife time.Duration

	// RestrictThreshold is the score at which the engine recommends blocking
	// peer-to-peer traffic.
	RestrictThreshold float64
	// QuarantineThreshold is the score at which it recommends the walled
	// garden.
	QuarantineThreshold float64

	// RequireCorroboration, when true, blocks escalation on a single signal
	// kind no matter how high the score.
	RequireCorroboration bool
	// MinIndependentSources is how many distinct signal kinds must be present
	// before escalation is permitted.
	MinIndependentSources int

	// ClassMultipliers scales a signal's contribution by the device class.
	// A nil map means DefaultClassMultipliers. This is the device-class
	// weighting that detectors deliberately do not apply, because detectors
	// never hold the Device.
	ClassMultipliers map[core.DeviceClass]float64

	// MaxAge prunes observations older than this multiple of the half-life.
	// Beyond a few half-lives a signal's contribution is numerically
	// irrelevant, and retaining it would let memory grow without bound on a
	// long-running sensor.
	MaxAgeHalfLives float64
}

// DefaultConfig returns the published defaults.
func DefaultConfig() Config {
	return Config{
		HalfLife:              72 * time.Hour,
		RestrictThreshold:     30,
		QuarantineThreshold:   60,
		RequireCorroboration:  true,
		MinIndependentSources: 2,
		ClassMultipliers:      DefaultClassMultipliers(),
		MaxAgeHalfLives:       10,
	}
}

// DefaultClassMultipliers returns the device-class weighting.
//
// The asymmetry is deliberate and comes straight from DETECTION.md: model
// activity is expected on a workstation and alarming on a camera. Workstations
// and servers are down-weighted rather than excluded outright, because a
// device that is misclassified must still be able to escalate if it is
// genuinely compromised. Finer per-signal suppression is future work; this is
// the coarse lever.
func DefaultClassMultipliers() map[core.DeviceClass]float64 {
	return map[core.DeviceClass]float64{
		core.ClassServer:      0.3,
		core.ClassWorkstation: 0.3,
		core.ClassMobile:      0.8,
		core.ClassUnknown:     1.0,
		core.ClassIoT:         1.5,
		core.ClassAppliance:   1.5,
		core.ClassCamera:      1.5,
		core.ClassTV:          1.5,
	}
}

// observation is one recorded signal with the time it was seen.
type observation struct {
	kind       core.SignalKind
	class      core.SignalClass
	weight     float64
	confidence float64
	reason     string
	at         time.Time
}

// Assessment is the engine's current view of one device.
type Assessment struct {
	// MAC is the device assessed.
	MAC net.HardwareAddr
	// Score is the decayed, class-weighted risk score as of the evaluation
	// time.
	Score float64
	// Tier is the recommended containment state. It is ContainmentMonitor
	// whenever corroboration is not satisfied, regardless of score.
	Tier core.ContainmentState
	// Policy is the concrete action set for Tier.
	Policy core.Policy
	// DistinctKinds is how many independent signal kinds currently
	// contribute, which is what the corroboration rule counts.
	DistinctKinds int
	// Corroborated reports whether the corroboration requirement is met.
	Corroborated bool
	// HighConfidence reports whether a named high-confidence combination is
	// present, which can satisfy escalation on its own.
	HighConfidence bool
	// Reasons are the surviving observations, highest contribution first,
	// rendered into the remediation portal. A user who has just had their
	// camera disconnected deserves the sentences, not a score.
	Reasons []string
	// Contributions exposes the per-signal breakdown for reporting and tests.
	Contributions []Contribution
}

// Contribution is one signal's current, decayed weight toward a device's
// score.
type Contribution struct {
	Kind     core.SignalKind
	Class    core.SignalClass
	Amount   float64
	Reason   string
	Age      time.Duration
	Decay    float64
	Weighted float64 // pre-decay weighted amount, for debugging
}

// Engine accumulates signals and computes Assessments. It is safe for
// concurrent use: the ingest loop observes while the portal evaluates.
type Engine struct {
	cfg  Config
	now  func() time.Time
	mu   sync.Mutex
	seen map[string][]observation
}

// Option customizes an Engine.
type Option func(*Engine)

// WithClock injects a clock. Tests use it to make decay deterministic; a nil
// or zero clock falls back to time.Now.
func WithClock(now func() time.Time) Option {
	return func(e *Engine) {
		if now != nil {
			e.now = now
		}
	}
}

// WithHalfLife sets only the decay horizon, leaving every other default —
// including the corroboration requirement — intact.
//
// This exists as a granular option because the alternative, passing a partial
// Config to WithConfig, is a trap: RequireCorroboration is a bool, so a zero
// Config means "corroboration disabled", and a caller who only wanted to set
// the half-life would silently turn off the project's central safety
// property. Prefer this over WithConfig unless you intend to control
// everything.
func WithHalfLife(d time.Duration) Option {
	return func(e *Engine) {
		if d > 0 {
			e.cfg.HalfLife = d
		}
	}
}

// WithConfig replaces the configuration wholesale.
//
// Zero numeric fields and a nil multiplier map fall back to the defaults, but
// the boolean RequireCorroboration is applied exactly as given. Build from
// DefaultConfig() and mutate it; passing a bare Config{...} literal disables
// corroboration, which is almost never what you want. Prefer WithHalfLife for
// the common case.
func WithConfig(cfg Config) Option {
	return func(e *Engine) {
		if cfg.HalfLife > 0 {
			e.cfg.HalfLife = cfg.HalfLife
		}
		if cfg.RestrictThreshold > 0 {
			e.cfg.RestrictThreshold = cfg.RestrictThreshold
		}
		if cfg.QuarantineThreshold > 0 {
			e.cfg.QuarantineThreshold = cfg.QuarantineThreshold
		}
		e.cfg.RequireCorroboration = cfg.RequireCorroboration
		if cfg.MinIndependentSources > 0 {
			e.cfg.MinIndependentSources = cfg.MinIndependentSources
		}
		if cfg.ClassMultipliers != nil {
			e.cfg.ClassMultipliers = cfg.ClassMultipliers
		}
		if cfg.MaxAgeHalfLives > 0 {
			e.cfg.MaxAgeHalfLives = cfg.MaxAgeHalfLives
		}
	}
}

// New returns an Engine with the published defaults.
func New(opts ...Option) *Engine {
	e := &Engine{
		cfg:  DefaultConfig(),
		now:  time.Now,
		seen: map[string][]observation{},
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Observe records a signal.
//
// The signal's DeviceMAC selects the bucket. An unattributable signal (empty
// MAC) is dropped: a finding that cannot name a device cannot be acted on, and
// retaining it would only let memory grow.
func (e *Engine) Observe(sig core.Signal, at time.Time) {
	if len(sig.DeviceMAC) == 0 {
		return
	}
	if at.IsZero() {
		at = e.now()
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	key := sig.DeviceMAC.String()
	e.seen[key] = append(e.seen[key], observation{
		kind:       sig.Kind,
		class:      sig.Class,
		weight:     sig.Weight,
		confidence: sig.Confidence,
		reason:     sig.Reason,
		at:         at,
	})
	// Prune on write so that memory is bounded by the decay horizon rather
	// than by the lifetime of the process.
	e.pruneLocked(key, at)
}

// Score returns the current decayed, class-weighted score for a device.
func (e *Engine) Score(dev core.Device, at time.Time) float64 {
	a := e.Evaluate(dev, at)
	return a.Score
}

// Evaluate computes a device's Assessment as of `at`.
//
// It does not mutate stored observations beyond pruning, so it is safe to
// call repeatedly (the portal polls; the ingest loop observes).
func (e *Engine) Evaluate(dev core.Device, at time.Time) Assessment {
	if at.IsZero() {
		at = e.now()
	}

	e.mu.Lock()
	obs := make([]observation, len(e.seen[dev.MAC.String()]))
	copy(obs, e.seen[dev.MAC.String()])
	e.pruneLocked(dev.MAC.String(), at)
	e.mu.Unlock()

	mult := e.cfg.ClassMultipliers[dev.Class]
	if mult == 0 {
		// An unmapped class must not zero the score, which would silently
		// immunize a device simply because it was not categorized.
		mult = 1
	}

	a := Assessment{MAC: dev.MAC, Tier: core.ContainmentMonitor, Policy: core.PolicyMonitor}

	kinds := map[core.SignalKind]bool{}
	classes := map[core.SignalClass]bool{}

	for _, o := range obs {
		decay := e.decayFactor(o.at, at)
		amount := o.weight * o.confidence * mult * decay
		if amount <= 0 {
			continue
		}
		a.Score += amount
		a.Contributions = append(a.Contributions, Contribution{
			Kind:     o.kind,
			Class:    o.class,
			Amount:   amount,
			Reason:   o.reason,
			Age:      at.Sub(o.at),
			Decay:    decay,
			Weighted: o.weight * o.confidence * mult,
		})
		kinds[o.kind] = true
		classes[o.class] = true
	}

	a.DistinctKinds = len(kinds)
	a.Corroborated = a.DistinctKinds >= e.cfg.MinIndependentSources
	a.HighConfidence = highConfidence(kinds, classes)

	// Highest contribution first, so the portal shows the most damning
	// reason where a user will actually read it.
	sort.SliceStable(a.Contributions, func(i, j int) bool {
		return a.Contributions[i].Amount > a.Contributions[j].Amount
	})
	seen := map[string]bool{}
	for _, c := range a.Contributions {
		if c.Reason == "" || seen[c.Reason] {
			continue
		}
		seen[c.Reason] = true
		a.Reasons = append(a.Reasons, fmt.Sprintf("%s (score %.1f)", c.Reason, c.Amount))
	}

	a.Tier, a.Policy = e.decide(a.Score, a.Corroborated, a.HighConfidence)
	return a
}

// decide maps a score and corroboration state to a tier.
//
// The order of checks is the safety property: corroboration gates the tier
// before the score can, so a single loud signal on one device can never reach
// an action no matter how large its weight. This is what DETECTION.md means
// by "a single weak signal never produces an action."
func (e *Engine) decide(score float64, corroborated, highConfidence bool) (core.ContainmentState, core.Policy) {
	canAct := corroborated || highConfidence
	if e.cfg.RequireCorroboration && !canAct {
		return core.ContainmentMonitor, core.PolicyMonitor
	}

	switch {
	case score >= e.cfg.QuarantineThreshold:
		return core.ContainmentQuarantined, core.PolicyQuarantine
	case score >= e.cfg.RestrictThreshold:
		return core.ContainmentRestricted, core.PolicyRestrict
	default:
		return core.ContainmentMonitor, core.PolicyMonitor
	}
}

// highConfidence reports whether a named combination from DETECTION.md's
// corroboration table is present. These combinations earn escalation on their
// own because each pairs two observations that are independently unlikely.
func highConfidence(kinds map[core.SignalKind]bool, classes map[core.SignalClass]bool) bool {
	// "R7 + R1": novel model-domain contact and a large transfer from the
	// same device. Either alone is a common false positive; together they are
	// the weight-moving sequence itself.
	if kinds[core.SignalDNSDrift] && kinds[core.SignalWeightTransfer] {
		return true
	}
	// "Any [R] + any [P]": corroboration across classes. A behavior inherent
	// to replication, corroborated by an artifact of the prototypes that a
	// motivated adversary would strip, is the strongest available evidence.
	return classes[core.SignalReplicationRequired] && classes[core.SignalPoCArtifact]
}

// decayFactor is the exponential decay kernel: 0.5 ^ (age / half-life).
func (e *Engine) decayFactor(occurred, at time.Time) float64 {
	halfLife := e.cfg.HalfLife
	if halfLife <= 0 {
		return 1
	}
	age := at.Sub(occurred)
	if age < 0 {
		// A signal timestamped in the future is a clock-skew artifact, not a
		// reason to inflate the score. Treat it as fresh rather than
		// amplifying it.
		return 1
	}
	return math.Pow(0.5, float64(age)/float64(halfLife))
}

// pruneLocked drops observations that have decayed past the horizon. The
// caller must hold e.mu.
func (e *Engine) pruneLocked(key string, at time.Time) {
	obs := e.seen[key]
	if len(obs) == 0 {
		return
	}
	maxAge := time.Duration(e.cfg.MaxAgeHalfLives * float64(e.cfg.HalfLife))
	kept := obs[:0]
	for _, o := range obs {
		if at.Sub(o.at) <= maxAge {
			kept = append(kept, o)
		}
	}
	if len(kept) == 0 {
		delete(e.seen, key)
		return
	}
	e.seen[key] = kept
}

// Ranked returns every assessed device, highest score first. It is what the
// CLI and the remediation portal both render.
func (e *Engine) Ranked(devices []core.Device, at time.Time) []Assessment {
	out := make([]Assessment, 0, len(devices))
	for _, d := range devices {
		a := e.Evaluate(d, at)
		if a.Score <= 0 && len(a.Reasons) == 0 {
			continue
		}
		out = append(out, a)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

// Describe renders an Assessment as a human-readable line. Kept here rather
// than in the CLI so the portal and the CLI agree on wording.
func (a Assessment) Describe() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s  score=%-6.1f tier=%s", a.MAC, a.Score, a.Tier)
	if a.Corroborated {
		fmt.Fprintf(&b, " corroborated(%d kinds)", a.DistinctKinds)
	} else if a.HighConfidence {
		b.WriteString(" high-confidence")
	} else {
		fmt.Fprintf(&b, " uncorroborated(%d kinds)", a.DistinctKinds)
	}
	for _, r := range a.Reasons {
		b.WriteString("\n    - " + r)
	}
	return b.String()
}
