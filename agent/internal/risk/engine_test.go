package risk

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

func mac(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

// baseTime is a fixed instant so that decay is deterministic across runs.
var baseTime = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

func fixedClock(at time.Time) func() time.Time { return func() time.Time { return at } }

func device(class core.DeviceClass) core.Device {
	return core.Device{MAC: mac("aa:bb:cc:dd:ee:01"), Class: class}
}

func sig(kind core.SignalKind, class core.SignalClass, weight float64) core.Signal {
	return sigFor(mac("aa:bb:cc:dd:ee:01"), kind, class, weight)
}

// sigFor builds a signal attributed to a specific device. Threshold-focused
// tests use the neutral unknown class so that the score arithmetic is
// readable; class weighting is exercised separately.
func sigFor(m net.HardwareAddr, kind core.SignalKind, class core.SignalClass, weight float64) core.Signal {
	return core.Signal{
		Kind:       kind,
		Class:      class,
		DeviceMAC:  m,
		Weight:     weight,
		Confidence: 1.0,
		Reason:     "test " + string(kind),
	}
}

// TestDefaultsMatchDetectionDoc locks the engine to the published numbers. A
// silent change here would alter containment behaviour for every install
// without anyone noticing a diff in the docs.
func TestDefaultsMatchDetectionDoc(t *testing.T) {
	c := DefaultConfig()

	if c.HalfLife != 72*time.Hour {
		t.Errorf("HalfLife = %v, want 72h (DETECTION.md decay_half_life)", c.HalfLife)
	}
	if c.RestrictThreshold != 30 {
		t.Errorf("RestrictThreshold = %v, want 30", c.RestrictThreshold)
	}
	if c.QuarantineThreshold != 60 {
		t.Errorf("QuarantineThreshold = %v, want 60", c.QuarantineThreshold)
	}
	if !c.RequireCorroboration {
		t.Error("RequireCorroboration must default true; a single weak signal may never act")
	}
	if c.MinIndependentSources != 2 {
		t.Errorf("MinIndependentSources = %d, want 2", c.MinIndependentSources)
	}
}

// TestSingleSignalNeverEscalates is the central safety property. No matter how
// large a single signal's weight, corroboration must hold the device at
// monitor. This is what stops one false positive from bricking an appliance.
func TestSingleSignalNeverEscalates(t *testing.T) {
	e := New(WithClock(fixedClock(baseTime)))
	dev := device(core.ClassCamera)

	// A signal weighted far past the quarantine threshold, on its own.
	e.Observe(sig(core.SignalWeightTransfer, core.SignalReplicationRequired, 5000), baseTime)

	a := e.Evaluate(dev, baseTime)
	if a.Score < 60 {
		t.Fatalf("score = %v, want it to exceed the quarantine threshold", a.Score)
	}
	if a.Tier != core.ContainmentMonitor {
		t.Errorf("tier = %q, want monitor: one signal kind may never escalate", a.Tier)
	}
	if a.Corroborated {
		t.Error("Corroborated = true with a single kind; want false")
	}
}

// TestTwoIndependentKindsEscalate verifies the documented path: corroboration
// from two independent signal kinds permits escalation once the score clears
// the threshold.
func TestTwoIndependentKindsEscalate(t *testing.T) {
	e := New(WithClock(fixedClock(baseTime)))
	// Neutral class keeps the arithmetic readable: 25 + 25 = 50, which sits
	// between the restrict (30) and quarantine (60) thresholds.
	dev := device(core.ClassUnknown)

	e.Observe(sig(core.SignalDNSDrift, core.SignalReplicationRequired, 25), baseTime)
	e.Observe(sig(core.SignalEastWestVolume, core.SignalReplicationRequired, 25), baseTime)

	a := e.Evaluate(dev, baseTime)
	if a.DistinctKinds != 2 {
		t.Fatalf("DistinctKinds = %d, want 2", a.DistinctKinds)
	}
	if !a.Corroborated {
		t.Fatal("two independent kinds must satisfy corroboration")
	}
	if a.Score < 49 || a.Score > 51 {
		t.Fatalf("score = %v, want ~50", a.Score)
	}
	if a.Tier != core.ContainmentRestricted {
		t.Errorf("tier = %q, want restricted at score >= 30", a.Tier)
	}
}

// TestQuarantineAtHighScore verifies the upper tier is reachable once
// corroborated.
func TestQuarantineAtHighScore(t *testing.T) {
	e := New(WithClock(fixedClock(baseTime)))
	dev := device(core.ClassUnknown)

	e.Observe(sig(core.SignalDNSDrift, core.SignalReplicationRequired, 40), baseTime)
	e.Observe(sig(core.SignalEastWestVolume, core.SignalReplicationRequired, 40), baseTime)

	a := e.Evaluate(dev, baseTime)
	if a.Tier != core.ContainmentQuarantined {
		t.Errorf("tier = %q, want quarantined at score >= 60", a.Tier)
	}
	if !a.Policy.RestrictEgress {
		t.Error("quarantine policy must restrict egress")
	}
}

// TestHighConfidencePairEscalates covers the R7+R1 combination, which
// DETECTION.md names as high confidence: novel contact plus a large transfer
// is the weight-moving sequence itself.
func TestHighConfidencePairEscalates(t *testing.T) {
	e := New(WithClock(fixedClock(baseTime)))
	dev := device(core.ClassUnknown)

	e.Observe(sig(core.SignalDNSDrift, core.SignalReplicationRequired, 25), baseTime)
	e.Observe(sig(core.SignalWeightTransfer, core.SignalReplicationRequired, 25), baseTime)

	a := e.Evaluate(dev, baseTime)
	if !a.HighConfidence {
		t.Fatal("R7 + R1 must be recognized as a high-confidence combination")
	}
	if a.Tier != core.ContainmentRestricted {
		t.Errorf("tier = %q, want restricted: high confidence satisfies escalation", a.Tier)
	}
}

// TestCrossClassCorroboration covers the other named combination: a
// replication-required signal corroborated by a proof-of-concept artifact.
func TestCrossClassCorroboration(t *testing.T) {
	e := New(WithClock(fixedClock(baseTime)))
	dev := device(core.ClassUnknown)

	e.Observe(sig(core.SignalModelHostOnIoT, core.SignalReplicationRequired, 25), baseTime)
	e.Observe(sig(core.SignalBeacon, core.SignalPoCArtifact, 25), baseTime)

	a := e.Evaluate(dev, baseTime)
	if !a.HighConfidence {
		t.Fatal("[R] + [P] must be recognized as cross-class corroboration")
	}
	if a.Tier != core.ContainmentRestricted {
		t.Errorf("tier = %q, want restricted", a.Tier)
	}
}

// TestDecayHalvesAtHalfLife verifies the decay kernel numerically. A score
// that never faded would mean one bad afternoon follows a device forever.
func TestDecayHalvesAtHalfLife(t *testing.T) {
	e := New(WithClock(fixedClock(baseTime)))
	dev := device(core.ClassUnknown)

	// Two kinds so corroboration is not the thing under test; neutral class
	// keeps the arithmetic exact.
	e.Observe(sig(core.SignalWeightTransfer, core.SignalReplicationRequired, 100), baseTime)
	e.Observe(sig(core.SignalDNSDrift, core.SignalReplicationRequired, 100), baseTime)

	if got := e.Score(dev, baseTime); got < 199 || got > 201 {
		t.Fatalf("score at t0 = %v, want ~200", got)
	}

	// One half-life later, both contributions have halved: 200 -> 100.
	atHalf := baseTime.Add(72 * time.Hour)
	if got := e.Score(dev, atHalf); got < 99 || got > 101 {
		t.Errorf("score at one half-life = %v, want ~100", got)
	}

	// Two half-lives: 200 -> 100 -> 50.
	atTwo := baseTime.Add(144 * time.Hour)
	if got := e.Score(dev, atTwo); got < 49 || got > 51 {
		t.Errorf("score at two half-lives = %v, want ~50", got)
	}
}

func TestDecayFadesToNothing(t *testing.T) {
	e := New(WithClock(fixedClock(baseTime)))
	dev := device(core.ClassUnknown)

	e.Observe(sig(core.SignalWeightTransfer, core.SignalReplicationRequired, 100), baseTime)
	e.Observe(sig(core.SignalDNSDrift, core.SignalReplicationRequired, 100), baseTime)

	// Ten half-lives is a 1/1024 residual, far below any threshold.
	longAfter := baseTime.Add(720 * time.Hour)
	if got := e.Score(dev, longAfter); got > 1 {
		t.Errorf("score after 10 half-lives = %v, want ~0", got)
	}
	if a := e.Evaluate(dev, longAfter); a.Tier != core.ContainmentMonitor {
		t.Errorf("tier after full decay = %q, want monitor", a.Tier)
	}
}

// TestClassWeighting is the device-class weighting that detectors deliberately
// do not apply. The same signal must score higher on a camera than on a
// workstation, because on a workstation model activity is expected.
func TestClassWeighting(t *testing.T) {
	e := New(WithClock(fixedClock(baseTime)))

	// Two distinct devices so their observations do not pile into one bucket.
	camMAC := mac("aa:bb:cc:dd:ee:01")
	wsMAC := mac("aa:bb:cc:dd:ee:02")

	for _, k := range []core.SignalKind{core.SignalModelHostOnIoT, core.SignalDNSDrift} {
		e.Observe(sigFor(camMAC, k, core.SignalReplicationRequired, 100), baseTime)
		e.Observe(sigFor(wsMAC, k, core.SignalReplicationRequired, 100), baseTime)
	}

	camScore := e.Score(core.Device{MAC: camMAC, Class: core.ClassCamera}, baseTime)
	wsScore := e.Score(core.Device{MAC: wsMAC, Class: core.ClassWorkstation}, baseTime)

	if camScore <= wsScore {
		t.Errorf("camera score %v must exceed workstation score %v", camScore, wsScore)
	}
	// Default multipliers are 1.5 and 0.3, so the same 200 raw weight becomes
	// 300 and 60.
	if camScore < 299 || camScore > 301 {
		t.Errorf("camera score = %v, want ~300", camScore)
	}
	if wsScore < 59 || wsScore > 61 {
		t.Errorf("workstation score = %v, want ~60", wsScore)
	}
}

// TestUnknownClassIsNotImmunized guards a subtle failure: an unmapped class
// must not multiply the score by zero, which would let an uncategorized
// device escalate with no resistance simply because nobody classified it.
func TestUnknownClassIsNotImmunized(t *testing.T) {
	e := New(WithClock(fixedClock(baseTime)))
	cfg := DefaultConfig()
	cfg.ClassMultipliers = map[core.DeviceClass]float64{core.ClassCamera: 1.5}
	e = New(WithConfig(cfg), WithClock(fixedClock(baseTime)))

	dev := core.Device{MAC: mac("aa:bb:cc:dd:ee:01"), Class: "unmapped-class"}
	e.Observe(sig(core.SignalModelHostOnIoT, core.SignalReplicationRequired, 100), baseTime)
	e.Observe(sig(core.SignalDNSDrift, core.SignalReplicationRequired, 100), baseTime)

	if got := e.Score(dev, baseTime); got < 199 || got > 201 {
		t.Errorf("unmapped class score = %v, want ~200 (multiplier 1), not 0", got)
	}
}

// TestUnclassifiedDeviceDefaultsNeutral checks the ordinary unknown class
// behaves as the neutral multiplier.
func TestUnclassifiedDeviceDefaultsNeutral(t *testing.T) {
	e := New(WithClock(fixedClock(baseTime)))
	dev := device(core.ClassUnknown)

	e.Observe(sig(core.SignalModelHostOnIoT, core.SignalReplicationRequired, 100), baseTime)
	if got := e.Score(dev, baseTime); got < 99 || got > 101 {
		t.Errorf("unknown-class score = %v, want ~100 (multiplier 1)", got)
	}
}

// TestUnattributableSignalIsDropped verifies the engine refuses to score a
// finding that cannot name a device, which would otherwise inflate some other
// device's bucket or leak memory.
func TestUnattributableSignalIsDropped(t *testing.T) {
	e := New(WithClock(fixedClock(baseTime)))

	unattributed := sig(core.SignalWeightTransfer, core.SignalReplicationRequired, 100)
	unattributed.DeviceMAC = nil
	e.Observe(unattributed, baseTime)

	if got := e.Score(device(core.ClassUnknown), baseTime); got != 0 {
		t.Errorf("score = %v, want 0 for a dropped unattributable signal", got)
	}
}

// TestFutureTimestampDoesNotInflate guards against clock skew manufacturing
// score. A signal stamped in the future must not be treated as "about to
// happen" and amplified.
func TestFutureTimestampDoesNotInflate(t *testing.T) {
	e := New(WithClock(fixedClock(baseTime)))
	dev := device(core.ClassUnknown)

	e.Observe(sig(core.SignalWeightTransfer, core.SignalReplicationRequired, 100), baseTime.Add(time.Hour))
	if got := e.Score(dev, baseTime); got > 100.01 {
		t.Errorf("score = %v, want <= 100: a future signal must not amplify", got)
	}
}

func TestEmptyEngineScoresZero(t *testing.T) {
	e := New(WithClock(fixedClock(baseTime)))
	dev := device(core.ClassCamera)

	a := e.Evaluate(dev, baseTime)
	if a.Score != 0 {
		t.Errorf("score = %v, want 0", a.Score)
	}
	if a.Tier != core.ContainmentMonitor {
		t.Errorf("tier = %q, want monitor", a.Tier)
	}
}

func TestRankedSortsByScoreDescending(t *testing.T) {
	e := New(WithClock(fixedClock(baseTime)))

	devs := []core.Device{
		{MAC: mac("aa:bb:cc:dd:ee:01"), Class: core.ClassCamera},
		{MAC: mac("aa:bb:cc:dd:ee:02"), Class: core.ClassCamera},
		{MAC: mac("aa:bb:cc:dd:ee:03"), Class: core.ClassCamera},
	}

	// Device 1: three kinds, heavy. Device 2: two kinds, light. Device 3: none.
	for _, k := range []core.SignalKind{core.SignalDNSDrift, core.SignalEastWestVolume, core.SignalWeightTransfer} {
		s := sig(k, core.SignalReplicationRequired, 40)
		s.DeviceMAC = mac("aa:bb:cc:dd:ee:01")
		e.Observe(s, baseTime)
	}
	for _, k := range []core.SignalKind{core.SignalDNSDrift, core.SignalBeacon} {
		s := sig(k, core.SignalPoCArtifact, 20)
		s.DeviceMAC = mac("aa:bb:cc:dd:ee:02")
		e.Observe(s, baseTime)
	}

	ranked := e.Ranked(devs, baseTime)
	if len(ranked) != 2 {
		t.Fatalf("Ranked returned %d devices, want 2 (the scored ones)", len(ranked))
	}
	if ranked[0].MAC.String() != "aa:bb:cc:dd:ee:01" {
		t.Errorf("first ranked = %v, want the highest scorer ee:01", ranked[0].MAC)
	}
	if ranked[0].Score <= ranked[1].Score {
		t.Errorf("scores not descending: %v then %v", ranked[0].Score, ranked[1].Score)
	}
}

// TestAssessmentCarriesReasonsForPortal checks the user-facing requirement: a
// person whose camera was just disconnected gets sentences, not a number.
func TestAssessmentCarriesReasonsForPortal(t *testing.T) {
	e := New(WithClock(fixedClock(baseTime)))
	dev := device(core.ClassCamera)

	s := sig(core.SignalModelHostOnIoT, core.SignalReplicationRequired, 40)
	s.Reason = "device contacted a model-hosting endpoint (huggingface.co)"
	e.Observe(s, baseTime)
	s2 := sig(core.SignalEastWestVolume, core.SignalReplicationRequired, 40)
	s2.Reason = "sustained peer volume"
	e.Observe(s2, baseTime)

	a := e.Evaluate(dev, baseTime)
	if len(a.Reasons) < 2 {
		t.Fatalf("Reasons = %v, want one per contributing signal", a.Reasons)
	}
	if a.Reasons[0] == "" {
		t.Error("highest-contribution reason must be non-empty and first")
	}
	// Reasons are ordered by contribution, so the heavier signal leads.
	if !strings.Contains(a.Reasons[0], "huggingface.co") {
		t.Errorf("first reason = %q, want the highest-weight signal", a.Reasons[0])
	}
}

// TestPruningBoundsMemory verifies observations past the horizon are dropped
// rather than retained forever, which matters on a sensor that runs for
// months.
func TestPruningBoundsMemory(t *testing.T) {
	e := New(WithClock(fixedClock(baseTime)))
	dev := device(core.ClassUnknown)

	e.Observe(sig(core.SignalWeightTransfer, core.SignalReplicationRequired, 10), baseTime)
	e.Observe(sig(core.SignalDNSDrift, core.SignalReplicationRequired, 10), baseTime)

	// Evaluate past the horizon. maxAge is 10 half-lives (720h); an age
	// strictly greater than that is pruned.
	e.Evaluate(dev, baseTime.Add(721*time.Hour))

	e.mu.Lock()
	n := len(e.seen[dev.MAC.String()])
	e.mu.Unlock()

	if n != 0 {
		t.Errorf("retained %d observations past the horizon, want 0", n)
	}
}

// TestRequireCorroborationCanBeDisabled documents the escape hatch without
// pretending it is safe: with corroboration off, a loud single signal can
// act. This is available for an operator who has tuned thresholds against
// their own network, and nowhere is it the default.
func TestRequireCorroborationCanBeDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequireCorroboration = false
	e := New(WithConfig(cfg), WithClock(fixedClock(baseTime)))
	dev := device(core.ClassCamera)

	e.Observe(sig(core.SignalWeightTransfer, core.SignalReplicationRequired, 100), baseTime)

	a := e.Evaluate(dev, baseTime)
	if a.Tier == core.ContainmentMonitor {
		t.Error("with corroboration disabled a single high score should escalate")
	}
}

// TestHalfLifeOptionPreservesCorroboration is the regression test for a bug
// that reached the CLI: setting only the half-life through the wholesale
// WithConfig path zeroed RequireCorroboration, letting a single signal
// escalate a device. The granular option must leave the safety defaults
// untouched.
func TestHalfLifeOptionPreservesCorroboration(t *testing.T) {
	e := New(WithHalfLife(12*time.Hour), WithClock(fixedClock(baseTime)))
	if e.cfg.HalfLife != 12*time.Hour {
		t.Fatalf("HalfLife = %v, want 12h", e.cfg.HalfLife)
	}
	if !e.cfg.RequireCorroboration {
		t.Fatal("WithHalfLife must not disable corroboration")
	}

	// And the property still holds at runtime: one signal, huge score, no
	// escalation.
	dev := device(core.ClassCamera)
	e.Observe(sig(core.SignalWeightTransfer, core.SignalReplicationRequired, 5000), baseTime)
	if a := e.Evaluate(dev, baseTime); a.Tier != core.ContainmentMonitor {
		t.Errorf("tier = %q, want monitor: corroboration must survive a half-life override", a.Tier)
	}
}

// TestZeroHalfLifeIgnored checks a zero duration is a no-op rather than
// something that would divide by zero in the decay kernel.
func TestZeroHalfLifeIgnored(t *testing.T) {
	e := New(WithHalfLife(0))
	if e.cfg.HalfLife != DefaultConfig().HalfLife {
		t.Errorf("HalfLife = %v, want the default", e.cfg.HalfLife)
	}
}

func TestDescribeIsHumanReadable(t *testing.T) {
	a := Assessment{
		MAC:           mac("aa:bb:cc:dd:ee:01"),
		Score:         72.5,
		Tier:          core.ContainmentQuarantined,
		DistinctKinds: 2,
		Corroborated:  true,
		Reasons:       []string{"device contacted a model-hosting endpoint (huggingface.co) (score 45.0)"},
	}
	got := a.Describe()
	if !strings.Contains(got, "aa:bb:cc:dd:ee:01") || !strings.Contains(got, "quarantined") {
		t.Errorf("Describe() = %q, want MAC and tier", got)
	}
	if !strings.Contains(got, "huggingface.co") {
		t.Errorf("Describe() = %q, want the reason rendered", got)
	}
}
