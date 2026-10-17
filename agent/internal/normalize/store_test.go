package normalize

import (
	"testing"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/feeds"
)

func domain(value string, conf int, expires time.Time) IoC {
	return IoC{Value: value, Kind: feeds.KindDomain, Confidence: conf, Feeds: []string{"f"}, Expires: expires}
}

func TestStoreMatchExactAndSubdomain(t *testing.T) {
	s := NewStore(0)
	s.Replace("f", []IoC{domain("evil.example", 75, testNow.Add(time.Hour))})

	tests := []struct {
		name string
		want bool
	}{
		{"evil.example", true},
		{"a.evil.example", true},
		{"deep.a.evil.example", true},
		{"EVIL.EXAMPLE.", true}, // canonicalized like the resolver does
		{"notevil.example", false},
		{"evil.example.org", false},
		{"", false},
	}
	for _, tt := range tests {
		if _, ok := s.Match(tt.name, testNow); ok != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.name, ok, tt.want)
		}
	}
}

func TestStoreMatchConfidenceGateAppliesToMatchingNotStorage(t *testing.T) {
	iocs := []IoC{domain("weak.example", 50, testNow.Add(time.Hour))}

	gated := NewStore(75)
	gated.Replace("f", iocs)
	if _, ok := gated.Match("weak.example", testNow); ok {
		t.Error("min-confidence 75 matched a 50-confidence indicator")
	}
	if gated.Count(testNow) != 1 {
		t.Errorf("Count = %d, want 1: the value is stored, only matching is gated", gated.Count(testNow))
	}

	open := NewStore(0)
	open.Replace("f", iocs)
	if _, ok := open.Match("weak.example", testNow); !ok {
		t.Error("min-confidence 0 did not match a 50-confidence indicator")
	}
}

func TestStoreMatchSkipsExpired(t *testing.T) {
	s := NewStore(0)
	s.Replace("f", []IoC{domain("gone.example", 75, testNow.Add(-time.Second))})

	if _, ok := s.Match("gone.example", testNow); ok {
		t.Error("Match returned an expired indicator")
	}
	if s.Count(testNow) != 0 {
		t.Errorf("Count = %d, want 0 (expired)", s.Count(testNow))
	}

	s.Replace("f", []IoC{domain("live.example", 75, testNow.Add(time.Second))})
	if _, ok := s.Match("live.example", testNow); !ok {
		t.Error("Match missed a live indicator")
	}
	if s.Count(testNow) != 1 {
		t.Errorf("Count = %d, want 1", s.Count(testNow))
	}
}

func TestStorePruneRemovesExpiredSnapshots(t *testing.T) {
	s := NewStore(0)
	s.Replace("f", []IoC{
		domain("old.example", 75, testNow.Add(-time.Hour)),
		domain("new.example", 75, testNow.Add(time.Hour)),
	})
	s.Prune(testNow)

	if got := len(s.snapshots["f"]); got != 1 {
		t.Errorf("snapshot has %d entries after prune, want 1", got)
	}
	if s.CountFeed("f", testNow) != 1 {
		t.Errorf("CountFeed = %d, want 1", s.CountFeed("f", testNow))
	}
}

func TestStoreReplaceSwapsTheWholeSnapshot(t *testing.T) {
	s := NewStore(0)
	s.Replace("f", []IoC{domain("first.example", 75, testNow.Add(time.Hour))})
	if _, ok := s.Match("first.example", testNow); !ok {
		t.Fatal("first snapshot not visible")
	}

	s.Replace("f", []IoC{domain("second.example", 75, testNow.Add(time.Hour))})
	if _, ok := s.Match("first.example", testNow); ok {
		t.Error("value the feed stopped publishing still matches")
	}
	if _, ok := s.Match("second.example", testNow); !ok {
		t.Error("new snapshot not visible")
	}
}

func TestStoreMatchPrefersExactOverSuffix(t *testing.T) {
	s := NewStore(0)
	s.Replace("f", []IoC{
		domain("evil.example", 40, testNow.Add(time.Hour)),
		domain("a.evil.example", 90, testNow.Add(time.Hour)),
	})

	got, ok := s.Match("a.evil.example", testNow)
	if !ok {
		t.Fatal("Match missed a covered name")
	}
	// The exact indicator is what the operator listed; suffix coverage on a
	// bolder confidence must not outvote it.
	if got.Value != "a.evil.example" {
		t.Errorf("matched %q, want exact a.evil.example", got.Value)
	}
}

func TestStoreMatchPrefersHigherConfidenceAtEqualExactness(t *testing.T) {
	s := NewStore(0)
	s.Replace("threatfox", []IoC{domain("evil.example", 40, testNow.Add(time.Hour))})
	s.Replace("urlhaus", []IoC{domain("evil.example", 75, testNow.Add(time.Hour))})

	got, ok := s.Match("evil.example", testNow)
	if !ok {
		t.Fatal("Match missed an exact indicator")
	}
	if got.Confidence != 75 {
		t.Errorf("matched confidence %d, want 75 (the braver feed wins)", got.Confidence)
	}
}

func TestStoreIndependentFeedsDoNotClobber(t *testing.T) {
	s := NewStore(0)
	s.Replace("threatfox", []IoC{domain("tf.example", 75, testNow.Add(time.Hour))})
	s.Replace("urlhaus", []IoC{domain("uh.example", 50, testNow.Add(time.Hour))})

	if _, ok := s.Match("tf.example", testNow); !ok {
		t.Error("threatfox snapshot missing")
	}
	if _, ok := s.Match("uh.example", testNow); !ok {
		t.Error("urlhaus snapshot missing")
	}
	if s.CountFeed("threatfox", testNow) != 1 || s.CountFeed("urlhaus", testNow) != 1 {
		t.Errorf("Counts = %d, %d; want 1, 1", s.CountFeed("threatfox", testNow), s.CountFeed("urlhaus", testNow))
	}
}
