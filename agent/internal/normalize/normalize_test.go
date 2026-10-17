package normalize

import (
	"testing"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/feeds"
)

var testNow = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

func TestNormalizeMergesDuplicatesAcrossFeeds(t *testing.T) {
	items := []feeds.Item{
		{
			Value: "c2.evil.example", Kind: feeds.KindDomain, Feed: "threatfox",
			Confidence: 75, Tags: []string{"mirai"},
			FirstSeen: time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC),
		},
		{
			Value: "c2.evil.example", Kind: feeds.KindDomain, Feed: "urlhaus",
			Confidence: 50, Tags: []string{"MIRAI", "elf"},
			FirstSeen: time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC),
		},
	}

	got := Normalize(items, testNow, 72*time.Hour)
	if len(got) != 1 {
		t.Fatalf("got %d indicators, want 1", len(got))
	}
	ioc := got[0]
	if ioc.Confidence != 75 {
		t.Errorf("Confidence = %d, want 75 (max of contributors)", ioc.Confidence)
	}
	if len(ioc.Feeds) != 2 || ioc.Feeds[0] != "threatfox" || ioc.Feeds[1] != "urlhaus" {
		t.Errorf("Feeds = %v, want [threatfox urlhaus]", ioc.Feeds)
	}
	// Case-insensitive union: one "mirai", not two.
	if len(ioc.Tags) != 2 || ioc.Tags[0] != "mirai" || ioc.Tags[1] != "elf" {
		t.Errorf("Tags = %v, want [mirai elf]", ioc.Tags)
	}
	wantSeen := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	if !ioc.FirstSeen.Equal(wantSeen) {
		t.Errorf("FirstSeen = %v, want earliest %v", ioc.FirstSeen, wantSeen)
	}
	if want := testNow.Add(72 * time.Hour); !ioc.Expires.Equal(want) {
		t.Errorf("Expires = %v, want %v", ioc.Expires, want)
	}
}

func TestNormalizeKeepsSameValueDifferentKindsSeparate(t *testing.T) {
	items := []feeds.Item{
		{Value: "203.0.113.9", Kind: feeds.KindIP, Feed: "threatfox", Confidence: 50},
		{Value: "203.0.113.9", Kind: feeds.KindDomain, Feed: "urlhaus", Confidence: 50},
	}

	got := Normalize(items, testNow, time.Hour)
	if len(got) != 2 {
		t.Fatalf("got %d indicators, want 2 (kinds do not merge)", len(got))
	}
}

func TestNormalizeSortsDeterministically(t *testing.T) {
	items := []feeds.Item{
		{Value: "z.example", Kind: feeds.KindDomain, Feed: "a", Confidence: 1},
		{Value: "CVE-2025-0001", Kind: feeds.KindCVE, Feed: "a", Confidence: 1},
		{Value: "a.example", Kind: feeds.KindDomain, Feed: "a", Confidence: 1},
		{Value: "192.0.2.9", Kind: feeds.KindIP, Feed: "a", Confidence: 1},
	}

	got := Normalize(items, testNow, time.Hour)
	wantOrder := []struct {
		kind  feeds.Kind
		value string
	}{
		{feeds.KindCVE, "CVE-2025-0001"},
		{feeds.KindDomain, "a.example"},
		{feeds.KindDomain, "z.example"},
		{feeds.KindIP, "192.0.2.9"},
	}
	if len(got) != len(wantOrder) {
		t.Fatalf("got %d indicators, want %d", len(got), len(wantOrder))
	}
	for i, w := range wantOrder {
		if got[i].Kind != w.kind || got[i].Value != w.value {
			t.Errorf("got[%d] = %s/%s, want %s/%s", i, got[i].Kind, got[i].Value, w.kind, w.value)
		}
	}
}

func TestNormalizeDropsEmptyAndClampsConfidence(t *testing.T) {
	items := []feeds.Item{
		{Value: "", Kind: feeds.KindDomain, Feed: "a", Confidence: 90},
		{Value: "ok.example", Kind: feeds.KindDomain, Feed: "a", Confidence: -3},
		{Value: "high.example", Kind: feeds.KindDomain, Feed: "a", Confidence: 500},
	}

	got := Normalize(items, testNow, time.Hour)
	if len(got) != 2 {
		t.Fatalf("got %d indicators, want 2", len(got))
	}
	// Sorted: high.example (clamped to 100) then ok.example (clamped to 0).
	if got[0].Value != "high.example" || got[0].Confidence != 100 {
		t.Errorf("got[0] = %s/%d, want high.example/100", got[0].Value, got[0].Confidence)
	}
	if got[1].Value != "ok.example" || got[1].Confidence != 0 {
		t.Errorf("got[1] = %s/%d, want ok.example/0", got[1].Value, got[1].Confidence)
	}
}
