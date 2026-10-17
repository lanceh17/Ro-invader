package dns

// This file is the seam the rest of the suite does not cross: a feed pulled
// over HTTP, normalized, stored, and then consulted by the resolver through
// the Blocked predicate — the exact path a live query takes, with the only
// substitution being a fixture server standing in for abuse.ch.

import (
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
	"github.com/lanceh17/Ro-invader/agent/internal/feeds"
	"github.com/lanceh17/Ro-invader/agent/internal/normalize"
)

func TestFeedIndicatorBlocksThroughHandle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Auth-Key") != "integration-key" {
			t.Errorf("Auth-Key = %q, want integration-key", r.Header.Get("Auth-Key"))
		}
		w.Write([]byte(`{
			"query_status": "ok",
			"data": [
				{"ioc": "c2.integration.example", "ioc_type": "domain", "confidence_level": 80, "first_seen": "2026-10-16 00:00:00 UTC"}
			]
		}`))
	}))
	defer srv.Close()

	puller := feeds.NewThreatFox("integration-key")
	puller.Endpoint = srv.URL

	items, err := puller.Pull(context.Background())
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if len(items) != 1 || items[0].Value != "c2.integration.example" {
		t.Fatalf("items = %+v, want the one fixture indicator", items)
	}

	store := normalize.NewStore(0)
	store.Replace(puller.Name(), normalize.Normalize(items, time.Now(), time.Hour))

	var called bool
	var gotAction Action
	s := testServer(t, Config{
		Blocked: func(name string) bool {
			_, ok := store.Match(name, time.Now())
			return ok
		},
		OnQuery: func(_ core.NormalizedEvent, a Action) { gotAction = a },
	}, okForward(&called))

	resp := s.Handle(buildQuery(t, "c2.integration.example", TypeA), testClient)
	if called {
		t.Error("a feed-listed name was forwarded upstream")
	}
	if rcode := uint8(binary.BigEndian.Uint16(resp[2:4]) & 0x000F); rcode != RCodeNameErr {
		t.Errorf("RCODE = %d, want NXDOMAIN for a feed-listed name", rcode)
	}
	if gotAction != ActionNXDomain {
		t.Errorf("OnQuery action = %v, want nxdomain (what the audit records)", gotAction)
	}

	// Subdomain coverage: "a feed listed evil.example" must block its
	// subdomains too, which is how blocklists actually work.
	s.Handle(buildQuery(t, "sub.c2.integration.example", TypeA), testClient)
	if called {
		t.Error("a subdomain of a feed-listed name was forwarded upstream")
	}

	// An ordinary name is untouched by the blocklist.
	s.Handle(buildQuery(t, "ordinary.example", TypeA), testClient)
	if !called {
		t.Error("an unlisted name must still forward")
	}
}
