package feeds

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fixtureServer serves body for every request and fails the test on any
// request arriving after the server is closed. Handlers that also record
// method, path, and headers are written per test, because the request shape
// is part of each provider's contract.
func fixtureServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

const threatFoxFixture = `{
    "query_status": "ok",
    "data": [
        {
            "ioc": "C2.Evil-Example.COM",
            "ioc_type": "domain",
            "confidence_level": 75,
            "first_seen": "2026-10-15 08:00:00 UTC",
            "tags": ["mirai", "elf"]
        },
        {
            "ioc": "203.0.113.66:443",
            "ioc_type": "ip:port",
            "confidence_level": 50,
            "first_seen": "2026-10-16 09:30:00 UTC",
            "tags": null
        },
        {
            "ioc": "http://Drop.Bad-Host.example:8080/gate",
            "ioc_type": "url",
            "confidence_level": 100,
            "first_seen": "2026-10-16 10:00:00 UTC",
            "tags": ["botnet_cc"]
        },
        {
            "ioc": "d41d8cd98f00b204e9800998ecf8427e",
            "ioc_type": "md5",
            "confidence_level": 100,
            "first_seen": "2026-10-16 10:00:00 UTC"
        },
        {
            "ioc": "not a domain",
            "ioc_type": "domain",
            "confidence_level": 75,
            "first_seen": "2026-10-16 10:00:00 UTC"
        }
    ]
}`

func TestThreatFoxPullParsesItems(t *testing.T) {
	var gotMethod, gotAuth, gotContentType, gotBody string
	srv := fixtureServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Auth-Key")
		gotContentType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Write([]byte(threatFoxFixture))
	})

	p := NewThreatFox("test-key-123")
	p.Endpoint = srv.URL

	items, err := p.Pull(context.Background())
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %s, want POST", gotMethod)
	}
	if gotAuth != "test-key-123" {
		t.Errorf("Auth-Key = %q, want test-key-123", gotAuth)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}
	var req map[string]any
	if err := json.Unmarshal([]byte(gotBody), &req); err != nil {
		t.Fatalf("request body is not JSON: %v", err)
	}
	if req["query"] != "get_iocs" {
		t.Errorf("query = %v, want get_iocs", req["query"])
	}
	if days, _ := req["days"].(float64); days != 3 {
		t.Errorf("days = %v, want 3", req["days"])
	}

	// Hash rows and unparseable rows are dropped; three rows survive.
	if len(items) != 3 {
		t.Fatalf("got %d items, want 3: %+v", len(items), items)
	}

	domain := items[0]
	if domain.Value != "c2.evil-example.com" {
		t.Errorf("domain value = %q, want c2.evil-example.com", domain.Value)
	}
	if domain.Kind != KindDomain {
		t.Errorf("domain kind = %q, want domain", domain.Kind)
	}
	if domain.Feed != "threatfox" {
		t.Errorf("domain feed = %q, want threatfox", domain.Feed)
	}
	if domain.Confidence != 75 {
		t.Errorf("domain confidence = %d, want 75", domain.Confidence)
	}
	if len(domain.Tags) != 2 || domain.Tags[0] != "mirai" {
		t.Errorf("domain tags = %v, want [mirai elf]", domain.Tags)
	}
	wantSeen := time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)
	if !domain.FirstSeen.Equal(wantSeen) {
		t.Errorf("domain FirstSeen = %v, want %v", domain.FirstSeen, wantSeen)
	}

	ip := items[1]
	if ip.Value != "203.0.113.66" || ip.Kind != KindIP {
		t.Errorf("ip item = %s/%s, want 203.0.113.66/ip", ip.Value, ip.Kind)
	}
	if ip.Confidence != 50 {
		t.Errorf("ip confidence = %d, want 50", ip.Confidence)
	}

	fromURL := items[2]
	if fromURL.Value != "drop.bad-host.example" || fromURL.Kind != KindDomain {
		t.Errorf("url-derived item = %s/%s, want drop.bad-host.example/domain", fromURL.Value, fromURL.Kind)
	}
	if fromURL.Confidence != 100 {
		t.Errorf("url-derived confidence = %d, want 100", fromURL.Confidence)
	}
}

func TestThreatFoxNoResultsIsEmptyNotError(t *testing.T) {
	srv := fixtureServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"query_status": "no_results"}`))
	})
	p := NewThreatFox("k")
	p.Endpoint = srv.URL

	items, err := p.Pull(context.Background())
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if len(items) != 0 {
		t.Errorf("got %d items, want 0", len(items))
	}
}

func TestThreatFoxMissingKeyFailsWithVariableName(t *testing.T) {
	srv := fixtureServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request should reach the endpoint without a key")
	})
	p := NewThreatFox("")
	p.Endpoint = srv.URL

	_, err := p.Pull(context.Background())
	if err == nil {
		t.Fatal("Pull succeeded without an Auth-Key")
	}
	if !strings.Contains(err.Error(), "R0_ABUSECH_KEY") {
		t.Errorf("error %q does not name R0_ABUSECH_KEY", err)
	}
}

func TestThreatFoxStatusErrorSurfaces(t *testing.T) {
	srv := fixtureServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"query_status": "unauthorized"}`))
	})
	p := NewThreatFox("bad")
	p.Endpoint = srv.URL

	_, err := p.Pull(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("error = %v, want it to mention unauthorized", err)
	}
}

func TestThreatFoxHTTPFailureSurfaces(t *testing.T) {
	srv := fixtureServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "go away", http.StatusServiceUnavailable)
	})
	p := NewThreatFox("k")
	p.Endpoint = srv.URL

	_, err := p.Pull(context.Background())
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("error = %v, want it to mention status 503", err)
	}
}

const urlhausFixture = `{
    "query_status": "ok",
    "urls": [
        {
            "url": "http://c2.corroborated.example/gate",
            "host": "c2.corroborated.example",
            "date_added": "2026-10-14 12:00:00 UTC",
            "threat": "malware_download",
            "tags": ["mirai"],
            "blacklists": {"spamhaus_dbl": "botnet_cc_domain", "surbl": "listed"}
        },
        {
            "url": "http://198.51.100.9/payload.elf",
            "host": "198.51.100.9",
            "date_added": "2026-10-15 06:30:00 UTC",
            "threat": "malware_download",
            "tags": ["elf"],
            "blacklists": {"spamhaus_dbl": "not listed", "surbl": "not listed"}
        },
        {
            "url": "http://OnlyFrom.Url.example/dropper",
            "host": "",
            "date_added": "2026-10-16 01:00:00 UTC",
            "threat": "malware_download",
            "tags": null,
            "blacklists": {"spamhaus_dbl": "abused_legit_malware", "surbl": "not listed"}
        },
        {
            "url": "not-a-url",
            "host": "",
            "date_added": "2026-10-16 02:00:00 UTC",
            "threat": "malware_download"
        }
    ]
}`

func TestURLhausPullParsesItems(t *testing.T) {
	var gotMethod, gotAuth string
	srv := fixtureServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Auth-Key")
		w.Write([]byte(urlhausFixture))
	})

	p := NewURLhaus("haus-key")
	p.Endpoint = srv.URL

	items, err := p.Pull(context.Background())
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method = %s, want GET", gotMethod)
	}
	if gotAuth != "haus-key" {
		t.Errorf("Auth-Key = %q, want haus-key", gotAuth)
	}
	if len(items) != 3 {
		t.Fatalf("got %d items, want 3: %+v", len(items), items)
	}

	// Listed on two independent blocklists: 50 baseline + 25 + 25.
	c2 := items[0]
	if c2.Value != "c2.corroborated.example" || c2.Kind != KindDomain {
		t.Errorf("item = %s/%s, want c2.corroborated.example/domain", c2.Value, c2.Kind)
	}
	if c2.Confidence != 100 {
		t.Errorf("corroborated confidence = %d, want 100", c2.Confidence)
	}
	// The feed's threat field rides ahead of its own tags.
	if len(c2.Tags) < 2 || c2.Tags[0] != "malware_download" || c2.Tags[1] != "mirai" {
		t.Errorf("tags = %v, want malware_download first then mirai", c2.Tags)
	}

	unlisted := items[1]
	if unlisted.Value != "198.51.100.9" || unlisted.Kind != KindIP {
		t.Errorf("item = %s/%s, want 198.51.100.9/ip", unlisted.Value, unlisted.Kind)
	}
	if unlisted.Confidence != 50 {
		t.Errorf("unlisted confidence = %d, want 50 baseline", unlisted.Confidence)
	}

	// Empty host falls back to the URL; one listed blacklist is +25.
	fallback := items[2]
	if fallback.Value != "onlyfrom.url.example" || fallback.Kind != KindDomain {
		t.Errorf("item = %s/%s, want onlyfrom.url.example/domain", fallback.Value, fallback.Kind)
	}
	if fallback.Confidence != 75 {
		t.Errorf("partly corroborated confidence = %d, want 75", fallback.Confidence)
	}
}

func TestURLhausNoResultsIsEmptyNotError(t *testing.T) {
	srv := fixtureServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"query_status": "no_results"}`))
	})
	p := NewURLhaus("k")
	p.Endpoint = srv.URL

	items, err := p.Pull(context.Background())
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if len(items) != 0 {
		t.Errorf("got %d items, want 0", len(items))
	}
}

const kevFixture = `{
    "catalogVersion": "2026.10.16",
    "dateReleased": "2026-10-16T17:15:48.8752Z",
    "count": 3,
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-102764",
            "vendorProject": "BeyondTrust",
            "product": "Remote Support",
            "dateAdded": "2026-10-16",
            "shortDescription": "Authentication bypass."
        },
        {
            "cveID": "cve-2025-0001",
            "vendorProject": "Acme",
            "product": "Widget",
            "dateAdded": "2026-01-02"
        },
        {
            "cveID": "not-a-cve",
            "vendorProject": "Bad",
            "product": "Row",
            "dateAdded": "2026-01-02"
        }
    ]
}`

func TestKEVPullParsesCatalog(t *testing.T) {
	var gotMethod, gotAuth string
	srv := fixtureServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Auth-Key")
		w.Write([]byte(kevFixture))
	})

	p := NewKev()
	p.Endpoint = srv.URL

	items, err := p.Pull(context.Background())
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method = %s, want GET", gotMethod)
	}
	if gotAuth != "" {
		t.Errorf("Auth-Key = %q, want none (KEV needs no key)", gotAuth)
	}
	if len(items) != 2 {
		t.Fatalf("got %d items, want 2: %+v", len(items), items)
	}

	first := items[0]
	if first.Value != "CVE-2026-102764" || first.Kind != KindCVE {
		t.Errorf("item = %s/%s, want CVE-2026-102764/cve", first.Value, first.Kind)
	}
	if first.Feed != "kev" {
		t.Errorf("feed = %q, want kev", first.Feed)
	}
	if first.Confidence != 100 {
		t.Errorf("confidence = %d, want 100", first.Confidence)
	}
	if len(first.Tags) != 2 || first.Tags[0] != "BeyondTrust" || first.Tags[1] != "Remote Support" {
		t.Errorf("tags = %v, want [BeyondTrust Remote Support]", first.Tags)
	}
	wantSeen := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)
	if !first.FirstSeen.Equal(wantSeen) {
		t.Errorf("FirstSeen = %v, want %v", first.FirstSeen, wantSeen)
	}

	// Lowercase identifiers are canonicalized; non-CVE rows are dropped.
	if items[1].Value != "CVE-2025-0001" {
		t.Errorf("second value = %q, want CVE-2025-0001", items[1].Value)
	}
}

func TestCanonicalization(t *testing.T) {
	tests := []struct {
		name string
		fn   func(string) (string, bool)
		in   string
		want string
		ok   bool
	}{
		{"domain lowercases and trims root dot", canonicalDomain, "EXAMPLE.Com.", "example.com", true},
		{"domain rejects dotless", canonicalDomain, "localhost", "", false},
		{"domain rejects spaces", canonicalDomain, "bad host.example", "", false},
		{"domain rejects an address", canonicalDomain, "192.0.2.1", "", false},
		{"ip keeps a bare IPv6 address", canonicalIP, "2001:db8::1", "2001:db8::1", true},
		{"ip unmaps an IPv4-mapped IPv6 address", canonicalIP, "::ffff:192.0.2.1", "192.0.2.1", true},
		{"ip rejects a port", canonicalIP, "192.0.2.1:443", "", false},
		{"ip rejects a name", canonicalIP, "example.com", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := tt.fn(tt.in)
			if got != tt.want || ok != tt.ok {
				t.Errorf("(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestClampConfidence(t *testing.T) {
	for in, want := range map[int]int{-5: 0, 0: 0, 75: 75, 100: 100, 101: 100} {
		if got := clampConfidence(in); got != want {
			t.Errorf("clampConfidence(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestParseFeedTimeBadValueIsZero(t *testing.T) {
	if ts := parseFeedTime("yesterday-ish"); !ts.IsZero() {
		t.Errorf("parseFeedTime(bad) = %v, want zero", ts)
	}
	if ts := parseFeedTime(""); !ts.IsZero() {
		t.Errorf("parseFeedTime(empty) = %v, want zero", ts)
	}
}
