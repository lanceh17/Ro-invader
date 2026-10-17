package feeds

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// defaultThreatFoxEndpoint is the community API documented at
// https://threatfox.abuse.ch/api/. It requires an Auth-Key header; keys are
// free from the abuse.ch authentication portal and are read from the
// environment (SAFETY.md section 4), never from config files or code.
const defaultThreatFoxEndpoint = "https://threatfox-api.abuse.ch/api/v1/"

// ThreatFox pulls recent indicators from abuse.ch ThreatFox: botnet C2
// domains, addresses, and URLs.
type ThreatFox struct {
	// Endpoint is the API URL. Tests point it at a local fixture server.
	Endpoint string
	// Days is the get_iocs lookback, clamped to the API's 1-7 range.
	Days int
	// AuthKey is sent in the Auth-Key header. Required by the API.
	AuthKey string
	// HTTP is the client used for the round trip; nil uses a default.
	HTTP *http.Client
}

// NewThreatFox returns a puller for the production endpoint. The key comes
// from the caller (serve reads the environment); an empty key makes Pull
// fail with a message that names the variable rather than getting a 401
// from the API that says nothing about what to do.
func NewThreatFox(authKey string) *ThreatFox {
	return &ThreatFox{Endpoint: defaultThreatFoxEndpoint, Days: 3, AuthKey: authKey, HTTP: newClient()}
}

func (t *ThreatFox) Name() string { return "threatfox" }

// Pull fetches the get_iocs window and parses it. Rows whose ioc_type is a
// file hash are skipped: DNS policy has no way to act on them, and storing
// them would imply a consumer that does not exist.
func (t *ThreatFox) Pull(ctx context.Context) ([]Item, error) {
	if t.AuthKey == "" {
		return nil, fmt.Errorf("threatfox: no Auth-Key (set R0_ABUSECH_KEY)")
	}
	days := t.Days
	if days < 1 || days > 7 {
		days = 3
	}
	body, err := json.Marshal(map[string]any{"query": "get_iocs", "days": days})
	if err != nil {
		return nil, fmt.Errorf("threatfox: encoding request: %w", err)
	}
	client := t.HTTP
	if client == nil {
		client = newClient()
	}
	raw, err := post(ctx, client, t.Endpoint, t.AuthKey, body)
	if err != nil {
		return nil, fmt.Errorf("threatfox: %w", err)
	}
	return parseThreatFox(raw)
}

type threatFoxResponse struct {
	QueryStatus string          `json:"query_status"`
	Data        []threatFoxItem `json:"data"`
}

type threatFoxItem struct {
	IOC             string   `json:"ioc"`
	IOCType         string   `json:"ioc_type"`
	ConfidenceLevel int      `json:"confidence_level"`
	FirstSeen       string   `json:"first_seen"`
	Tags            []string `json:"tags"`
}

func parseThreatFox(raw []byte) ([]Item, error) {
	var resp threatFoxResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("threatfox: parsing response: %w", err)
	}
	switch resp.QueryStatus {
	case "ok":
	case "no_results":
		return nil, nil
	default:
		return nil, fmt.Errorf("threatfox: query_status %q", resp.QueryStatus)
	}

	items := make([]Item, 0, len(resp.Data))
	for _, row := range resp.Data {
		value, kind, ok := threatFoxValue(row.IOC, row.IOCType)
		if !ok {
			continue
		}
		items = append(items, Item{
			Value:      value,
			Kind:       kind,
			Feed:       "threatfox",
			Confidence: clampConfidence(row.ConfidenceLevel),
			Tags:       row.Tags,
			FirstSeen:  parseFeedTime(row.FirstSeen),
		})
	}
	return items, nil
}

// threatFoxValue resolves a feed row's value according to its ioc_type.
// "ip:port" carries the destination port DNS never sees, and "url" wraps a
// host the resolver would have to answer for anyway.
func threatFoxValue(raw, kind string) (string, Kind, bool) {
	switch kind {
	case "domain":
		if name, ok := canonicalDomain(raw); ok {
			return name, KindDomain, true
		}
		return "", "", false
	case "ip:port":
		host, _, err := net.SplitHostPort(strings.TrimSpace(raw))
		if err != nil {
			host = raw
		}
		if ip, ok := canonicalIP(host); ok {
			return ip, KindIP, true
		}
		return "", "", false
	case "url":
		if host, k, ok := hostFromURL(raw); ok {
			return host, k, true
		}
		return "", "", false
	default:
		// Hashes and other non-address types are intentionally dropped.
		return "", "", false
	}
}

// clampConfidence keeps a hostile or broken field inside the documented
// 0-100 range rather than letting it decide policy out of bounds.
func clampConfidence(c int) int {
	if c < 0 {
		return 0
	}
	if c > 100 {
		return 100
	}
	return c
}

// parseFeedTime reads the abuse.ch timestamp format
// ("2020-12-08 13:36:27 UTC") and the bare date format CISA uses
// ("2026-10-16"). A row with an unparseable date keeps a zero FirstSeen:
// the indicator is still valid, only its provenance is incomplete.
func parseFeedTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse("2006-01-02 15:04:05 MST", s); err == nil {
		return t.UTC()
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC()
	}
	return time.Time{}
}
