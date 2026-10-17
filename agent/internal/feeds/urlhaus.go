package feeds

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// defaultURLhausEndpoint is the recent-additions feed documented at
// https://urlhaus-api.abuse.ch/ — the last three days, at most 1000 rows.
// It requires the same Auth-Key header as ThreatFox.
const defaultURLhausEndpoint = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

// URLhaus pulls recent malware URLs from abuse.ch URLhaus and reduces them
// to the hosts they are served from, which is what DNS policy can answer on.
type URLhaus struct {
	// Endpoint is the API URL. Tests point it at a local fixture server.
	Endpoint string
	// AuthKey is sent in the Auth-Key header. Required by the API.
	AuthKey string
	// HTTP is the client used for the round trip; nil uses a default.
	HTTP *http.Client
}

// NewURLhaus returns a puller for the production endpoint.
func NewURLhaus(authKey string) *URLhaus {
	return &URLhaus{Endpoint: defaultURLhausEndpoint, AuthKey: authKey, HTTP: newClient()}
}

func (u *URLhaus) Name() string { return "urlhaus" }

// Pull fetches recent additions and parses them.
func (u *URLhaus) Pull(ctx context.Context) ([]Item, error) {
	if u.AuthKey == "" {
		return nil, fmt.Errorf("urlhaus: no Auth-Key (set R0_ABUSECH_KEY)")
	}
	client := u.HTTP
	if client == nil {
		client = newClient()
	}
	raw, err := get(ctx, client, u.Endpoint, u.AuthKey)
	if err != nil {
		return nil, fmt.Errorf("urlhaus: %w", err)
	}
	return parseURLhaus(raw)
}

type urlhausResponse struct {
	QueryStatus string         `json:"query_status"`
	URLs        []urlhausEntry `json:"urls"`
}

type urlhausEntry struct {
	URL        string            `json:"url"`
	Host       string            `json:"host"`
	DateAdded  string            `json:"date_added"`
	Threat     string            `json:"threat"`
	Tags       []string          `json:"tags"`
	Blacklists map[string]string `json:"blacklists"`
}

func parseURLhaus(raw []byte) ([]Item, error) {
	var resp urlhausResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("urlhaus: parsing response: %w", err)
	}
	switch resp.QueryStatus {
	case "ok":
	case "no_results":
		return nil, nil
	default:
		return nil, fmt.Errorf("urlhaus: query_status %q", resp.QueryStatus)
	}

	items := make([]Item, 0, len(resp.URLs))
	for _, row := range resp.URLs {
		value, kind, ok := urlhausHost(row)
		if !ok {
			continue
		}
		tags := row.Tags
		if row.Threat != "" {
			tags = append([]string{row.Threat}, tags...)
		}
		items = append(items, Item{
			Value:      value,
			Kind:       kind,
			Feed:       "urlhaus",
			Confidence: urlhausConfidence(row),
			Tags:       tags,
			FirstSeen:  parseFeedTime(row.DateAdded),
		})
	}
	return items, nil
}

// urlhausHost prefers the host field URLhaus extracted and falls back to
// parsing the URL itself, because entries have shipped with an empty host.
func urlhausHost(row urlhausEntry) (string, Kind, bool) {
	if ip, ok := canonicalIP(row.Host); ok {
		return ip, KindIP, true
	}
	if name, ok := canonicalDomain(row.Host); ok {
		return name, KindDomain, true
	}
	if row.Host == "" {
		return hostFromURL(row.URL)
	}
	return "", "", false
}

// urlhausConfidence derives a 0-100 estimate for a feed that publishes none.
// The baseline of 50 matches ThreatFox's own default for an unvetted row.
// A row that a second independent blocklist (Spamhaus DBL or SURBL) also
// lists is corroborated and scores higher, which is the same two-source
// rule the risk engine applies to devices, applied to indicators.
func urlhausConfidence(row urlhausEntry) int {
	conf := 50
	if listed(row.Blacklists["spamhaus_dbl"]) {
		conf += 25
	}
	if listed(row.Blacklists["surbl"]) {
		conf += 25
	}
	return conf
}

func listed(status string) bool {
	switch status {
	case "", "not listed":
		return false
	}
	return true
}
