package feeds

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// defaultKEVEndpoint is CISA's Known Exploited Vulnerabilities catalog, a
// plain JSON file with no authentication. Its license terms allow
// redistribution and reuse, and it is vendor data rather than a derived
// blocklist, which keeps it clear of the GPL blocklist traps in
// SAFETY.md section 4.
const defaultKEVEndpoint = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// Kev pulls CISA's Known Exploited Vulnerabilities catalog. The items are
// CVE identifiers, not domains or addresses: nothing in DNS policy acts on
// them yet. They are pulled now so the inventory can later join a device's
// vendor and product against vulnerabilities CISA says are exploited in the
// wild, without a second data source landing in the codebase then.
type Kev struct {
	// Endpoint is the catalog URL. Tests point it at a local fixture server.
	Endpoint string
	// HTTP is the client used for the round trip; nil uses a default.
	HTTP *http.Client
}

// NewKev returns a puller for the production catalog.
func NewKev() *Kev {
	return &Kev{Endpoint: defaultKEVEndpoint, HTTP: newClient()}
}

func (k *Kev) Name() string { return "kev" }

// Pull fetches the catalog and parses it.
func (k *Kev) Pull(ctx context.Context) ([]Item, error) {
	client := k.HTTP
	if client == nil {
		client = newClient()
	}
	raw, err := get(ctx, client, k.Endpoint, "")
	if err != nil {
		return nil, fmt.Errorf("kev: %w", err)
	}
	return parseKEV(raw)
}

type kevCatalog struct {
	Vulnerabilities []kevEntry `json:"vulnerabilities"`
}

type kevEntry struct {
	CVEID         string `json:"cveID"`
	VendorProject string `json:"vendorProject"`
	Product       string `json:"product"`
	DateAdded     string `json:"dateAdded"`
}

func parseKEV(raw []byte) ([]Item, error) {
	var cat kevCatalog
	if err := json.Unmarshal(raw, &cat); err != nil {
		return nil, fmt.Errorf("kev: parsing catalog: %w", err)
	}

	items := make([]Item, 0, len(cat.Vulnerabilities))
	for _, row := range cat.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(row.CVEID))
		if !strings.HasPrefix(id, "CVE-") || len(id) < len("CVE-")+4 {
			continue
		}
		var tags []string
		if v := strings.TrimSpace(row.VendorProject); v != "" {
			tags = append(tags, v)
		}
		if p := strings.TrimSpace(row.Product); p != "" {
			tags = append(tags, p)
		}
		items = append(items, Item{
			Value: id,
			Kind:  KindCVE,
			Feed:  "kev",
			// CISA's catalog is, by definition, vulnerabilities with
			// reliable public proof of exploitation. There is no softer
			// confidence tier to express.
			Confidence: 100,
			Tags:       tags,
			FirstSeen:  parseFeedTime(row.DateAdded),
		})
	}
	return items, nil
}
