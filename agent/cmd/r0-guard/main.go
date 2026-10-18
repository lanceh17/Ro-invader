// Command r0-guard is the R0-Invader control plane.
//
// Two things ship today:
//
//   - `analyze` reads a Suricata EVE file, normalizes it, runs the detectors,
//     scores each device with exponential decay, and reports the recommended
//     containment tier. It reads and reports only.
//
//   - `serve` runs the DNS resolver wired to that same pipeline: queries are
//     attributed, scored, and a device whose assessment reaches the quarantine
//     tier has its lookups answered with the remediation portal, served by
//     this same command. The portal explains the quarantine, carries cleanup
//     guidance, and offers release behind an operator token; every release
//     is time-boxed and every decision and release is written to an
//     append-only audit log. That walled garden is the one containment action
//     this binary takes, and it is gated by the risk engine's corroboration
//     rule, so it reaches only devices that crossed the published threshold.
//
//   - `serve` can read the device table from the router itself, over that
//     router's own HTTP API: DHCP leases on all three backends, plus the
//     neighbour table where the vendor publishes one. An address that moves
//     is then reflected without regenerating a file. It is a read of state the
//     router offers — the router is asked what it knows, and nothing is written
//     and nothing is executed on it.
//
// That table is also the remediation portal's, so a device only the router has
// seen is containable and releasable on the same terms as one a file names —
// it simply has no class and no vendor yet, and its page says so.
//
// Pushing firewall rules to a router is still in progress; see
// docs/ROADMAP.md. Nothing here contacts a managed device directly.
//
// This tool is passive by architecture: it never probes, scans, or transmits
// to a managed device. See SAFETY.md.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/act"
	"github.com/lanceh17/Ro-invader/agent/internal/core"
	"github.com/lanceh17/Ro-invader/agent/internal/dns"
	"github.com/lanceh17/Ro-invader/agent/internal/feeds"
	"github.com/lanceh17/Ro-invader/agent/internal/ingest/oui"
	"github.com/lanceh17/Ro-invader/agent/internal/ingest/router"
	"github.com/lanceh17/Ro-invader/agent/internal/ingest/suricata"
	"github.com/lanceh17/Ro-invader/agent/internal/inventory"
	"github.com/lanceh17/Ro-invader/agent/internal/normalize"
	"github.com/lanceh17/Ro-invader/agent/internal/pipeline"
	"github.com/lanceh17/Ro-invader/agent/internal/portal"
	"github.com/lanceh17/Ro-invader/agent/internal/risk"
)

// version is stamped by the build. The default is what a plain `go install`
// produces, which is why CI and release builds set it via -ldflags.
var version = "dev"

const usage = `r0-guard — R0-Invader control plane (pre-alpha)

Usage:
  r0-guard <command> [flags]

Commands:
  version     Print build version and supported actuator backends
  analyze     Read a Suricata EVE file, score devices, recommend a tier
  serve       Run the DNS resolver and detection pipeline live
  help        Show this message

Analyze flags:
  -eve <path>          Suricata EVE JSON file to read (required)
  -inventory <path>    JSON device inventory for attribution and classification
  -half-life <dur>     Risk score decay half-life (default 72h)

Serve flags:
  -listen <addr>       UDP address to resolve on (default :53)
  -upstream <addr>     upstream resolver to forward to (default 8.8.8.8:53)
  -portal <ip>         remediation-portal address sinkholes point at (required)
  -garden <list>       comma-separated domains a quarantined device may still reach
  -inventory <path>    JSON device inventory for attribution and classification
  -half-life <dur>     Risk score decay half-life (default 72h)
  -report <dur>        interval between assessment reports; 0 disables (default 30s)
  -observe             score and report only: never sinkhole, regardless of tier
  -portal-http <addr>  portal HTTP listen address (default :80); empty disables
  -portal-token <tok>  operator token that releases devices (default: random)
  -release-ttl <dur>   how long one release lasts before re-containing (default 24h)
  -state <path>        persisted release store (default r0-guard-state.json)
  -audit <path>        action audit log, JSON Lines (default r0-guard-audit.jsonl)
  -remediation <path>  JSON map of vendor name to portal cleanup steps
  -feeds <list>        comma-separated threat feeds: threatfox, urlhaus, kev
                       (default off; threatfox/urlhaus need R0_ABUSECH_KEY)
  -feed-interval <dur> how often enabled feeds refresh (default 6h)
  -ioc-ttl <dur>       how long one refresh keeps indicators active (default 72h)
  -ioc-min-confidence <n>  lowest indicator confidence that can block a name
                       (default 75)
  -router <list>       comma-separated router backends to read the device table
                       from: openwrt, vyos, opnsense (default off)
  -router-url <url>    router base URL, e.g. http://192.168.1.1 (required with -router)
  -router-user <name>  OpenWrt ubus account allowed to read the lease table
  -router-pass <secret>  OpenWrt password; OPNsense API secret
  -router-key <apikey> VyOS or OPNsense API key; falls back to R0_ROUTER_KEY
  -router-interval <dur>  how often the router's tables are read (default 5m)

Status:
  v0.1 containment core is in progress. analyze is read-only. serve runs the
  resolver, applies the walled garden to quarantined devices, and serves the
  remediation portal with token-gated, audited releases, but does not yet push
  firewall rules to a router. With -feeds it also answers NXDOMAIN for uncontained
  devices querying names published by the enabled threat feeds; that is off
  unless -feeds is given, and -observe disables it even then. See docs/ROADMAP.md.

  With -router the router decides which device an address belongs to, so a
  lease that moved is reflected without editing a file. -inventory stays the
  source of each device's class and vendor; a device it does not name is still
  attributed, scored and contained, and shows the generic cleanup steps instead
  of vendor-specific ones. Reading the router is still only a read.

This tool is passive by architecture: it never probes, scans, or transmits
to a managed device. See SAFETY.md.
`

func main() {
	cmd := "help"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	args := os.Args[1:]
	if len(args) > 0 {
		args = args[1:]
	}

	switch cmd {
	case "version":
		printVersion()
	case "analyze":
		if err := runAnalyze(args); err != nil {
			fmt.Fprintf(os.Stderr, "r0-guard: %v\n", err)
			os.Exit(1)
		}
	case "serve":
		if err := runServe(args); err != nil {
			fmt.Fprintf(os.Stderr, "r0-guard: %v\n", err)
			os.Exit(1)
		}
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "r0-guard: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
}

func printVersion() {
	fmt.Printf("r0-guard %s\n", version)
	fmt.Printf("actuators: %s\n", strings.Join(act.Supported(), ", "))

	// A single backend is required for containment to have any effect, and
	// the failure mode of forgetting to set one is a tool that scores
	// devices and never acts on the result. Say so at startup rather than
	// discovering it during an incident.
	if os.Getenv("R0_ACTUATOR") == "" {
		fmt.Println("warning: R0_ACTUATOR is not set; containment is disabled")
	}
}

// runAnalyze drives the detection pipeline over a single EVE file. It is the
// smallest thing that proves ingest, detection, and scoring work together,
// and it is deliberately read-only: no router is contacted, no rule is
// written, and no device is probed.
func runAnalyze(args []string) error {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	evePath := fs.String("eve", "", "Suricata EVE JSON file to read")
	invPath := fs.String("inventory", "", "JSON device inventory for attribution and classification")
	halfLife := fs.Duration("half-life", 72*time.Hour, "risk score decay half-life")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *evePath == "" {
		return fmt.Errorf("analyze: -eve is required\n\n%s", usage)
	}

	// Load the inventory first. Without it nothing can be attributed, which
	// means no signal can name a device, which means the report would be
	// empty for reasons that are not obvious. Say so rather than looking
	// broken.
	var inv *inventory.Inventory
	var attributor suricata.Attributor
	if *invPath != "" {
		loaded, err := inventory.Load(*invPath)
		if err != nil {
			return err
		}
		inv = loaded
		attributor = loaded
	} else {
		fmt.Fprintln(os.Stderr, "warning: no -inventory given; events cannot be attributed to devices, so no signals will fire")
	}

	f, err := os.Open(*evePath)
	if err != nil {
		return fmt.Errorf("analyze: opening %s: %w", *evePath, err)
	}
	defer f.Close()

	events, err := suricata.ReadAll(f, attributor)
	if err != nil {
		return fmt.Errorf("analyze: reading %s: %w", *evePath, err)
	}

	// The pipeline is the single connection from events to scoring: it
	// attributes (already done here by Suricata, so it is preserved), runs the
	// detectors, and observes the engine. The inline loop this replaces is the
	// same one the DNS resolver path uses, so both paths are now identical
	// rather than merely similar.
	//
	// WithHalfLife, not WithConfig: the latter takes a full Config, and a
	// partial one would zero out RequireCorroboration and let a single
	// signal escalate a device. That is the opposite of what this tool is
	// for.
	engine := risk.New(risk.WithHalfLife(*halfLife))
	pipe := pipeline.New(attributor, engine)
	fired := pipe.IngestAll(events)
	signals := len(fired)
	detectors := pipe.Detectors()

	fmt.Printf("eve: %s\n", *evePath)
	fmt.Printf("events: %d normalized\n", len(events))
	if inv != nil {
		fmt.Printf("inventory: %d devices\n", inv.Len())
	}
	fmt.Printf("signals: %d from %d detectors\n\n", signals, len(detectors))

	if inv == nil || inv.Len() == 0 {
		fmt.Println("no devices to assess (need an inventory with devices)")
		return nil
	}

	// Score against the capture's own end, not wall-clock now.
	//
	// The engine decays each signal toward the evaluation time, so evaluating
	// at time.Now() would make this command non-reproducible: the same EVE
	// file returns a different score on every run as real time passes its
	// fixed timestamps, and an old log would report every signal already
	// decayed to nothing. The question an analysis of a captured log asks is
	// "what did this look like," which is answered at the end of the capture.
	// The live daemon, when it exists, will score against now -- that is its
	// job. This is only the batch reader.
	captureEnd := time.Time{}
	for _, ev := range events {
		if ev.Time.After(captureEnd) {
			captureEnd = ev.Time
		}
	}
	ranked := engine.Ranked(inv.Devices(), captureEnd)
	if len(ranked) == 0 {
		fmt.Println("no device scored above zero; nothing to report")
		return nil
	}

	for _, a := range ranked {
		fmt.Println(a.Describe())
		dev, _ := inv.Get(a.MAC)
		if dev.Vendor != "" {
			fmt.Printf("    vendor: %s  class: %s\n", dev.Vendor, dev.Class)
		}
	}
	return nil
}

// runServe runs the DNS resolver against the live detection pipeline.
//
// It is the first command in this binary that changes what a device sees: a
// device whose assessment reaches the quarantine tier has its lookups answered
// with the remediation portal. That is not an action this function takes
// directly -- it falls out of the risk engine's own tier, which cannot leave
// monitor without corroboration, so a single signal never sinkholes anything.
// -observe removes even that, for an operator who wants to watch first.
func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", ":53", "UDP address to resolve on")
	upstream := fs.String("upstream", "8.8.8.8:53", "upstream resolver to forward to")
	portalIP := fs.String("portal", "", "remediation-portal address sinkholes point at")
	garden := fs.String("garden", "", "comma-separated domains a quarantined device may still reach")
	invPath := fs.String("inventory", "", "JSON device inventory for attribution and classification")
	halfLife := fs.Duration("half-life", 72*time.Hour, "risk score decay half-life")
	reportEvery := fs.Duration("report", 30*time.Second, "interval between assessment reports; 0 disables")
	observe := fs.Bool("observe", false, "score and report only: never sinkhole")
	portalHTTP := fs.String("portal-http", ":80", "portal HTTP listen address; empty disables the portal")
	portalToken := fs.String("portal-token", "", "operator token that releases devices; empty generates a random one")
	releaseTTL := fs.Duration("release-ttl", 24*time.Hour, "how long one release lasts before the device is contained again")
	statePath := fs.String("state", "r0-guard-state.json", "persisted release store")
	auditPath := fs.String("audit", "r0-guard-audit.jsonl", "action audit log, one JSON object per line")
	remediationPath := fs.String("remediation", "", "JSON map of vendor name to portal cleanup steps")
	feedsList := fs.String("feeds", "", "comma-separated threat feeds to pull: threatfox, urlhaus, kev; empty disables feed-driven blocking")
	feedInterval := fs.Duration("feed-interval", 6*time.Hour, "how often enabled feeds refresh")
	iocTTL := fs.Duration("ioc-ttl", 72*time.Hour, "how long one feed refresh keeps its indicators active")
	iocMinConfidence := fs.Int("ioc-min-confidence", 75, "lowest indicator confidence that can block a DNS answer")
	routerList := fs.String("router", "", "comma-separated router backends to read the device table from: openwrt, vyos, opnsense; empty keeps attribution static")
	routerURL := fs.String("router-url", "", "router base URL, e.g. http://192.168.1.1 (required with -router)")
	routerUser := fs.String("router-user", "", "OpenWrt ubus account allowed to read the lease table")
	routerPass := fs.String("router-pass", "", "OpenWrt password, or the API secret half of an OPNsense key/secret pair")
	routerKey := fs.String("router-key", "", "VyOS or OPNsense API key; falls back to R0_ROUTER_KEY")
	routerInterval := fs.Duration("router-interval", 5*time.Minute, "how often the router's lease and neighbour tables are read")
	ouiEndpoint := fs.String("oui", "", "IEEE OUI registry URL for vendor lookup; empty disables")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *portalIP == "" {
		return fmt.Errorf("serve: -portal is required\n\n%s", usage)
	}
	portalAddr, err := netip.ParseAddr(*portalIP)
	if err != nil {
		return fmt.Errorf("serve: -portal %q: %w", *portalIP, err)
	}

	// Validate the feed configuration before anything binds. A typo in
	// -feeds should stop the run with a name it can fix, not surface later
	// as a resolver that silently blocks nothing.
	pullers, skippedFeeds, err := buildPullers(*feedsList, feedsAuthKey())
	if err != nil {
		return err
	}
	if len(pullers) > 0 {
		if *feedInterval <= 0 {
			return fmt.Errorf("serve: -feed-interval must be positive, got %s", *feedInterval)
		}
		if *iocTTL <= 0 {
			return fmt.Errorf("serve: -ioc-ttl must be positive, got %s", *iocTTL)
		}
	}

	// The router configuration is validated on the same terms, and for the
	// same reason: an unknown backend name, or a missing URL, must stop the
	// run while the message is still on the operator's screen rather than
	// becoming a resolver whose device table is quietly empty.
	//
	// The order is most-fundamental first: a backend that does not exist is
	// reported before the URL it would have needed, which is reported before
	// the interval it would have used, which is reported before the
	// credentials any particular backend turns out to want. The interval is
	// checked against the request rather than against the backends that
	// survived credential filtering, so naming a keyed backend with no key
	// still fails loudly on a bad interval instead of quietly accepting one
	// and then never reading anything.
	routerNames, err := parseRouterList(*routerList)
	if err != nil {
		return err
	}
	if len(routerNames) > 0 {
		if strings.TrimSpace(*routerURL) == "" {
			return fmt.Errorf("serve: -router-url is required when -router is set")
		}
		if *routerInterval <= 0 {
			return fmt.Errorf("serve: -router-interval must be positive, got %s", *routerInterval)
		}
	}
	routerSources, skippedRouters, err := buildRouterSources(routerNames, router.Config{
		BaseURL:  strings.TrimSpace(*routerURL),
		Username: strings.TrimSpace(*routerUser),
		Password: *routerPass,
		Token:    routerAPIKey(*routerKey),
	})
	if err != nil {
		return err
	}
	routerRequested := len(routerNames) > 0

	// Build the router client only when a backend actually survived. Passing
	// an empty Sources list to router.New would quietly get a default OpenWrt
	// source -- a backend the operator did not ask for, pointed at a URL they
	// may not have intended to authenticate against, failing once per poll.
	var routerClient *router.Client
	if len(routerSources) > 0 {
		routerClient, err = router.New(router.Config{
			BaseURL:  strings.TrimSpace(*routerURL),
			Username: strings.TrimSpace(*routerUser),
			Password: *routerPass,
			Token:    routerAPIKey(*routerKey),
			Sources:  routerSources,
		})
		if err != nil {
			return err
		}
	}

	// Load the inventory before binding. Without it nothing can be attributed,
	// so no signal can fire and nothing will ever be contained -- a resolver
	// that silently forwards everything would look identical to one that is
	// working. Say so rather than appearing broken.
	var inv *inventory.Inventory
	if *invPath != "" {
		loaded, err := inventory.Load(*invPath)
		if err != nil {
			return err
		}
		inv = loaded
	} else if routerClient != nil {
		// The router names devices and addresses, so attribution, scoring and
		// containment all work without this file: the portal reads the same
		// table. What the file alone would have supplied is a class and a
		// vendor, so say that plainly rather than letting an operator find it
		// out on a page for a device they think they know.
		fmt.Fprintln(os.Stderr,
			"warning: no -inventory given; the router supplies devices and addresses, so queries are attributed, scored and contained.\n"+
				"          Devices the router alone knows carry no class and no vendor: they are scored at neutral class\n"+
				"          weighting and shown the generic cleanup steps. Add them to -inventory to classify them.")
	} else {
		fmt.Fprintln(os.Stderr, "warning: no -inventory given; queries cannot be attributed, so no signals will fire and nothing will be contained")
	}

	// One table for the whole run. Everything downstream -- the detectors, the
	// containment predicate, the audit lines, the periodic report -- resolves
	// addresses and devices through it, so they cannot disagree about which
	// device an event belongs to.
	table := newDeviceTable(inv, routerClient)

	if *ouiEndpoint != "" {
		store, err := oui.New(oui.Config{Endpoint: *ouiEndpoint})
		if err != nil {
			return err
		}
		if err := store.Load(context.Background()); err != nil {
			return fmt.Errorf("serve: loading OUI registry: %w", err)
		}
		table.oui.Store(store)
		fmt.Fprintf(os.Stderr, "oui: %d vendor prefixes loaded\n", store.Len())
	}

	var gardenDomains []string
	for _, g := range strings.Split(*garden, ",") {
		if g = strings.TrimSpace(g); g != "" {
			gardenDomains = append(gardenDomains, g)
		}
	}

	// The release store refuses to start on malformed state rather than
	// skipping it: a state file we cannot parse means releases we cannot
	// honor, and continuing would silently re-contain devices the operator
	// already freed. The audit log is opened lazily by its own type, so runs
	// that never contain anything leave no files behind.
	exceptions, err := portal.NewExceptions(*statePath, nil)
	if err != nil {
		return err
	}
	auditLog := portal.NewAudit(*auditPath, nil)
	defer auditLog.Close()

	remediation, err := loadRemediation(*remediationPath)
	if err != nil {
		return err
	}
	token, err := releaseToken(*portalToken)
	if err != nil {
		return err
	}

	// A feed that needs an Auth-Key and did not get one is skipped loudly
	// rather than failing the run: an operator who enabled three feeds and
	// forgot one key still wants the other two (and the DNS resolver) to
	// come up.
	for _, name := range skippedFeeds {
		fmt.Fprintf(os.Stderr, "r0-guard: feed %s skipped: no Auth-Key (set R0_ABUSECH_KEY)\n", name)
	}

	// Same rule for the router backends: a backend that needs an API key and
	// did not get one is skipped and named, and the run continues with
	// whatever else is configured.
	for _, name := range skippedRouters {
		fmt.Fprintf(os.Stderr, "r0-guard: router backend %s skipped: no API key (set %s or pass -router-key)\n", name, routerKeyEnv)
	}
	// Every backend the operator named was skipped, so nothing is being polled.
	// Attribution has quietly fallen back to whatever -inventory holds, and
	// saying so is the difference between a router that has no devices and a
	// router that is not being read.
	if routerRequested && routerClient == nil {
		fmt.Fprintln(os.Stderr, "r0-guard: no router backend is active; the device table is static only")
	}

	// Both sources configured is a supported configuration, not a conflict, so
	// it is spelled out rather than resolved silently. The router is
	// authoritative for which device an address belongs to -- a lease that
	// moved this morning is a fact the file cannot know -- and the file
	// remains authoritative for classification and vendor.
	if routerClient != nil && inv != nil {
		fmt.Fprintln(os.Stderr,
			"r0-guard: -router and -inventory are both set: the router decides which device an address belongs to;\n"+
				"          -inventory supplies each device's class and vendor. A device it does not name is still\n"+
				"          attributed, scored and contained from the router's evidence alone, with no class and no vendor.")
	}

	// The indicator store exists even with no feeds: an empty store is the
	// no-blocklist default, and one code path serves both cases. -observe
	// keeps the store populated for provenance and counts but disables the
	// predicate below, so observing runs affect no traffic at all.
	iocStore := normalize.NewStore(*iocMinConfidence)
	var blocked func(string) bool
	if len(pullers) > 0 {
		if *observe {
			fmt.Fprintln(os.Stderr, "r0-guard: -observe active: feeds are pulled and logged, but no answer will be blocked")
		} else {
			blocked = func(name string) bool {
				_, ok := iocStore.Match(name, time.Now())
				return ok
			}
		}
	}

	engine := risk.New(risk.WithHalfLife(*halfLife))
	pipe := pipeline.New(table, engine)

	// The containment predicate is driven by the engine, not by a flag this
	// command owns, so there is exactly one source of truth for a device's
	// tier. -observe overrides it entirely rather than adjusting a threshold,
	// because "never contain" should not depend on getting a number right.
	// The release store sits inside the predicate: a released device is
	// contained by no one until its time box runs out.
	quarantined := quarantineFunc(table, engine, exceptions)
	if *observe {
		quarantined = func(netip.Addr) bool { return false }
	}

	// The portal binds before the resolver does: a permission error on :80
	// should stop the run before :53 is taken, and a run whose sinkholes
	// point at an address nobody answers would strand every contained device
	// on a dead page.
	var portalSrv *http.Server
	var portalErrc chan error
	if *portalHTTP != "" {
		ps, err := portal.New(portal.Config{
			Engine: engine,
			// The table, not the file. The portal is the only place a human
			// can undo a containment, so handing it a narrower view than the
			// resolver holds is how a device ends up contained with no way out;
			// this is the same pointer the resolver and the detectors resolve
			// addresses through, so every device one can act on, the other can
			// act back on. A device only the router knows renders with no class
			// and no vendor, which changes what the page says and nothing else.
			DeviceSource: table,
			Garden:       gardenDomains,
			Remediation:  remediation,
			Exceptions:   exceptions,
			Audit:        auditLog,
			Token:        token,
			ReleaseTTL:   *releaseTTL,
			ReadOnly:     *observe,
		})
		if err != nil {
			return err
		}
		ln, err := net.Listen("tcp", *portalHTTP)
		if err != nil {
			return fmt.Errorf("serve: portal http on %s: %w (change with -portal-http)", *portalHTTP, err)
		}
		portalSrv = &http.Server{Handler: ps.Handler()}
		portalErrc = make(chan error, 1)
		go func() { portalErrc <- portalSrv.Serve(ln) }()
		fmt.Fprintf(os.Stderr, "r0-guard: portal on %s (listening on %s)\n", deviceFacingURL(portalAddr, ln.Addr()), ln.Addr())
		fmt.Fprintf(os.Stderr, "r0-guard: portal release token: %s\n", token)
	}

	// Discover the bound address (the real port when -listen uses :0) and
	// detect a bind failure before reporting readiness, so a permission error
	// on :53 surfaces as an error rather than as a server that never answers.
	ready := make(chan net.Addr, 1)
	srv, err := dns.New(dns.Config{
		ListenAddr:  *listen,
		Upstream:    *upstream,
		Portal:      portalAddr,
		Garden:      gardenDomains,
		Quarantined: quarantined,
		Blocked:     blocked,
		OnQuery: func(ev core.NormalizedEvent, action dns.Action) {
			// The sinkhole record is written before Ingest: Handle decided
			// from the engine state as it stood before this query was
			// observed, so evaluating now reproduces the decision's own
			// score, not one this query has already moved.
			//
			// Forwarded queries stay unlogged either way: they are every
			// lookup on the network, and printing them would bury the lines
			// that matter when something is actually acted on.
			switch action {
			case dns.ActionSinkhole:
				recordSinkhole(auditLog, table, engine, ev)
				fmt.Fprintf(os.Stderr, "r0-guard: sinkholed %s for %s\n", ev.QueryName, ev.Src.IP)
			case dns.ActionNXDomain:
				// NXDOMAIN has exactly one producer: the Blocked predicate
				// consulting the indicator store. The matching indicator is
				// re-read here for the audit line; the decision itself was
				// already made in Decide.
				recordIOCBlock(auditLog, table, iocStore, ev)
				fmt.Fprintf(os.Stderr, "r0-guard: blocked %s for %s (threat intel)\n", ev.QueryName, ev.Src.IP)
			}
			pipe.Ingest(ev)
		},
		Ready: func(a net.Addr) { ready <- a },
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// portalErrc stays nil when the portal is disabled; a nil channel in a
	// select blocks forever, which is exactly right.
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe(ctx) }()

	select {
	case addr := <-ready:
		fmt.Fprintf(os.Stderr, "r0-guard: resolving on %s (forwarding to %s)\n", addr, *upstream)
	case err := <-errc:
		return err
	case err := <-portalErrc:
		return fmt.Errorf("serve: portal: %w", err)
	}

	// The first pull happens on this goroutine, not on the startup path:
	// an offline install must still bring the resolver up, and the store
	// simply stays empty until a refresh succeeds. Each failed refresh
	// keeps the previous snapshot active rather than emptying the list.
	if len(pullers) > 0 {
		go feedLoop(ctx, pullers, iocStore, *feedInterval, *iocTTL)
	}

	// The router is polled here for the same reason, and it matters more: the
	// first request to a router can sit behind its own boot, a slow WAN, or a
	// captive login page, and none of that should hold up a resolver that is
	// already answering. Until the first poll lands, attribution falls back to
	// whatever -inventory holds, which is the old behavior rather than none of
	// it. The loop polls once immediately and then on the interval.
	if routerClient != nil {
		go routerLoop(ctx, routerClient, *routerInterval)
	}

	if *reportEvery > 0 {
		go func() {
			t := time.NewTicker(*reportEvery)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					printReport(pipe, table)
				}
			}
		}()
	}

	select {
	case err := <-errc:
		return err
	case err := <-portalErrc:
		// Serve never returns nil on its own: only our own Shutdown below
		// makes it exit, and that path does not come through this case.
		return fmt.Errorf("serve: portal: %w", err)
	case <-ctx.Done():
		// ListenAndServe closes its socket on cancellation and returns nil.
		if err := <-errc; err != nil {
			return err
		}
	}

	// Shut the portal down after the resolver has drained, with a bound so a
	// browser holding the connection open cannot hold the process open; the
	// Close below is the forcing function.
	if portalSrv != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := portalSrv.Shutdown(shutdownCtx); err != nil {
			portalSrv.Close()
		}
		<-portalErrc // the Serve goroutine finishes here
	}

	printReport(pipe, table)
	return nil
}

// quarantineFunc is the resolver's containment predicate: a device is contained
// when its current assessment tier is quarantine and no active release says
// otherwise.
//
// It consults the risk engine rather than tracking a separate containment flag,
// because two sources of truth for a device's tier would eventually disagree
// during an incident. A device that has not crossed the engine's corroboration-
// gated quarantine threshold is never contained, which is what keeps a single
// signal -- however large -- from sinkholing anything. The release store is the
// one documented override: an operator's time-boxed decision to let a specific
// device back on, checked on every query so it expires by itself.
//
// The address is resolved through the table rather than through one source, so
// the device judged here is the device the detectors scored. Resolving through
// a different table than the one attribution used is how a decision gets
// recorded against one MAC and executed against another.
func quarantineFunc(t *deviceTable, eng *risk.Engine, exc *portal.Exceptions) func(netip.Addr) bool {
	return func(ip netip.Addr) bool {
		if t == nil || eng == nil {
			return false
		}
		mac, ok := t.MACFor(ip)
		if !ok {
			return false
		}
		if _, released := exc.Active(mac); released {
			return false
		}
		// A device this run may contain is exactly a device the portal can
		// find a page for: the same table, handed to the portal as its
		// DeviceSource, answering with the same two lookups. That used to be
		// narrower -- the static inventory alone, because the portal was typed
		// to *inventory.Inventory and had no page for a device the router alone
		// knew. Refusing those was right while that was true, and it is what
		// left a whole class of confirmed infections uncontainable. Now that
		// the page is built from the table, the check is simply whether the
		// table can describe the device.
		dev, ok := t.Get(mac)
		if !ok {
			return false
		}
		return eng.Evaluate(dev, time.Now()).Tier == core.ContainmentQuarantined
	}
}

// deviceTable is this run's view of the network: it resolves an address to a
// device for attribution, scoring, and containment.
//
// It exists because there are now two sources of that answer, and one
// consumer that must not be allowed to mix them. A run can read the router
// live, can read a static inventory, or both, and the router wins on
// attribution -- a lease that moved this morning is a fact a file cannot know,
// and attributing to the previous holder is how the wrong camera gets
// quarantined. The static file still supplies class and vendor, because
// classification drives the score's weighting and no router publishes one.
//
// Containment and the portal are now the same table's business. The page and
// its release button are built from the same two lookups the containment
// predicate makes, so a device this run can act on is by construction one an
// operator can act back on. A device the router alone knows carries no class
// and no vendor, which changes what the page says about it and not whether it
// can be freed.
//
// Both fields may be nil, in which case nothing can be attributed -- the same
// honest nothing the run had before a router existed.
//
// The struct is immutable after construction and nothing here is ever
// reassigned. That is what makes it safe to hand the same pointer to the
// resolver and to every portal handler goroutine with no lock of its own: the
// only mutable state underneath is the router client's, which carries its own
// RWMutex, and the inventory's, which is written once by Load and read-only
// forever after. There is no pointer here to swap under a running handler.
type deviceTable struct {
	inv    *inventory.Inventory
	router *router.Client
	oui    atomic.Value // stores *oui.Store
}

// The portal declares what it needs; this is where the concrete tables are, so
// the assertion lives here. If either signature moves in a way the portal's
// contract depends on, the build breaks at the wiring rather than at a call
// site nobody was watching.
var (
	_ portal.DeviceSource = (*deviceTable)(nil)
	_ portal.DeviceSource = (*inventory.Inventory)(nil)
)

// newDeviceTable wires a table. Both arguments are optional.
func newDeviceTable(inv *inventory.Inventory, rtr *router.Client) *deviceTable {
	return &deviceTable{inv: inv, router: rtr}
}

// MACFor satisfies pipeline.Attributor: which device owns this address.
//
// The router is asked first and the static inventory second, in that order and
// not as a merge. A live lease and a file disagree in exactly one situation --
// the file is stale -- and in that situation the live one is the correct one.
// Falling through to the file keeps an address working during the window
// before the first poll lands, which is the difference between "attribution
// starts a little late" and "attribution does not exist".
func (t *deviceTable) MACFor(ip netip.Addr) (net.HardwareAddr, bool) {
	if t == nil {
		return nil, false
	}
	if t.router != nil {
		if mac, ok := t.router.MACFor(ip); ok {
			return mac, true
		}
	}
	if t.inv != nil {
		return t.inv.MACFor(ip)
	}
	return nil, false
}

// Get returns the record to score for mac: the static inventory's when it has
// one, otherwise the router's. It satisfies portal.DeviceSource alongside
// MACFor, which is what makes this table the portal's page for every device
// the run can see.
//
// The preference is the enrichment rule above. A router-only device carries
// core.ClassUnknown, which the risk engine scores at the neutral multiplier --
// an uncategorized device is weighted honestly rather than being handed a
// guess that would move its number in a direction nobody chose.
//
// The router fallback is a linear scan and is only reached when the file does
// not know the MAC. Every device the file does name -- every device an
// operator has classified -- is a single map lookup away. The scan runs once
// per portal request and once per containment decision, not once per event.
func (t *deviceTable) Get(mac net.HardwareAddr) (core.Device, bool) {
	if t == nil {
		return core.Device{}, false
	}
	if t.inv != nil {
		if dev, ok := t.inv.Get(mac); ok {
			return dev, true
		}
	}
	if t.router != nil {
		for _, d := range t.router.Devices() {
			if d.MAC.String() == mac.String() {
				if v := t.oui.Load(); v != nil {
					if store, ok := v.(*oui.Store); ok {
						if d.Vendor == "" {
							if vendor, found := store.Lookup(mac); found {
								d.Vendor = vendor
							}
						}
					}
				}
				return d, true
			}
		}
	}
	return core.Device{}, false
}

// Devices returns every device the run can assess, for the periodic report.
// Static entries come first so a device named by both sources is reported from
// the file, with its class attached.
func (t *deviceTable) Devices() []core.Device {
	if t == nil {
		return nil
	}
	var out []core.Device
	seen := map[string]bool{}
	if t.inv != nil {
		for _, dev := range t.inv.Devices() {
			seen[dev.MAC.String()] = true
			out = append(out, dev)
		}
	}
	if t.router != nil {
		for _, dev := range t.router.Devices() {
			if seen[dev.MAC.String()] {
				continue
			}
			out = append(out, dev)
		}
	}
	return out
}

// recordSinkhole writes the audit line for one containment decision: which
// device, on which query, at what score, with which evidence.
//
// The address is resolved through the same table the containment predicate
// used, so the entry names the device that was actually contained. The lookup
// is the same one too: the containment predicate refused to contain a device
// the table cannot describe, so this enrichment is found whenever a sinkhole
// was issued at all -- but the table is still what answers, so this code stays
// correct if that ever stops being true.
//
// An audit write failure cannot be allowed to fail the DNS response -- the
// device is already contained either way -- so it is reported loudly on
// stderr instead of swallowed. ARCHITECTURE.md makes the log not optional;
// this is the loud part.
func recordSinkhole(auditLog *portal.Audit, t *deviceTable, eng *risk.Engine, ev core.NormalizedEvent) {
	entry := portal.AuditEntry{
		Action: "sinkhole",
		IPs:    []string{ev.Src.IP.String()},
		Query:  ev.QueryName,
	}
	if t != nil && eng != nil {
		if mac, ok := t.MACFor(ev.Src.IP); ok {
			if dev, ok := t.Get(mac); ok {
				a := eng.Evaluate(dev, time.Now())
				entry.MAC = mac.String()
				entry.Vendor = dev.Vendor
				entry.Class = string(dev.Class)
				entry.Score = a.Score
				entry.Tier = string(a.Tier)
				entry.Corroborated = a.Corroborated
				entry.DistinctKinds = a.DistinctKinds
				entry.Reasons = a.Reasons
			}
		}
	}
	if err := auditLog.Record(entry); err != nil {
		fmt.Fprintf(os.Stderr, "r0-guard: audit write failed: %v\n", err)
	}
}

// recordIOCBlock writes the audit line for a DNS answer refused because the
// name matched a feed indicator: which device, which query, which indicator
// said so.
//
// Score and Tier stay zero on purpose. This action comes from the indicator
// blocklist, not from the device's risk score, and filling those fields with
// engine numbers would make the audit imply corroboration the blocklist
// never had.
//
// The MAC comes from the table, so a device the router has learned about is
// named here even when no inventory file describes it -- this action contains
// nothing, and refusing to record who asked would be the wrong trade. Vendor
// and class stay empty for such a device, which is the truth.
func recordIOCBlock(auditLog *portal.Audit, t *deviceTable, store *normalize.Store, ev core.NormalizedEvent) {
	entry := portal.AuditEntry{
		Action: "ioc-block",
		IPs:    []string{ev.Src.IP.String()},
		Query:  ev.QueryName,
	}
	if t != nil {
		if mac, ok := t.MACFor(ev.Src.IP); ok {
			entry.MAC = mac.String()
			if dev, ok := t.Get(mac); ok {
				entry.Vendor = dev.Vendor
				entry.Class = string(dev.Class)
			}
		}
	}
	if store != nil {
		if ioc, ok := store.Match(ev.QueryName, time.Now()); ok {
			entry.Reasons = []string{fmt.Sprintf(
				"indicator %s=%s via %s (confidence %d, expires %s)",
				ioc.Kind, ioc.Value, strings.Join(ioc.Feeds, "+"),
				ioc.Confidence, ioc.Expires.UTC().Format(time.RFC3339))}
		}
	}
	if err := auditLog.Record(entry); err != nil {
		fmt.Fprintf(os.Stderr, "r0-guard: audit write failed: %v\n", err)
	}
}

// validFeeds lists the pullers serve can enable, in the order -feeds parses
// them. SSLBL is deliberately absent: abuse.ch deprecated its botnet C2 IP
// blacklist on 2025-01-03, and building on a dead feed is the trap
// SAFETY.md already documents for Feodo Tracker.
var validFeeds = []string{"threatfox", "urlhaus", "kev"}

// buildPullers turns the -feeds list into pullers. Feeds that need an
// Auth-Key and did not receive one come back in skipped rather than failing
// the build: the operator is told which one was skipped, and the run
// continues with the feeds that are configured. An unknown name is an
// error — silently ignoring a typo would block nothing while looking live.
func buildPullers(list, authKey string) ([]feeds.Puller, []string, error) {
	var names []string
	seen := map[string]bool{}
	for _, n := range strings.Split(list, ",") {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		names = append(names, n)
	}
	if len(names) == 0 {
		return nil, nil, nil
	}

	var pullers []feeds.Puller
	var skipped []string
	for _, n := range names {
		switch n {
		case "threatfox":
			if authKey == "" {
				skipped = append(skipped, n)
				continue
			}
			pullers = append(pullers, feeds.NewThreatFox(authKey))
		case "urlhaus":
			if authKey == "" {
				skipped = append(skipped, n)
				continue
			}
			pullers = append(pullers, feeds.NewURLhaus(authKey))
		case "kev":
			pullers = append(pullers, feeds.NewKev())
		default:
			return nil, nil, fmt.Errorf("serve: unknown feed %q (valid: %s)", n, strings.Join(validFeeds, ", "))
		}
	}
	return pullers, skipped, nil
}

// feedsAuthKey reads the abuse.ch Auth-Key shared by ThreatFox and URLhaus.
// R0_ABUSECH_KEY is the general name; R0_THREATFOX_KEY stays honored because
// SAFETY.md documents it as the variable ThreatFox reads from. Keys are
// environment-only: never flags, never config files, never code.
func feedsAuthKey() string {
	if k := os.Getenv("R0_ABUSECH_KEY"); k != "" {
		return k
	}
	return os.Getenv("R0_THREATFOX_KEY")
}

// feedLoop refreshes every enabled feed: one cycle immediately, then on the
// interval, until ctx is canceled.
func feedLoop(ctx context.Context, pullers []feeds.Puller, store *normalize.Store, interval, ttl time.Duration) {
	pullAll(ctx, pullers, store, ttl)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pullAll(ctx, pullers, store, ttl)
		}
	}
}

// pullAll runs one refresh cycle. An error on one feed keeps that feed's
// previous snapshot active and moves on: a provider outage must never
// empty the blocklist or stall the other feeds' refresh.
func pullAll(ctx context.Context, pullers []feeds.Puller, store *normalize.Store, ttl time.Duration) {
	for _, p := range pullers {
		items, err := p.Pull(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "r0-guard: feed %s refresh failed: %v (previous snapshot stays active)\n", p.Name(), err)
			continue
		}
		now := time.Now()
		iocs := normalize.Normalize(items, now, ttl)
		store.Replace(p.Name(), iocs)
		store.Prune(now)
		fmt.Fprintf(os.Stderr, "r0-guard: feed %s: %d indicators, %d active in total\n",
			p.Name(), len(iocs), store.Count(now))
	}
}

// validRouters lists the router backends serve can poll, in the order -router
// parses them.
var validRouters = []string{"openwrt", "vyos", "opnsense"}

// routerKeyEnv is where a router API key comes from when -router-key is not
// given. A command line is readable by every other process on the host and
// survives in shell history; an environment variable does not. The flag is
// still honored, for the case where the daemon is supervised by something that
// hands it a prepared environment anyway.
const routerKeyEnv = "R0_ROUTER_KEY"

// routerAPIKey resolves the API key: the flag if given, R0_ROUTER_KEY
// otherwise. The flag wins so an operator can override a key inherited from a
// shell profile without unsetting it first.
func routerAPIKey(given string) string {
	if k := strings.TrimSpace(given); k != "" {
		return k
	}
	return strings.TrimSpace(os.Getenv(routerKeyEnv))
}

// routerNeedsKey reports whether a backend authenticates with an API key.
// OpenWrt authenticates with a ubus username and password pair, so a missing
// key is never its problem and it is never skipped for one.
func routerNeedsKey(name string) bool {
	switch name {
	case "vyos", "opnsense":
		return true
	default:
		return false
	}
}

// parseRouterList turns the -router list into backend names.
//
// It is a separate step because the checks that follow it need the names
// before anything is built: a backend that does not exist has to be reported
// as such rather than as the missing BaseURL its constructor would complain
// about. Names are lowercased, trimmed, and de-duplicated, first spelling
// first, so "-router opnsense" and "-router OpenWrt, opnsense" both give the
// same backends in the same order.
func parseRouterList(list string) ([]string, error) {
	var names []string
	seen := map[string]bool{}
	for _, n := range strings.Split(list, ",") {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		names = append(names, n)
	}

	for _, n := range names {
		if !slices.Contains(validRouters, n) {
			return nil, fmt.Errorf("serve: unknown router %q (valid: %s)", n, strings.Join(validRouters, ", "))
		}
	}
	return names, nil
}

// buildRouterSources turns parsed backend names into sources, using cfg for
// everything but the choice of backend.
//
// A backend whose credential is missing is skipped and reported rather than
// failing the run: naming three backends and forgetting one key still leaves
// two working ones, and a partial device table beats a daemon that refuses to
// start. This is the same trade buildPullers makes for a missing Auth-Key.
func buildRouterSources(names []string, cfg router.Config) ([]router.Source, []string, error) {
	var sources []router.Source
	var skipped []string
	for _, n := range names {
		// Credential gate before construction, so a missing key reads as a
		// skip here exactly as a missing Auth-Key does for a keyed feed.
		if routerNeedsKey(n) && cfg.Token == "" {
			skipped = append(skipped, n)
			continue
		}
		var (
			src router.Source
			err error
		)
		switch n {
		case "openwrt":
			src, err = router.NewOpenWrt(cfg)
		case "vyos":
			src, err = router.NewVyOS(cfg)
		case "opnsense":
			src, err = router.NewOPNsense(cfg)
		default:
			// Unreachable: parseRouterList has already rejected any name
			// outside validRouters. Kept rather than omitted because the
			// constructors and this list have to be edited together, and a
			// silently empty case would be the wrong way to discover that.
			return nil, nil, fmt.Errorf("serve: unknown router %q (valid: %s)", n, strings.Join(validRouters, ", "))
		}
		// A backend that cannot even be constructed -- no username for
		// OpenWrt, no API secret for OPNsense -- is a hard error rather than a
		// skip. There is nothing to fall back to: the credential exists and
		// was not supplied, and continuing would poll a backend that can only
		// fail on every cycle.
		if err != nil {
			return nil, nil, fmt.Errorf("serve: -router %s: %w", n, err)
		}
		sources = append(sources, src)
	}
	return sources, skipped, nil
}

// routerLoop refreshes the device table from the router: one poll immediately,
// then on the interval, until ctx is canceled.
func routerLoop(ctx context.Context, c *router.Client, interval time.Duration) {
	pollRouter(ctx, c)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pollRouter(ctx, c)
		}
	}
}

// pollRouter runs one refresh cycle.
//
// An error is reported and the loop continues, because the client's contract
// is that a failed poll never removes what an earlier one learned: a router
// that reboots mid-run degrades to a stale table, which misattributes only
// addresses nobody re-claims, rather than to no table at all, where every
// event would become unattributable and every signal would stop firing with no
// error anywhere to show for it.
func pollRouter(ctx context.Context, c *router.Client) {
	err := c.Poll(ctx)
	// A cancellation is how the loop is meant to end, not a fault to report.
	if err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "r0-guard: router refresh failed: %v (leases learned earlier stay active)\n", err)
		return
	}
	fmt.Fprintf(os.Stderr, "r0-guard: router: %d devices known\n", c.Len())
}

// releaseToken returns the operator's release token, generating a random one
// when none was given. A per-run random token printed to the operator's
// terminal is the right default: nothing to forget to change, nothing in
// shell history, and the device being contained never sees it.
func releaseToken(given string) (string, error) {
	if given != "" {
		return given, nil
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("serve: generating release token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// loadRemediation reads the optional vendor -> steps map shown by the portal.
// Inventing device-specific instructions we have not verified would be worse
// than the generic list, so the file is the only source of vendor claims.
func loadRemediation(path string) (map[string][]string, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("serve: reading remediation file: %w", err)
	}
	var m map[string][]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("serve: parsing remediation file: %w", err)
	}
	return m, nil
}

// deviceFacingURL is the URL a redirected device will actually request: the
// portal address from the sinkhole answer, on the port the listener took.
func deviceFacingURL(device netip.Addr, bound net.Addr) string {
	port := 80
	if ta, ok := bound.(*net.TCPAddr); ok && ta.Port != 0 {
		port = ta.Port
	}
	if port == 80 {
		return fmt.Sprintf("http://%s/", device)
	}
	return fmt.Sprintf("http://%s:%d/", device, port)
}

// printReport writes the current ranked assessments to stdout. It is how the
// daemon's scoring stays visible without waiting for containment to happen.
// Sinkhole logs go to stderr, so the two never interleave in a way that is hard
// to read when piping output.
//
// It assesses every device the table knows, which under -router includes the
// devices no file names. That is deliberate: a device being scored is how an
// operator finds out it should be classified in the inventory, and under
// -router it is also how they find out it is already being contained.
func printReport(pipe *pipeline.Pipeline, t *deviceTable) {
	if t == nil {
		return
	}
	devices := t.Devices()
	if len(devices) == 0 {
		return
	}
	ranked := pipe.Engine().Ranked(devices, time.Now())
	if len(ranked) == 0 {
		return
	}
	fmt.Println("--- assessments ---")
	for _, a := range ranked {
		fmt.Println(a.Describe())
	}
}
