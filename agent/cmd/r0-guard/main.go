// Command r0-guard is the R0-Invader control plane.
//
// Two things ship today:
//
//   - `analyze` reads a Suricata EVE file, normalizes it, runs the detectors,
//     scores each device with exponential decay, and reports the recommended
//     containment tier. It reads and reports only.
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
	"strings"
	"syscall"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/act"
	"github.com/lanceh17/Ro-invader/agent/internal/core"
	"github.com/lanceh17/Ro-invader/agent/internal/dns"
	"github.com/lanceh17/Ro-invader/agent/internal/ingest/suricata"
	"github.com/lanceh17/Ro-invader/agent/internal/inventory"
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

Status:
  v0.1 containment core is in progress. analyze is read-only. serve runs the
  resolver, applies the walled garden to quarantined devices, and serves the
  remediation portal with token-gated, audited releases, but does not yet push
  firewall rules to a router. See docs/ROADMAP.md.

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

	// Load the inventory before binding. Without it nothing can be attributed,
	// so no signal can fire and nothing will ever be contained -- a resolver
	// that silently forwards everything would look identical to one that is
	// working. Say so rather than appearing broken.
	var inv *inventory.Inventory
	var attr pipeline.Attributor
	if *invPath != "" {
		loaded, err := inventory.Load(*invPath)
		if err != nil {
			return err
		}
		inv = loaded
		attr = loaded
	} else {
		fmt.Fprintln(os.Stderr, "warning: no -inventory given; queries cannot be attributed, so no signals will fire and nothing will be contained")
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

	engine := risk.New(risk.WithHalfLife(*halfLife))
	pipe := pipeline.New(attr, engine)

	// The containment predicate is driven by the engine, not by a flag this
	// command owns, so there is exactly one source of truth for a device's
	// tier. -observe overrides it entirely rather than adjusting a threshold,
	// because "never contain" should not depend on getting a number right.
	// The release store sits inside the predicate: a released device is
	// contained by no one until its time box runs out.
	quarantined := quarantineFunc(inv, engine, exceptions)
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
			Engine:      engine,
			Inventory:   inv,
			Garden:      gardenDomains,
			Remediation: remediation,
			Exceptions:  exceptions,
			Audit:       auditLog,
			Token:       token,
			ReleaseTTL:  *releaseTTL,
			ReadOnly:    *observe,
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
		OnQuery: func(ev core.NormalizedEvent, action dns.Action) {
			// The sinkhole record is written before Ingest: Handle decided
			// from the engine state as it stood before this query was
			// observed, so evaluating now reproduces the decision's own
			// score, not one this query has already moved.
			if action == dns.ActionSinkhole {
				recordSinkhole(auditLog, inv, engine, ev)
				// Only sinkholes are logged. Forwarded queries are every
				// lookup on the network; printing them would bury the one
				// line that matters when a device is actually contained.
				fmt.Fprintf(os.Stderr, "r0-guard: sinkholed %s for %s\n", ev.QueryName, ev.Src.IP)
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

	if *reportEvery > 0 {
		go func() {
			t := time.NewTicker(*reportEvery)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					printReport(pipe, inv)
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

	printReport(pipe, inv)
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
func quarantineFunc(inv *inventory.Inventory, eng *risk.Engine, exc *portal.Exceptions) func(netip.Addr) bool {
	return func(ip netip.Addr) bool {
		if inv == nil || eng == nil {
			return false
		}
		mac, ok := inv.MACFor(ip)
		if !ok {
			return false
		}
		if _, released := exc.Active(mac); released {
			return false
		}
		dev, ok := inv.Get(mac)
		if !ok {
			return false
		}
		return eng.Evaluate(dev, time.Now()).Tier == core.ContainmentQuarantined
	}
}

// recordSinkhole writes the audit line for one containment decision: which
// device, on which query, at what score, with which evidence.
//
// An audit write failure cannot be allowed to fail the DNS response -- the
// device is already contained either way -- so it is reported loudly on
// stderr instead of swallowed. ARCHITECTURE.md makes the log not optional;
// this is the loud part.
func recordSinkhole(auditLog *portal.Audit, inv *inventory.Inventory, eng *risk.Engine, ev core.NormalizedEvent) {
	entry := portal.AuditEntry{
		Action: "sinkhole",
		IPs:    []string{ev.Src.IP.String()},
		Query:  ev.QueryName,
	}
	if inv != nil && eng != nil {
		if mac, ok := inv.MACFor(ev.Src.IP); ok {
			if dev, ok := inv.Get(mac); ok {
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
func printReport(pipe *pipeline.Pipeline, inv *inventory.Inventory) {
	if inv == nil || inv.Len() == 0 {
		return
	}
	ranked := pipe.Engine().Ranked(inv.Devices(), time.Now())
	if len(ranked) == 0 {
		return
	}
	fmt.Println("--- assessments ---")
	for _, a := range ranked {
		fmt.Println(a.Describe())
	}
}
