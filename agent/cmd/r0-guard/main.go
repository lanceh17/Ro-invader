// Command r0-guard is the R0-Invader control plane.
//
// The daemon loop that will continuously ingest telemetry and push containment
// rules to a router is still in progress; see docs/ROADMAP.md. What ships today
// is the detection half wired end to end: `analyze` reads a Suricata EVE file,
// normalizes it, runs the detectors, scores each device with exponential
// decay, and reports the recommended containment tier. It reads and reports
// only — it never contacts a router or a device.
//
// This tool is passive by architecture: it never probes, scans, or transmits
// to a managed device. See SAFETY.md.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/act"
	"github.com/lanceh17/Ro-invader/agent/internal/detect"
	"github.com/lanceh17/Ro-invader/agent/internal/ingest/suricata"
	"github.com/lanceh17/Ro-invader/agent/internal/inventory"
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
  help        Show this message

Analyze flags:
  -eve <path>          Suricata EVE JSON file to read (required)
  -inventory <path>    JSON device inventory for attribution and classification
  -half-life <dur>     Risk score decay half-life (default 72h)

Status:
  v0.1 containment core is in progress. analyze reads and reports; it does not
  contact a router or contain devices. See docs/ROADMAP.md.

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

	// Run every detector over every event and feed the resulting signals into
	// the risk engine. Detectors are pure functions, so this loop is the only
	// place the pipeline has any side effects: it mutates the engine.
	// WithHalfLife, not WithConfig: the latter takes a full Config, and a
	// partial one would zero out RequireCorroboration and let a single
	// signal escalate a device. That is the opposite of what this tool is
	// for.
	engine := risk.New(risk.WithHalfLife(*halfLife))
	detectors := detect.All()

	var signals int
	for _, ev := range events {
		for _, d := range detectors {
			for _, s := range d.Evaluate(ev) {
				engine.Observe(s, ev.Time)
				signals++
			}
		}
	}

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

	ranked := engine.Ranked(inv.Devices(), time.Time{})
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
