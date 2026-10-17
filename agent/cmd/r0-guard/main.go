// Command r0-guard is the R0-Invader control plane.
//
// It is pre-alpha. The daemon loop that will ingest telemetry, score
// devices, and push containment rules to a router is not implemented yet;
// what exists today is the type system, the pure-function detectors, and the
// actuator contract. This binary exists so that the wiring and the CLI
// surface are settled before the implementation fills in, and so that the
// build is exercised by CI.
//
// See docs/ROADMAP.md for what ships in v0.1.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/lanceh17/Ro-invader/agent/internal/act"
)

// version is stamped by the build. The default is what a plain `go install`
// produces, which is why CI and release builds set it via -ldflags.
var version = "dev"

const usage = `r0-guard — R0-Invader control plane (pre-alpha)

Usage:
  r0-guard <command>

Commands:
  version     Print build version and supported actuator backends
  help        Show this message

Status:
  v0.1 containment core is in progress. The daemon does not yet ingest
  telemetry or contain devices. See docs/ROADMAP.md.

This tool is passive by architecture: it never probes, scans, or transmits
to a managed device. See SAFETY.md.
`

func main() {
	cmd := "help"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	switch cmd {
	case "version":
		printVersion()
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
