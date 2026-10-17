package detect

import "github.com/lanceh17/Ro-invader/agent/internal/core"

// All returns the default detector set compiled into this build.
//
// It is a single choke point rather than a slice literal scattered through
// the CLI, so that adding a detector is one edit here and cannot silently
// leave the portal and the CLI running different sets.
//
// Each entry is a pure function; the caller supplies the NormalizedEvent and
// collects the Signals. Nothing here does I/O, so the whole set runs in a
// test with no Suricata and no hardware.
func All() []core.Detector {
	return []core.Detector{
		NewModelHostDetector(nil),
		// R7 carries its own baseline state (see DNSDriftDetector), which is
		// why it is constructed here rather than being a package-level
		// singleton: each caller gets an independent baseline.
		NewDNSDriftDetector(0, nil),
	}
}
