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
		NewWeightTransferDetector(nil),
		NewEastWestVolumeDetector(nil),
		NewAuthFanoutDetector(0),
		NewBurstDetector(0, 0),
		NewBeaconDetector(0, 0, nil),
		NewInferenceEngineDetector(nil),
		NewNewDeviceDetector(0),
	}
}

// EvalAll evaluates all detectors on a slice of events and returns all signals
// that fired across the entire detector set.
func EvalAll(events []core.NormalizedEvent) []core.Signal {
	var all []core.Signal
	for _, ev := range events {
		for _, d := range All() {
			for _, s := range d.Evaluate(ev) {
				all = append(all, s)
			}
		}
	}
	return all
}
