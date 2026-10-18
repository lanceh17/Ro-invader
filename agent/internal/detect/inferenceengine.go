package detect

import (
	"strings"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

// DefaultInferenceServerSignatures are the fingerprints of common inference
// servers. A device running one of these on the LAN — rather than a dedicated
// server — is a strong indicator of local model serving.
var DefaultInferenceServerSignatures = []struct {
	// SNI or hostname the server presents
	sni string
	// HTTP header or path component that identifies the server
	header string
}{
	{sni: "vllm.ai", header: "vllm"},
	{sni: "ollama.com", header: "ollama"},
	{sni: "github.com", header: "llama.cpp"},     // model downloads
	{sni: "huggingface.co", header: "inference"}, // inference API
}

// InferenceEngineDetector implements signal R3: an inference server signature
// on a non-server device.
//
// This is a [core.SignalPoCArtifact] signal. A motivated adversary could run
// inference under a custom server name, but most prototypes use the default
// endpoints and headers.
type InferenceEngineDetector struct {
	signatures []struct {
		sni    string
		header string
	}
}

// NewInferenceEngineDetector returns a detector firing on inference server
// signatures. A nil signatures slice falls back to DefaultInferenceServerSignatures.
func NewInferenceEngineDetector(signatures []struct{ sni, header string }) *InferenceEngineDetector {
	if signatures == nil {
		signatures = DefaultInferenceServerSignatures
	}
	out := make([]struct{ sni, header string }, len(signatures))
	copy(out, signatures)
	return &InferenceEngineDetector{signatures: out}
}

// Kind identifies this detector's signal.
func (d *InferenceEngineDetector) Kind() core.SignalKind { return core.SignalInferenceEngine }

// Evaluate reports a signal when the event carries an inference server signature.
//
// Looks at SNI for TLS events and at a synthetic check for flow events.
// In production this would need HTTP header inspection, which Suricata's EVE
// provides in the http section; for now we flag based on SNI/hostname matches.
func (d *InferenceEngineDetector) Evaluate(e core.NormalizedEvent) []core.Signal {
	if len(e.DeviceMAC) == 0 {
		return nil
	}

	host := firstNonEmpty(e.SNI, e.QueryName)
	if host == "" {
		return nil
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))

	for _, sig := range d.signatures {
		if strings.Contains(host, strings.ToLower(sig.sni)) ||
			strings.Contains(host, strings.ToLower(sig.header)) {
			return []core.Signal{{
				Kind:       core.SignalInferenceEngine,
				Class:      core.SignalPoCArtifact,
				DeviceMAC:  e.DeviceMAC,
				Weight:     15,
				Confidence: 0.5,
				Reason:     "inference server signature detected (" + host + ")",
				Evidence: map[string]any{
					"host": host,
					"sni":  e.SNI,
				},
			}}
		}
	}
	return nil
}

// ShouldSuppressDeviceClass reports whether this signal kind is suppressed for
// the given device class. It is the stable public hook that the pipeline and the
// risk engine call, so that the suppression rule is one place and not a
// duplicated switch in every detector.
func (d *InferenceEngineDetector) ShouldSuppressDeviceClass(cls core.DeviceClass) bool {
	return d.suppressed(cls)
}

// suppressed reports whether a signal whose class matters should be suppressed
// for the given device class.
func (d *InferenceEngineDetector) suppressed(cls core.DeviceClass) bool {
	// Workstations, servers, and mobile devices are expected to open many
	// connections, run inference, and use non-standard ports for development.
	// Cameras, IoT, and appliances are not.
	switch cls {
	case core.ClassWorkstation, core.ClassServer, core.ClassMobile:
		return true
	default:
		return false
	}
}

var _ = strings.Contains // keep import

// InferenceEngineDetector satisfies driftInspector so the pipeline can reach its
// ShouldSuppressDeviceClass without casting.
var _ interface {
	ShouldSuppressDeviceClass(core.DeviceClass) bool
} = (*InferenceEngineDetector)(nil)
