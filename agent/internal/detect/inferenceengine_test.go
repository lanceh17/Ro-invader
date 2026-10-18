package detect

import (
	"testing"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

func TestInferenceEngineDetector_FiresOnVLLMSignature(t *testing.T) {
	d := NewInferenceEngineDetector(nil)

	e := baseTLSEvent()
	e.SNI = "vllm.ai"

	got := d.Evaluate(e)
	if len(got) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(got))
	}
	sig := got[0]
	if sig.Kind != core.SignalInferenceEngine {
		t.Errorf("Kind = %q, want %q", sig.Kind, core.SignalInferenceEngine)
	}
	if sig.Class != core.SignalPoCArtifact {
		t.Errorf("Class = %q, want %q", sig.Class, core.SignalPoCArtifact)
	}
	if sig.Reason == "" {
		t.Error("Reason must be non-empty")
	}
}

func TestInferenceEngineDetector_FiresOnOllamaSignature(t *testing.T) {
	d := NewInferenceEngineDetector(nil)

	e := baseTLSEvent()
	e.SNI = "ollama.com"

	got := d.Evaluate(e)
	if len(got) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(got))
	}
}

func TestInferenceEngineDetector_FiresOnHuggingfaceInference(t *testing.T) {
	d := NewInferenceEngineDetector(nil)

	e := baseTLSEvent()
	e.SNI = "huggingface.co"

	got := d.Evaluate(e)
	if len(got) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(got))
	}
}

func TestInferenceEngineDetector_RejectsUnknownHosts(t *testing.T) {
	d := NewInferenceEngineDetector(nil)

	e := baseTLSEvent()
	e.SNI = "example.com"

	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("unknown host should not fire, got %d signals", len(got))
	}
}

func TestInferenceEngineDetector_RequiresDeviceMAC(t *testing.T) {
	d := NewInferenceEngineDetector(nil)

	e := baseTLSEvent()
	e.DeviceMAC = nil

	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("unattributable event should not fire, got %d signals", len(got))
	}
}

func TestInferenceEngineDetector_RequiresHostName(t *testing.T) {
	d := NewInferenceEngineDetector(nil)

	e := baseTLSEvent()
	e.SNI = ""
	e.QueryName = ""

	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("event without SNI or query name should not fire, got %d signals", len(got))
	}
}

func TestInferenceEngineDetector_FallbackToQueryName(t *testing.T) {
	d := NewInferenceEngineDetector(nil)

	e := baseTLSEvent()
	e.SNI = ""
	e.QueryName = "ollama.com"

	got := d.Evaluate(e)
	if len(got) != 1 {
		t.Errorf("should fall back to QueryName, got %d signals", len(got))
	}
}

func TestInferenceEngineDetector_CaseInsensitive(t *testing.T) {
	d := NewInferenceEngineDetector(nil)

	e := baseTLSEvent()
	e.SNI = "VLLM.AI" // Uppercase

	got := d.Evaluate(e)
	if len(got) != 1 {
		t.Errorf("case-insensitive match should fire, got %d signals", len(got))
	}
}

func TestInferenceEngineDetector_SubdomainMatching(t *testing.T) {
	d := NewInferenceEngineDetector(nil)

	// The detector uses strings.Contains for matching
	e := baseTLSEvent()
	e.SNI = "sub.ollama.com"

	got := d.Evaluate(e)
	if len(got) != 1 {
		t.Errorf("subdomain should match, got %d signals", len(got))
	}
}

func TestInferenceEngineDetector_SignalKind(t *testing.T) {
	d := NewInferenceEngineDetector(nil)

	if d.Kind() != core.SignalInferenceEngine {
		t.Errorf("Kind = %v, want SignalInferenceEngine", d.Kind())
	}
}

func TestInferenceEngineDetector_SignalClassIsPoCArtifact(t *testing.T) {
	d := NewInferenceEngineDetector(nil)

	e := baseTLSEvent()
	e.SNI = "vllm.ai"

	got := d.Evaluate(e)
	if len(got) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(got))
	}
	if got[0].Class != core.SignalPoCArtifact {
		t.Errorf("Class = %v, want SignalPoCArtifact", got[0].Class)
	}
}

func TestInferenceEngineDetector_SuppressionForWorkstation(t *testing.T) {
	d := NewInferenceEngineDetector(nil)

	// Workstations, servers, mobile should be suppressed
	if !d.ShouldSuppressDeviceClass(core.ClassWorkstation) {
		t.Error("Workstation should be suppressed")
	}
	if !d.ShouldSuppressDeviceClass(core.ClassServer) {
		t.Error("Server should be suppressed")
	}
	if !d.ShouldSuppressDeviceClass(core.ClassMobile) {
		t.Error("Mobile should be suppressed")
	}

	// IoT, camera, appliance should NOT be suppressed
	if d.ShouldSuppressDeviceClass(core.ClassIoT) {
		t.Error("IoT should not be suppressed")
	}
	if d.ShouldSuppressDeviceClass(core.ClassCamera) {
		t.Error("Camera should not be suppressed")
	}
	if d.ShouldSuppressDeviceClass(core.ClassAppliance) {
		t.Error("Appliance should not be suppressed")
	}
}

func TestInferenceEngineDetector_CustomSignatures(t *testing.T) {
	d := NewInferenceEngineDetector([]struct {
		sni    string
		header string
	}{
		{sni: "custom.inference.local", header: "custom"},
	})

	e := baseTLSEvent()
	e.SNI = "custom.inference.local"

	got := d.Evaluate(e)
	if len(got) != 1 {
		t.Errorf("custom signature should fire, got %d signals", len(got))
	}

	// Default signatures should not work
	e.SNI = "vllm.ai"
	if got := d.Evaluate(e); len(got) != 0 {
		t.Errorf("default signature should not fire with custom config, got %d signals", len(got))
	}
}

func TestInferenceEngineDetector_NilSignaturesUsesDefaults(t *testing.T) {
	d := NewInferenceEngineDetector(nil)

	e := baseTLSEvent()
	e.SNI = "vllm.ai"

	if got := d.Evaluate(e); len(got) != 1 {
		t.Errorf("default signatures should be used when nil, got %d signals", len(got))
	}
}

func TestInferenceEngineDetector_IsPure(t *testing.T) {
	d := NewInferenceEngineDetector(nil)

	e := baseTLSEvent()
	e.SNI = "vllm.ai"

	a := d.Evaluate(e)
	b := d.Evaluate(e)

	if len(a) != len(b) {
		t.Fatalf("non-deterministic: %d then %d signals", len(a), len(b))
	}
	if len(a) > 0 && a[0].Reason != b[0].Reason {
		t.Errorf("non-deterministic reason: %q then %q", a[0].Reason, b[0].Reason)
	}
}

func TestInferenceEngineDetector_SuppressionForMobile(t *testing.T) {
	d := NewInferenceEngineDetector(nil)

	if !d.ShouldSuppressDeviceClass(core.ClassMobile) {
		t.Error("Mobile should be suppressed")
	}
	if !d.ShouldSuppressDeviceClass(core.ClassWorkstation) {
		t.Error("Workstation should be suppressed")
	}
	if !d.ShouldSuppressDeviceClass(core.ClassServer) {
		t.Error("Server should be suppressed")
	}

	if d.ShouldSuppressDeviceClass(core.ClassIoT) {
		t.Error("IoT should not be suppressed")
	}
	if d.ShouldSuppressDeviceClass(core.ClassCamera) {
		t.Error("Camera should not be suppressed")
	}
	if d.ShouldSuppressDeviceClass(core.ClassAppliance) {
		t.Error("Appliance should not be suppressed")
	}
}
