package lab

import (
	"testing"
)

func TestContainmentReducesR0Below1(t *testing.T) {
	control := NewSimulation(Config{
		N:                  50,
		SpreadRate:         0.3,
		ContainmentEnabled: false,
		Seed:               42,
	}).Run(50)

	treatment := NewSimulation(Config{
		N:                  50,
		SpreadRate:         0.3,
		ContainmentEnabled: true,
		Seed:               42,
	}).Run(50)

	t.Logf("Control:   R0=%.2f infections=%d steps=%d", control.R0, control.TotalInfections, control.Steps)
	t.Logf("Treatment: R0=%.2f infections=%d contained=%d steps=%d",
		treatment.R0, treatment.TotalInfections, treatment.ContainedDevices, treatment.Steps)

	if control.R0 <= treatment.R0 {
		t.Errorf("control R0 (%.2f) should exceed treatment R0 (%.2f)", control.R0, treatment.R0)
	}
	if treatment.TotalInfections >= control.TotalInfections {
		t.Errorf("treatment infections (%d) >= control (%d)",
			treatment.TotalInfections, control.TotalInfections)
	}
	if treatment.R0 >= 1.0 {
		t.Errorf("treatment R0 = %.2f, want < 1", treatment.R0)
	}
}
