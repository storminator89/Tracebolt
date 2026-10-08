package profile

import "testing"

func usableExtensions() ExtensionObservation {
	return ExtensionObservation{Frames: 1, V5Frames: 1, EventApplication: "observed", EventSystem: "bounded", Volumes: "observed", VolumeCapacity: "observed", ProcessCPU: "observed", ProcessMemory: "observed", Network: "observed", NetworkRows: 1, PeerLoopbackRows: 1, VolumeRows: 1, ProcessRows: 1, VolumeCapacityCounts: QualityCounts{Observed: 1}, ProcessCPUCounts: QualityCounts{Observed: 1}, ProcessMemoryCounts: QualityCounts{Observed: 1}}
}
func TestExtensionObservationFiniteTruth(t *testing.T) {
	if ZeroExtensionObservation().Validate() != nil || ZeroExtensionObservation().Usable() || (ExtensionObservation{}).Validate() == nil {
		t.Fatal("zero contract")
	}
	o := usableExtensions()
	if o.Validate() != nil || !o.Usable() {
		t.Fatal("valid contract")
	}
	for _, mutate := range []func(*ExtensionObservation){func(o *ExtensionObservation) { o.Frames = 65 }, func(o *ExtensionObservation) { o.PeerLoopbackRows = 2 }, func(o *ExtensionObservation) { o.V5Frames = 0 }, func(o *ExtensionObservation) { o.EventRows = 33 }, func(o *ExtensionObservation) { o.NetworkRows = 65 }, func(o *ExtensionObservation) { o.Network = "secret" }, func(o *ExtensionObservation) { o.VolumeCapacityCounts.Denied = 1 }, func(o *ExtensionObservation) { o.ProcessCPUFirstSampleRows = 1 }, func(o *ExtensionObservation) { o.ProcessMemoryCounts.FirstSample = 1 }} {
		b := o
		mutate(&b)
		if b.Validate() == nil {
			t.Fatal("invalid counts or quality admitted")
		}
	}
	emptyNetwork := o
	emptyNetwork.PeerLoopbackRows = 0
	if emptyNetwork.Validate() != nil || emptyNetwork.Usable() {
		t.Fatal("unproven peer endpoint passed")
	}
	o.ProcessRows = 2
	o.ProcessCPUCounts.Denied = 1
	o.ProcessMemoryCounts.Unavailable = 1
	o.ProcessCPU = "partial"
	o.ProcessMemory = "partial"
	if o.Validate() != nil || !o.Usable() {
		t.Fatal("honest mixed rows must not require broader rights")
	}
	o.ProcessCPUCounts = QualityCounts{FirstSample: 2}
	o.ProcessCPUFirstSampleRows = 2
	o.ProcessCPU = "first-sample"
	if o.Validate() != nil || o.Usable() {
		t.Fatal("first sample became CPU delta proof")
	}
	o.ProcessCPUCounts = QualityCounts{Denied: 2}
	o.ProcessCPUFirstSampleRows = 0
	o.ProcessCPU = "denied"
	if o.Validate() != nil || o.Usable() {
		t.Fatal("all denied passed")
	}
}

func TestExtensionObservationNeverClaimsFreshOrchestration(t *testing.T) {
	o := ZeroExtensionObservation()
	o.FreshOrchestrationAcceptance = true
	if o.Validate() == nil || o.Usable() {
		t.Fatal("fresh installer coverage invented")
	}
}
