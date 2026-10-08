package freshgate

import (
	"localrmm/internal/windowsacceptance/profile"
	"strings"
	"testing"
)

func TestFreshEvidenceNeverPromotesFixtureOrHuman(t *testing.T) {
	r := NewReport(strings.Repeat("a", 40))
	if r.Validate() != nil {
		t.Fatal("blocked zero report")
	}
	for _, edit := range []func(*Report){func(r *Report) { r.FreshOrchestrationAcceptance = true }, func(r *Report) { r.HiddenConsoleExercised = true }, func(r *Report) { r.HumanEntry = true }, func(r *Report) { r.HumanManagerApproval = true }, func(r *Report) { r.ProductionManagerExercised = true }, func(r *Report) { r.SharedDashboardExercised = true }, func(r *Report) { r.Status = "passed_fresh_native_subset" }, func(r *Report) { r.Extensions.FreshOrchestrationAcceptance = true }} {
		x := r
		edit(&x)
		if x.Validate() == nil {
			t.Fatal("false promotion")
		}
	}
}

func TestFreshSuccessfulStopDoesNotClaimDisabledOrDisposal(t *testing.T) {
	r := NewReport(strings.Repeat("a", 40))
	r.Status = "passed_fresh_native_subset"
	r.ApprovalValidated = true
	r.NativeActionsAttempted = true
	r.HiddenConsoleExercised = true
	r.SyntheticInput = true
	r.NoEchoVerified = true
	r.DisabledStageVerified = true
	r.FreshOrchestrationAcceptance = true
	r.ReceiptAndGrantsVerified = true
	r.LimitedServiceTokenVerified = true
	r.OwnedChildReaped = true
	r.ConsoleClosed = true
	r.FixtureClosed = true
	r.AppStateRetainedForVMDisposal = true
	r.ServiceAndAppStateRetained = true
	r.PlatformDisposalRequired = true
	r.OwnedServiceStopped = true
	r.AutomaticStartConfigurationRetained = true
	r.Inventory = profile.Observation{Frames: 1, CPU: "healthy", Memory: "healthy", Disk: "healthy", Hostname: "healthy", Processes: "healthy", Services: "healthy", Software: "healthy", Interfaces: "healthy"}
	r.Extensions = profile.ExtensionObservation{Frames: 1, V5Frames: 1, EventApplication: "observed", EventSystem: "bounded", Volumes: "observed", VolumeCapacity: "observed", ProcessCPU: "observed", ProcessMemory: "observed", Network: "observed", NetworkRows: 1, PeerLoopbackRows: 1, VolumeRows: 1, ProcessRows: 1, VolumeCapacityCounts: profile.QualityCounts{Observed: 1}, ProcessCPUCounts: profile.QualityCounts{Observed: 1}, ProcessMemoryCounts: profile.QualityCounts{Observed: 1}}
	if r.Validate() != nil {
		t.Fatal("finite stop evidence refused")
	}
	for _, change := range []func(*Report){func(r *Report) { r.ServiceDisabled = true }, func(r *Report) { r.AutomaticStartConfigurationRetained = false }, func(r *Report) { r.OwnedServiceStopped = false }, func(r *Report) { r.VMDisposalVerified = true }, func(r *Report) { r.ApplicationCleanupVerified = true }, func(r *Report) { r.PlatformDisposalRequired = false }, func(r *Report) { r.ServiceAndAppStateRetained = false }} {
		x := r
		change(&x)
		if x.Validate() == nil {
			t.Fatal("stop/disposal truth promoted")
		}
	}
}
