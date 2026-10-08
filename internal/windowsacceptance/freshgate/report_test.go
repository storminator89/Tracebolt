package freshgate

import (
	"encoding/json"
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

func passingFreshReport() Report {
	r := NewReport(strings.Repeat("a", 40))
	r.Status = "passed_fresh_native_subset"
	r.ControllerStage = "completed"
	r.SessionOutcome = "passed"
	r.NaturalChildExit = "zero"
	r.CoordinatorPhase = "configured"
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
	return r
}

func TestFreshSuccessfulStopDoesNotClaimDisabledOrDisposal(t *testing.T) {
	r := passingFreshReport()
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

var diagnosticCases = []struct {
	name   string
	values []string
	set    func(*Report, string)
}{
	{"outputRejection", []string{"none", "output_limit", "echo", "escape_unsupported", "csi_limit", "csi_unsupported", "csi_malformed", "osc_limit", "osc_malformed", "osc_unsupported", "post_input_title", "carriage_return", "text_unsupported", "line_limit", "protocol", "incomplete", "state"}, func(r *Report, value string) { r.OutputRejection = OutputRejection(value) }},
	{"controllerStage", []string{"not_started", "provisioning", "fixture", "bootstrap", "launch", "session", "verify_completed", "observe_inventory", "completed"}, func(r *Report, value string) { r.ControllerStage = value }},
	{"sessionOutcome", []string{"not_run", "invalid_steps", "cancelled", "output_rejected", "output_read_failed", "output_eof_missing", "input_failed", "approval_failed", "child_unsuccessful", "protocol_incomplete", "passed"}, func(r *Report, value string) { r.SessionOutcome = SessionOutcome(value) }},
	{"naturalChildExit", []string{"unknown", "zero", "nonzero"}, func(r *Report, value string) { r.NaturalChildExit = value }},
	{"coordinatorPhase", []string{"unknown", "install-started", "claim-started", "activation-started", "grants-started", "grants-incomplete", "grants-verified", "startup-transition-started", "configured"}, func(r *Report, value string) { r.CoordinatorPhase = value }},
}

func TestFreshDiagnosticsDefaultsAndFiniteFailureEvidence(t *testing.T) {
	r := NewReport(strings.Repeat("a", 40))
	raw, err := r.Encode()
	if err != nil {
		t.Fatal("blocked default report rejected")
	}
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil {
		t.Fatal("report encoding rejected")
	}
	defaults := map[string]string{"outputRejection": "none", "controllerStage": "not_started", "sessionOutcome": "not_run", "naturalChildExit": "unknown", "coordinatorPhase": "unknown"}
	for _, field := range diagnosticCases {
		t.Run(field.name, func(t *testing.T) {
			if fields[field.name] != defaults[field.name] {
				t.Fatal("required diagnostic default missing")
			}
			for _, value := range field.values {
				x := r
				x.Status = "failed"
				x.ApprovalValidated = true
				x.NativeActionsAttempted = true
				field.set(&x, value)
				if _, err := x.Encode(); err != nil {
					t.Fatalf("finite failure evidence %q rejected", value)
				}
				for _, status := range []string{"blocked", "failed"} {
					x = r
					x.Status = status
					field.set(&x, value)
					if (x.Validate() == nil) != (value == defaults[field.name]) {
						t.Fatal("diagnostics imply unattempted native actions")
					}
				}
			}
		})
	}
}

func TestFreshDiagnosticsRejectArbitraryStringsAndTypes(t *testing.T) {
	for _, field := range diagnosticCases {
		t.Run(field.name, func(t *testing.T) {
			for _, value := range []string{"", "raw private diagnostic", "PASSED", "0", "1", "passed\n"} {
				r := passingFreshReport()
				r.Status = "failed"
				field.set(&r, value)
				if _, err := r.Encode(); err == nil {
					t.Fatal("arbitrary diagnostic string accepted")
				}
			}
			for _, value := range []any{nil, true, false, 0, 1.5, []any{}, map[string]any{}} {
				raw, err := passingFreshReport().Encode()
				if err != nil {
					t.Fatal("valid report rejected")
				}
				var fields map[string]any
				if json.Unmarshal(raw, &fields) != nil {
					t.Fatal("report decoding failed")
				}
				fields[field.name] = value
				raw, err = json.Marshal(fields)
				if err != nil {
					t.Fatal("fixture encoding failed")
				}
				var decoded Report
				if json.Unmarshal(raw, &decoded) == nil && decoded.Validate() == nil {
					t.Fatal("non-string diagnostic accepted")
				}
			}
		})
	}
}

func TestFreshDiagnosticsDoNotPromoteSuccess(t *testing.T) {
	expected := map[string]string{"outputRejection": "none", "controllerStage": "completed", "sessionOutcome": "passed", "naturalChildExit": "zero", "coordinatorPhase": "configured"}
	for _, field := range diagnosticCases {
		t.Run(field.name, func(t *testing.T) {
			for _, value := range field.values {
				r := passingFreshReport()
				field.set(&r, value)
				if (r.Validate() == nil) != (value == expected[field.name]) {
					t.Fatalf("incompatible success diagnostic %q", value)
				}
				// Cleanup can still fail after all four diagnostic milestones.
				r.Status = "failed"
				if r.Validate() != nil {
					t.Fatal("finite nonpassing evidence rejected")
				}
			}
		})
	}
}
