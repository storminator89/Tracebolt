package setupgate

import (
	"strings"
	"testing"
	"time"

	"localrmm/internal/windowsacceptance/fixture"
	"localrmm/internal/windowsacceptance/profile"
)

func authorized() (map[string]string, Binding, time.Time) {
	now := time.Unix(1900000000, 0)
	b := Binding{Source: strings.Repeat("a", 40), CompiledSource: strings.Repeat("a", 40), DriverHash: strings.Repeat("b", 64), SetupHash: strings.Repeat("c", 64), ServiceHash: strings.Repeat("d", 64), SourceInputsHash: strings.Repeat("e", 64), RunID: "12", Machine: "fresh-vm", Case: Cases[0], Deadline: now.Add(14 * time.Minute)}
	e := map[string]string{"GITHUB_SHA": b.Source, "TRACEBOLT_SETUP_SOURCE": b.Source, "TRACEBOLT_SETUP_PROFILE": Profile, "TRACEBOLT_SETUP_CASE": b.Case, "TRACEBOLT_SETUP_MACHINE": b.Machine, "COMPUTERNAME": b.Machine, "GITHUB_REPOSITORY": "storminator89/Tracebolt", "GITHUB_REPOSITORY_OWNER": "storminator89", "GITHUB_REPOSITORY_OWNER_ID": "30489872", "GITHUB_ACTOR": "storminator89", "GITHUB_ACTOR_ID": "30489872", "GITHUB_TRIGGERING_ACTOR": "storminator89", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_ACTIONS": "true", "RUNNER_OS": "Windows", "RUNNER_ARCH": "X64", "RUNNER_ENVIRONMENT": "github-hosted", "GITHUB_RUN_ID": "12", "TRACEBOLT_SETUP_RUN_ID": "12", "TRACEBOLT_SETUP_DRIVER_SHA256": b.DriverHash, "TRACEBOLT_SETUP_SETUP_SHA256": b.SetupHash, "TRACEBOLT_SETUP_SERVICE_SHA256": b.ServiceHash, "TRACEBOLT_SETUP_SOURCE_INPUTS_SHA256": b.SourceInputsHash}
	for _, a := range Approvals {
		e["TRACEBOLT_SETUP_APPROVE_"+a] = "true"
	}
	return e, b, now
}
func TestExactAuthorizationFailClosed(t *testing.T) {
	e, b, n := authorized()
	if Authorize(e, b, n) != nil {
		t.Fatal("valid inert binding rejected")
	}
	for key := range e {
		old := e[key]
		e[key] = ""
		if Authorize(e, b, n) == nil {
			t.Fatal("missing binding accepted", key)
		}
		e[key] = old
	}
	for _, a := range Approvals {
		e["TRACEBOLT_SETUP_APPROVE_"+a] = "false"
		if Authorize(e, b, n) == nil {
			t.Fatal("false approval")
		}
		e["TRACEBOLT_SETUP_APPROVE_"+a] = "true"
	}
	if Authorize(e, b, b.Deadline) == nil {
		t.Fatal("expired")
	}
}
func TestFiniteReportCoverageAndIndeterminateTruth(t *testing.T) {
	e, b, _ := authorized()
	_ = e
	for _, which := range Cases {
		b.Case = which
		r := NewReport(b)
		if r.Validate() != nil {
			t.Fatal("initial")
		}
		r.Status = "passed_packaged_gui_subset"
		r.Stage = "completed"
		r.Reason = "none"
		r.ApprovalValidated = true
		r.NativeActionsAttempted = true
		r.PlatformDisposalRequired = true
		r.Startup = "disabled"
		if NormalCase(which) {
			r.Startup = "absent"
			r.Frames = 2
			r.FrameProgress = setupGateFrameProgressFixture()
		}
		for k := range r.Checks {
			r.Checks[k] = true
		}
		if r.Validate() != nil {
			t.Fatal("pass")
		}
		r.Startup = "inspection_required"
		if r.Validate() == nil {
			t.Fatal("unknown startup passed")
		}
		r.Startup = "disabled"
		r.Coverage["humanUAC"] = true
		if r.Validate() == nil {
			t.Fatal("invented coverage")
		}
	}
}

// Finite invented quality/counts only. No fixture server or collector is started.
func setupGateFrameProgressFixture() FrameProgress {
	observed := profile.QualityCounts{Observed: 1}
	return FrameProgress{Reason: "complete", AcceptedFrames: 2,
		Inventory:  profile.Observation{Frames: 2, CPU: "healthy", Memory: "healthy", Disk: "healthy", Hostname: "healthy", Processes: "healthy", Services: "healthy", Software: "healthy", Interfaces: "healthy"},
		Extensions: profile.ExtensionObservation{Frames: 2, V5Frames: 2, EventApplication: "observed", EventSystem: "observed", Volumes: "observed", VolumeCapacity: "observed", ProcessCPU: "observed", ProcessMemory: "observed", Network: "observed", EventRows: 1, VolumeRows: 1, ProcessRows: 1, NetworkRows: 1, PeerLoopbackRows: 1, VolumeCapacityCounts: observed, ProcessCPUCounts: observed, ProcessMemoryCounts: observed},
		Telemetry:  fixture.TelemetryObservation{Admitted: 2, Accepted: 2},
	}
}
