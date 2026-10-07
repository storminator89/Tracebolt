package gate

import (
	"strings"
	"testing"
	"time"

	"localrmm/internal/windowsacceptance/native"
)

func approvalFixture() (Approval, Environment, string) {
	sha := strings.Repeat("a", 40)
	return Approval{sha, true, true, true, true, true}, Environment{"workflow_dispatch", "true", "Windows", "github-hosted", Repository, sha, "123"}, sha
}
func TestManualSourceAuthorityDefaultsDeny(t *testing.T) {
	a, e, sha := approvalFixture()
	if _, err := Authorize(Approval{}, e, sha); err == nil {
		t.Fatal("default approvals accepted")
	}
	for _, mutate := range []func(*Approval, *Environment){
		func(a *Approval, e *Environment) { a.Services = false }, func(a *Approval, e *Environment) { a.Identity = false }, func(a *Approval, e *Environment) { a.AppACLs = false }, func(a *Approval, e *Environment) { a.LoopbackTLS = false }, func(a *Approval, e *Environment) { a.Cleanup = false },
		func(a *Approval, e *Environment) { a.ExpectedSource = strings.Repeat("b", 40) }, func(a *Approval, e *Environment) { e.Source = strings.Repeat("b", 40) }, func(a *Approval, e *Environment) { e.Event = "push" }, func(a *Approval, e *Environment) { e.Event = "pull_request" }, func(a *Approval, e *Environment) { e.RunnerEnvironment = "self-hosted" }, func(a *Approval, e *Environment) { e.RunnerOS = "Linux" }, func(a *Approval, e *Environment) { e.Repository = "foreign/repo" }, func(a *Approval, e *Environment) { e.Actions = "false" }, func(a *Approval, e *Environment) { e.RunID = "0" },
	} {
		aa, ee := a, e
		mutate(&aa, &ee)
		if _, err := Authorize(aa, ee, sha); err == nil {
			t.Fatal("unapproved environment or scope accepted")
		}
	}
	if _, err := Authorize(a, e, "unbound"); err == nil {
		t.Fatal("unbound executable accepted")
	}
}
func TestGrantIsBoundedAndRevocable(t *testing.T) {
	a, e, sha := approvalFixture()
	now := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	g, err := authorize(a, e, sha, func() time.Time { return now })
	if err != nil || !g.Check() {
		t.Fatal("valid fixture rejected")
	}
	now = now.Add(MaxLifetime)
	if g.Check() {
		t.Fatal("grant deadline extended")
	}
	now = now.Add(-MaxLifetime)
	g.Close()
	if g.Check() {
		t.Fatal("closed grant revived")
	}
}
func TestReportRejectsFalseFullAcceptanceAndMissingChecks(t *testing.T) {
	_, _, sha := approvalFixture()
	r := NewReport(sha)
	r.Status = "passed_native_subset"
	r.Stage = "owned_cleanup"
	r.NativeActionsAttempted = true
	for i := range r.Checks {
		r.Checks[i].Status = "pass"
	}
	r.Native = native.Evidence{Stage: native.StageCleanup, Reason: native.ReasonNone, Prerequisites: true, Provisioned: true, Installed: false, Prepared: true, ClaimCommitted: true, Ready: true, Stopped: true, Cleaned: true, Uninstalled: true, LimitedToken: true, IdentityRetained: true, SenderFloorRetained: true, PendingBytesRetained: true, UnrelatedServiceDenied: true, UninstallStateRetained: true}
	if _, err := Encode(r); err != nil {
		t.Fatal("finite fixture report rejected")
	}
	for _, mutate := range []func(*Report){func(r *Report) { r.OSRebootExercised = true }, func(r *Report) { r.OSShutdownExercised = true }, func(r *Report) { r.ProductionManagerExercised = true }, func(r *Report) { r.HiddenConsoleExercised = true }, func(r *Report) { r.BroadAncestorACLChanged = true }, func(r *Report) { r.RawTelemetryExported = true }, func(r *Report) { r.SecretsExported = true }, func(r *Report) { r.Checks = append([]Check{}, r.Checks...); r.Checks[0].Status = "not_run" }, func(r *Report) { r.Native.UninstallStateRetained = false }, func(r *Report) { r.Native.Reason = "private-error" }} {
		rr := r
		mutate(&rr)
		if Validate(rr) == nil {
			t.Fatal("false or unsafe acceptance allowed")
		}
	}
}
func TestBlockedReportCannotContainMutationClaim(t *testing.T) {
	_, _, sha := approvalFixture()
	r := NewReport(sha)
	r.Status = "blocked"
	r.Reason = native.ReasonPrerequisite
	r.Mark("prerequisites", "blocked")
	if Validate(r) != nil {
		t.Fatal("honest blocked report rejected")
	}
	r.NativeActionsAttempted = true
	if Validate(r) == nil {
		t.Fatal("mutation report relabeled as preflight block")
	}
}
