package gate

import (
	"strings"
	"testing"
	"time"

	"localrmm/internal/windowsacceptance/native"
	"localrmm/internal/windowsacceptance/profile"
)

func approvalFixture() (Approval, Environment, string) {
	sha := strings.Repeat("a", 40)
	return Approval{ExpectedSource: sha, Services: true, Identity: true, AppACLs: true, Loopback: true, Cleanup: true, Selection: profile.BasicTLS()}, Environment{"workflow_dispatch", "true", "Windows", "github-hosted", Repository, sha, "123"}, sha
}
func TestManualSourceAuthorityDefaultsDeny(t *testing.T) {
	a, e, sha := approvalFixture()
	if _, err := Authorize(Approval{}, e, sha); err == nil {
		t.Fatal("default approvals accepted")
	}
	for _, mutate := range []func(*Approval, *Environment){
		func(a *Approval, e *Environment) { a.Services = false }, func(a *Approval, e *Environment) { a.Identity = false }, func(a *Approval, e *Environment) { a.AppACLs = false }, func(a *Approval, e *Environment) { a.Loopback = false }, func(a *Approval, e *Environment) { a.Cleanup = false },
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
	r.LoopbackPeerExercised = true
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

func TestProfileScopeRequiresExactSeparateApprovals(t *testing.T) {
	for _, selected := range []profile.Selection{profile.BasicTLS(), profile.InventoryTLS(), {CollectionProfile: "windows-inventory-v1", Transport: "http-test"}} {
		a, e, sha := approvalFixture()
		a.Selection = selected
		a.InventoryMetadata = selected.Inventory()
		a.HTTPPlaintext = selected.HTTPTest()
		g, err := Authorize(a, e, sha)
		if err != nil || g.Selection() != selected {
			t.Fatal("approved profile rejected")
		}
		g.Close()
		for _, change := range []func(*Approval){func(a *Approval) { a.InventoryMetadata = !a.InventoryMetadata }, func(a *Approval) { a.HTTPPlaintext = !a.HTTPPlaintext }, func(a *Approval) { a.Selection.Transport = "unexpected" }} {
			next := a
			change(&next)
			if _, err := Authorize(next, e, sha); err == nil {
				t.Fatal("profile grant widened or omitted")
			}
		}
	}
	a, e, sha := approvalFixture()
	a.Selection.Transport = "http-test"
	a.HTTPPlaintext = true
	if _, err := Authorize(a, e, sha); err == nil {
		t.Fatal("basic HTTP accepted")
	}
}
func TestInventoryReportRequiresUsableNativeScope(t *testing.T) {
	_, _, sha := approvalFixture()
	r := NewSelectedReport(sha, profile.InventoryTLS())
	if Validate(r) != nil {
		t.Fatal("initial inventory report invalid")
	}
	r.NativeActionsAttempted = true
	r.Inventory = profile.Observation{Frames: 1, CPU: "healthy", Memory: "healthy", Disk: "healthy", Hostname: "healthy", Processes: "partial", Services: "denied", Software: "healthy", Interfaces: "healthy"}
	r.LoopbackPeerExercised = true
	r.NativeInventorySenderExercised = true
	if Validate(r) != nil || r.Inventory.Usable() {
		t.Fatal("denied observation obscured")
	}
	r.ProductionIngressExercised = true
	if Validate(r) == nil {
		t.Fatal("peer relabeled production ingress")
	}
}

func TestExpandedRequiresEveryFreshScopeAndInventory(t *testing.T) {
	for mask := 0; mask < 16; mask++ {
		for _, selected := range []profile.Selection{profile.BasicTLS(), profile.InventoryTLS(), {CollectionProfile: "windows-inventory-v1", Transport: "http-test"}} {
			a, e, sha := approvalFixture()
			a.Selection = selected
			a.InventoryMetadata = selected.Inventory()
			a.HTTPPlaintext = selected.HTTPTest()
			a.EventHeaders = mask&1 != 0
			a.VisibleVolumes = mask&2 != 0
			a.ProcessMetrics = mask&4 != 0
			a.NetworkEndpoints = mask&8 != 0
			g, err := Authorize(a, e, sha)
			allowed := mask == 0 || mask == 15 && selected.Inventory()
			if (err == nil) != allowed {
				t.Fatalf("wrong extension admission mask=%d", mask)
			}
			if allowed && g.ExtensionsApproved() != (mask == 15) {
				t.Fatal("scope changed")
			}
		}
	}
}
func TestExpandedReportCannotReuseBaseEvidence(t *testing.T) {
	_, _, sha := approvalFixture()
	r := NewSelectedReport(sha, profile.InventoryTLS())
	r.Schema = ExpandedSchema
	if Validate(r) == nil {
		t.Fatal("missing expanded evidence accepted")
	}
	z := profile.ZeroExtensionObservation()
	r.Extensions = &z
	if Validate(r) != nil {
		t.Fatal("finite not-run expanded failure rejected")
	}
	r.Schema = Schema
	if Validate(r) == nil {
		t.Fatal("expanded evidence smuggled into v2")
	}
	r.Schema = ExpandedSchema
	r.Selection = profile.BasicTLS()
	if Validate(r) == nil {
		t.Fatal("basic identity expanded")
	}
}
