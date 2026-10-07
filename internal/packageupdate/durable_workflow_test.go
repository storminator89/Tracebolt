//go:build linux

package packageupdate_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"localrmm/internal/packageplan"
	"localrmm/internal/packageupdate"
	"localrmm/internal/packageupdatestore"
)

const operator = "operator_11111111111111111111111111111111"

func durableFixture(t *testing.T) (*packageupdatestore.Store, packageupdate.Binding, packageupdate.SimulationFixture, packageupdate.PrepareRequest, *time.Time, string) {
	t.Helper()
	ctx := context.Background()
	raw, e := os.ReadFile("../packageplan/testdata/plan.json")
	if e != nil {
		t.Fatal(e)
	}
	p, e := packageplan.Decode(ctx, raw)
	if e != nil {
		t.Fatal(e)
	}
	b := packageupdate.Binding{ManagerID: "manager_11111111111111111111111111111111", DeviceID: p.EndpointID, IncarnationDigest: p.IncarnationDigest, RootPolicyDigest: p.RootPolicyDigest, TransportProfile: "production-tls"}
	at := time.Unix(p.CreatedAt, 0).UTC()
	dir := filepath.Join(t.TempDir(), "private")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "updates.db")
	s, e := packageupdatestore.Create(ctx, path, b, at.Unix())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	f := packageupdate.SimulationFixture{EvidenceMode: "synthetic", Plan: p, Sources: []packageupdate.Source{{IdentityDigest: p.Packages[0].Archive.SourceIdentityDigest, Label: "Synthetic repository", Suite: "trixie", Component: "main"}}, Outcome: "success", RebootState: "required"}
	req := packageupdate.PrepareRequest{RequestID: "update_11111111111111111111111111111111", Packages: []packageupdate.Selection{{Name: "sample-bin", Architecture: "amd64"}}}
	return s, b, f, req, &at, path
}
func TestSQLiteManagerSelectionApprovalResultsAndCleanReopen(t *testing.T) {
	ctx := context.Background()
	s, b, f, req, at, path := durableFixture(t)
	m, e := packageupdate.NewSimulation(ctx, s, b, f, func() time.Time { return *at })
	if e != nil {
		t.Fatal(e)
	}
	if e = m.Prepare(ctx, b.DeviceID, operator, req); e != nil {
		t.Fatal(e)
	}
	v, e := m.View(ctx, b.DeviceID, *at)
	if e != nil || v.ExecutionMode != "simulation" || v.Available || v.Preview == nil || v.Job.State != packageupdate.PreviewReady {
		t.Fatal(v, e)
	}
	digest := v.Preview.Digest
	expires := v.Preview.ExpiresAt
	*at = at.Add(time.Second)
	if e = m.Prepare(ctx, b.DeviceID, operator, req); e != nil {
		t.Fatal(e)
	}
	v, e = m.View(ctx, b.DeviceID, *at)
	if e != nil || v.Preview.Digest != digest || v.Preview.ExpiresAt != expires {
		t.Fatal("duplicate prepare replaced evidence", e)
	}
	if e = m.Approve(ctx, b.DeviceID, operator, packageupdate.ApprovalRequest{RequestID: req.RequestID, PreviewDigest: digest}); e != nil {
		t.Fatal(e)
	}
	if e = m.StartPendingSimulation(ctx, b.DeviceID); e != nil {
		t.Fatal(e)
	}
	if e = m.StartPendingSimulation(ctx, b.DeviceID); e != nil {
		t.Fatal("duplicate dispatcher", e)
	}
	v, e = m.View(ctx, b.DeviceID, *at)
	if e != nil || v.Job.State != packageupdate.Verifying {
		t.Fatal(v, e)
	}
	v, e = m.View(ctx, b.DeviceID, *at)
	if e != nil || v.Job.State != packageupdate.Succeeded || v.Job.Result.Reboot.State != "required" || v.Preview.Digest != digest || v.Job.Result.Packages[0].Outcome != "verified" {
		t.Fatal(v, e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s2, e := packageupdatestore.OpenExisting(ctx, path, b)
	if e != nil {
		t.Fatal(e)
	}
	defer s2.Close()
	m2, e := packageupdate.NewSimulation(ctx, s2, b, f, func() time.Time { return *at })
	if e != nil {
		t.Fatal(e)
	}
	got, e := m2.ViewJob(ctx, b.DeviceID, req.RequestID, *at)
	if e != nil || got.Job.State != packageupdate.Succeeded || got.Preview.Digest != digest || got.Job.Result.Reboot.State != "required" {
		t.Fatal("reopen lost exact verified result", e)
	}
	req.RequestID = "update_22222222222222222222222222222222"
	if e = m2.Prepare(ctx, b.DeviceID, operator, req); e != nil {
		t.Fatal(e)
	}
	old, e := m2.ViewJob(ctx, b.DeviceID, "update_11111111111111111111111111111111", *at)
	if e != nil || old.Job.State != packageupdate.Succeeded || old.Available {
		t.Fatal("exact recovery substituted newest job", e)
	}
}
func TestManagerReopenNeverRelaunchesLostSimulationRunner(t *testing.T) {
	ctx := context.Background()
	s, b, f, req, at, path := durableFixture(t)
	m, e := packageupdate.NewSimulation(ctx, s, b, f, func() time.Time { return *at })
	if e != nil {
		t.Fatal(e)
	}
	if e = m.Prepare(ctx, b.DeviceID, operator, req); e != nil {
		t.Fatal(e)
	}
	v, e := m.View(ctx, b.DeviceID, *at)
	if e != nil {
		t.Fatal(e)
	}
	if e = m.Approve(ctx, b.DeviceID, operator, packageupdate.ApprovalRequest{RequestID: req.RequestID, PreviewDigest: v.Preview.Digest}); e != nil {
		t.Fatal(e)
	}
	if e = m.StartPendingSimulation(ctx, b.DeviceID); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s2, e := packageupdatestore.OpenExisting(ctx, path, b)
	if e != nil {
		t.Fatal(e)
	}
	defer s2.Close()
	m2, e := packageupdate.NewSimulation(ctx, s2, b, f, func() time.Time { return *at })
	if e != nil {
		t.Fatal(e)
	}
	if e = m2.StartPendingSimulation(ctx, b.DeviceID); e != nil {
		t.Fatal(e)
	} // status-only recovery, no second Start
	v, e = m2.View(ctx, b.DeviceID, *at)
	if e != nil || v.Job.State != packageupdate.NeedsIntervention || v.Job.Result.Reason != "runner_state_unknown" || v.Available {
		t.Fatal("invented native completion/retry", v, e)
	}
}
func TestSimulationMismatchBlocksFurtherPackageMutation(t *testing.T) {
	ctx := context.Background()
	s, b, f, req, at, _ := durableFixture(t)
	f.Outcome = "mismatch"
	m, e := packageupdate.NewSimulation(ctx, s, b, f, func() time.Time { return *at })
	if e != nil {
		t.Fatal(e)
	}
	if e = m.Prepare(ctx, b.DeviceID, operator, req); e != nil {
		t.Fatal(e)
	}
	v, _ := m.View(ctx, b.DeviceID, *at)
	if e = m.Approve(ctx, b.DeviceID, operator, packageupdate.ApprovalRequest{RequestID: req.RequestID, PreviewDigest: v.Preview.Digest}); e != nil {
		t.Fatal(e)
	}
	if e = m.StartPendingSimulation(ctx, b.DeviceID); e != nil {
		t.Fatal(e)
	}
	_, _ = m.View(ctx, b.DeviceID, *at)
	v, e = m.View(ctx, b.DeviceID, *at)
	if e != nil || v.Job.State != packageupdate.NeedsIntervention || v.Job.Result.Packages[0].Outcome != "mismatch" || v.Job.Result.Reboot.State != "unknown" {
		t.Fatal(v, e)
	}
	req.RequestID = "update_22222222222222222222222222222222"
	if e = m.Prepare(ctx, b.DeviceID, operator, req); e == nil {
		t.Fatal("another job admitted after uncertain outcome")
	}
}
