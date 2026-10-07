//go:build linux

package packagecontroller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/operatorauth"
	"localrmm/internal/packagehelper"
	"localrmm/internal/packagepermit"
	"localrmm/internal/packageplan"
	"localrmm/internal/packageupdate"
	"localrmm/internal/packageupdatestore"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var ctx = context.Background()

const actor = "operator_11111111111111111111111111111111"

type fixtureState struct {
	m       *Manager
	store   *packageupdatestore.Store
	config  Config
	key     ed25519.PrivateKey
	at      time.Time
	req     packageupdate.PrepareRequest
	preview packageupdate.Preview
	caps    packagehelper.Capabilities
	grants  map[operatorauth.Capability]bool
	device  bool
}

func fixture(t *testing.T) *fixtureState {
	t.Helper()
	raw, e := os.ReadFile("../packageplan/testdata/plan.json")
	if e != nil {
		t.Fatal(e)
	}
	plan, e := packageplan.Decode(ctx, raw)
	if e != nil {
		t.Fatal(e)
	}
	f := &fixtureState{at: time.Unix(plan.CreatedAt, 0).UTC(), grants: map[operatorauth.Capability]bool{operatorauth.PlanUpdates: true, operatorauth.ExecuteUpdates: true}, device: true, key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{61}, 32))}
	dir := filepath.Join(t.TempDir(), "private")
	if e = os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	f.config = Config{Version: ConfigVersion, Enabled: true, ManagerID: "manager_11111111111111111111111111111111", EndpointID: plan.EndpointID, IncarnationDigest: plan.IncarnationDigest, RootPolicyDigest: plan.RootPolicyDigest, TransportProfile: "production-tls", StateFile: filepath.Join(dir, "jobs.sqlite"), PrivateKeyFile: filepath.Join(dir, "key"), LocalScopeAcknowledged: true}
	f.store, e = packageupdatestore.CreateNative(ctx, f.config.StateFile, f.config.Binding(), f.key.Public().(ed25519.PublicKey), f.at.Unix())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.m.Close(); _ = f.store.Close() })
	f.m, e = newManager(ctx, f.config, f.key, f.store, func(context.Context, string, string, time.Time) error {
		if !f.device {
			return errors.New("revoked")
		}
		return nil
	}, func(a string, c operatorauth.Capability) bool { return a == actor && f.grants[c] }, func() time.Time { return f.at })
	if e != nil {
		t.Fatal(e)
	}
	f.req = packageupdate.PrepareRequest{RequestID: "update_11111111111111111111111111111111", Packages: []packageupdate.Selection{{Name: "sample-bin", Architecture: "amd64"}}}
	f.preview, e = packageupdate.DescribePreview(ctx, f.config.Binding(), f.req, actor, plan, []packageupdate.Source{{IdentityDigest: plan.Packages[0].Archive.SourceIdentityDigest, Label: "Synthetic signed repository", Suite: "trixie", Component: "main"}})
	if e != nil {
		t.Fatal(e)
	}
	f.caps = packagehelper.Capabilities{Version: packagehelper.CapabilitiesVersion, Enabled: true, ManagerID: f.config.ManagerID, EndpointID: f.config.EndpointID, IncarnationDigest: f.config.IncarnationDigest, RootPolicyDigest: f.config.RootPolicyDigest, KeyID: actionpermit.Digest(f.key.Public().(ed25519.PublicKey)), TransportProfile: f.config.TransportProfile, CapturedAt: f.at.Unix(), Allowed: []packagepermit.Selection{{Name: "sample-bin", Architecture: "amd64"}}}
	if e = f.m.Report(ctx, f.config.EndpointID, f.config.IncarnationDigest, f.caps); e != nil {
		t.Fatal(e)
	}
	return f
}
func (f *fixtureState) prep(t *testing.T) packagehelper.Snapshot {
	t.Helper()
	if e := f.m.Prepare(ctx, f.config.EndpointID, actor, f.req); e != nil {
		t.Fatal(e)
	}
	d, e := f.m.Peek(ctx, f.config.EndpointID, f.config.IncarnationDigest)
	if e != nil || d.State != "pending" {
		t.Fatal(d, e)
	}
	grant, e := f.m.Claim(ctx, f.config.EndpointID, f.config.IncarnationDigest, d.Identity)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.m.Claim(ctx, f.config.EndpointID, f.config.IncarnationDigest, d.Identity); !errors.Is(e, packageupdate.ErrConflict) {
		t.Fatal("claim replay", e)
	}
	s := packagehelper.Snapshot{Version: packagehelper.SnapshotVersion, JobID: f.req.RequestID, Sequence: 1, PreparationEnvelopeDigest: actionpermit.Digest(grant.Envelope), State: packageupdate.PreviewReady, Preview: &f.preview, Results: []packageupdate.Result{}, UpdatedAt: f.at.Unix()}
	if e = f.m.Accept(ctx, f.config.EndpointID, f.config.IncarnationDigest, s); e != nil {
		t.Fatal(e)
	}
	return s
}
func TestNativeSQLiteExactDispatchResultsAndReopen(t *testing.T) {
	f := fixture(t)
	s := f.prep(t)
	d0 := s.PreparationEnvelopeDigest
	if e := f.m.Prepare(ctx, f.config.EndpointID, actor, f.req); e != nil {
		t.Fatal("same request retry", e)
	}
	if e := f.m.Approve(ctx, f.config.EndpointID, actor, packageupdate.ApprovalRequest{RequestID: f.req.RequestID, PreviewDigest: f.preview.Digest}); e != nil {
		t.Fatal(e)
	}
	d, e := f.m.Peek(ctx, f.config.EndpointID, f.config.IncarnationDigest)
	if e != nil || d.Identity.Kind != packagepermit.Execute {
		t.Fatal(d, e)
	}
	grant, e := f.m.Claim(ctx, f.config.EndpointID, f.config.IncarnationDigest, d.Identity)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.m.Claim(ctx, f.config.EndpointID, f.config.IncarnationDigest, d.Identity); !errors.Is(e, packageupdate.ErrConflict) {
		t.Fatal("execute replay", e)
	}
	s.ExecutionEnvelopeDigest = actionpermit.Digest(grant.Envelope)
	for i, phase := range []string{packageupdate.Applying, packageupdate.Verifying, packageupdate.Succeeded} {
		f.at = f.at.Add(time.Second)
		s.UpdatedAt = f.at.Unix()
		s.State = phase
		result := packageupdate.Result{Sequence: uint64(i + 1), Phase: phase, ObservedAt: f.at.Unix(), Reason: "native_running", DpkgState: "unknown", Packages: []packageupdate.PackageResult{{Name: "sample-bin", Architecture: "amd64", ExpectedVersion: "1.0-2", Outcome: "unknown"}}, Reboot: packageupdate.RebootEvidence{Source: "native", State: "unknown", ObservedAt: f.at.Unix()}}
		if phase == packageupdate.Succeeded {
			v := "1.0-2"
			result.Packages[0].ObservedVersion = &v
			result.Packages[0].Outcome = "verified"
			result.DpkgState = "clean"
			result.Reason = "native_verified"
			result.Reboot.State = "required"
		}
		s.Results = append(s.Results, result)
		s.Result = &s.Results[len(s.Results)-1]
		if e = f.m.Accept(ctx, f.config.EndpointID, f.config.IncarnationDigest, s); e != nil {
			t.Fatal(phase, e)
		}
		if e = f.m.Accept(ctx, f.config.EndpointID, f.config.IncarnationDigest, s); e != nil {
			t.Fatal("exact result retry", e)
		}
	}
	v, e := f.m.View(ctx, f.config.EndpointID, f.at)
	if e != nil || v.ExecutionMode != "native" || v.Job.State != packageupdate.Succeeded || v.Job.Result.Reboot.Source != "native" {
		t.Fatal(v, e)
	}
	s.Results[0].Reason = "simulated_running"
	if e = f.m.Accept(ctx, f.config.EndpointID, f.config.IncarnationDigest, s); e == nil {
		t.Fatal("altered history accepted")
	}
	if d0 == s.ExecutionEnvelopeDigest {
		t.Fatal("authority domains conflated")
	}
	f.m.Close()
	if e = f.store.Close(); e != nil {
		t.Fatal(e)
	}
	store, e := packageupdatestore.OpenExisting(ctx, f.config.StateFile, f.config.Binding())
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	m, e := newManager(ctx, f.config, f.key, store, func(context.Context, string, string, time.Time) error { return nil }, func(string, operatorauth.Capability) bool { return true }, func() time.Time { return f.at })
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	v, e = m.ViewJob(ctx, f.config.EndpointID, f.req.RequestID, f.at)
	if e != nil || v.Job.State != packageupdate.Succeeded || v.Available || v.Reason != "native_adapter_unavailable" {
		t.Fatal("restart manufactured live readiness", v, e)
	}
}
func TestNativeCurrentAuthorityAndLostPreparation(t *testing.T) {
	f := fixture(t)
	if e := f.m.Prepare(ctx, f.config.EndpointID, actor, f.req); e != nil {
		t.Fatal(e)
	}
	d, e := f.m.Peek(ctx, f.config.EndpointID, f.config.IncarnationDigest)
	if e != nil {
		t.Fatal(e)
	}
	f.grants[operatorauth.PlanUpdates] = false
	if _, e = f.m.Claim(ctx, f.config.EndpointID, f.config.IncarnationDigest, d.Identity); e == nil {
		t.Fatal("revoked operator claimed")
	}
	f.grants[operatorauth.PlanUpdates] = true
	g, e := f.m.Claim(ctx, f.config.EndpointID, f.config.IncarnationDigest, d.Identity)
	if e != nil {
		t.Fatal(e)
	}
	f.at = f.at.Add(time.Minute * 3)
	d, e = f.m.Peek(ctx, f.config.EndpointID, f.config.IncarnationDigest)
	if e != nil || d.State != "claimed" {
		t.Fatal("lost delivery expired into replay", d, e)
	}
	s := packagehelper.Snapshot{Version: packagehelper.SnapshotVersion, JobID: f.req.RequestID, Sequence: 1, PreparationEnvelopeDigest: actionpermit.Digest(g.Envelope), State: packageupdate.NeedsIntervention, Results: []packageupdate.Result{}, UpdatedAt: f.at.Unix()}
	if e = f.m.Accept(ctx, f.config.EndpointID, f.config.IncarnationDigest, s); e != nil {
		t.Fatal(e)
	}
	v, e := f.m.View(ctx, f.config.EndpointID, f.at)
	if e != nil || v.Job.State != packageupdate.NeedsIntervention || v.Job.Result != nil || v.Available {
		t.Fatal(v, e)
	}
	f.device = false
	if _, e = f.m.View(ctx, f.config.EndpointID, f.at); e == nil {
		t.Fatal("revoked endpoint served")
	}
}
func TestNativeStaleCapabilitiesAndWrongExactApproval(t *testing.T) {
	f := fixture(t)
	f.prep(t)
	f.grants[operatorauth.ExecuteUpdates] = false
	req := packageupdate.ApprovalRequest{RequestID: f.req.RequestID, PreviewDigest: f.preview.Digest}
	if e := f.m.Approve(ctx, f.config.EndpointID, actor, req); e == nil {
		t.Fatal("revoked execute accepted")
	}
	f.grants[operatorauth.ExecuteUpdates] = true
	req.PreviewDigest = actionpermit.Digest([]byte("changed"))
	if e := f.m.Approve(ctx, f.config.EndpointID, actor, req); e == nil {
		t.Fatal("changed digest accepted")
	}
	f.caps.Enabled = false
	if e := f.m.Report(ctx, f.config.EndpointID, f.config.IncarnationDigest, f.caps); e != nil {
		t.Fatal(e)
	}
	req.PreviewDigest = f.preview.Digest
	if e := f.m.Approve(ctx, f.config.EndpointID, actor, req); e == nil {
		t.Fatal("disabled helper approval")
	}
}

func TestExplicitInitializationIsCreateOnlyAndNeverGeneratesKey(t *testing.T) {
	f := fixture(t)
	c := f.config
	c.StateFile = filepath.Join(filepath.Dir(c.StateFile), "new.sqlite")
	raw, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(filepath.Dir(c.StateFile), "manager.json")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if Initialize(ctx, path, false, f.at) == nil {
		t.Fatal("missing acknowledgement accepted")
	}
	if Initialize(ctx, path, true, f.at) == nil {
		t.Fatal("missing key generated/adopted")
	}
	if e = os.WriteFile(c.PrivateKeyFile, f.key, 0600); e != nil {
		t.Fatal(e)
	}
	if e = Initialize(ctx, path, true, f.at); e != nil {
		t.Fatal(e)
	}
	if Initialize(ctx, path, true, f.at) == nil {
		t.Fatal("scope reset accepted")
	}
	s, e := packageupdatestore.OpenExisting(ctx, c.StateFile, c.Binding())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	raw, e = s.Open(ctx, c.Binding())
	if e != nil {
		t.Fatal(e)
	}
	r, e := packageupdate.Decode(ctx, raw)
	if e != nil || r.Mode != "native" || len(r.Jobs) != 0 || !bytes.Equal(r.PublicKey, f.key.Public().(ed25519.PublicKey)) {
		t.Fatal("wrong initialization", e)
	}
}

func TestOfflinePreparationRetainsExpiredPreviewWithoutApproval(t *testing.T) {
	f := fixture(t)
	if e := f.m.Prepare(ctx, f.config.EndpointID, actor, f.req); e != nil {
		t.Fatal(e)
	}
	d, e := f.m.Peek(ctx, f.config.EndpointID, f.config.IncarnationDigest)
	if e != nil {
		t.Fatal(e)
	}
	g, e := f.m.Claim(ctx, f.config.EndpointID, f.config.IncarnationDigest, d.Identity)
	if e != nil {
		t.Fatal(e)
	}
	original := f.at.Unix()
	f.at = f.at.Add(5 * time.Minute)
	s := packagehelper.Snapshot{Version: packagehelper.SnapshotVersion, JobID: f.req.RequestID, Sequence: 1, PreparationEnvelopeDigest: actionpermit.Digest(g.Envelope), State: packageupdate.PreviewReady, Preview: &f.preview, Results: []packageupdate.Result{}, UpdatedAt: original}
	if e = f.m.Accept(ctx, f.config.EndpointID, f.config.IncarnationDigest, s); e != nil {
		t.Fatal("lost historical preparation", e)
	}
	v, e := f.m.View(ctx, f.config.EndpointID, f.at)
	if e != nil || v.Job.State != packageupdate.Expired || v.Preview.Digest != f.preview.Digest || v.Preview.ExpiresAt.Unix() != f.preview.Plan.ExpiresAt {
		t.Fatal(v, e)
	}
	if e = f.m.Approve(ctx, f.config.EndpointID, actor, packageupdate.ApprovalRequest{RequestID: f.req.RequestID, PreviewDigest: f.preview.Digest}); e == nil {
		t.Fatal("historical preview authorized mutation")
	}
	if e = f.m.Accept(ctx, f.config.EndpointID, f.config.IncarnationDigest, s); e != nil {
		t.Fatal("exact late status retry", e)
	}
	f.caps.CapturedAt = f.at.Unix()
	if e = f.m.Report(ctx, f.config.EndpointID, f.config.IncarnationDigest, f.caps); e != nil {
		t.Fatal(e)
	}
	req := f.req
	req.RequestID = "update_22222222222222222222222222222222"
	if e = f.m.Prepare(ctx, f.config.EndpointID, actor, req); e != nil {
		t.Fatal("completed expired preparation blocked a new plan", e)
	}
}

func TestNativeControllerCannotBindWindowsEnrollmentScope(t *testing.T) {
	f := fixture(t)
	b := enrollmentstate.Binding{InstanceID: f.config.ManagerID, Profile: "tls", CollectionProfile: enrollmentcrypto.CollectionProfileComplete}
	if !f.m.MatchesBinding(b) {
		t.Fatal("expected complete Linux binding")
	}
	b.CollectionProfile = enrollmentcrypto.CollectionProfileWindowsInventory
	if f.m.MatchesBinding(b) {
		t.Fatal("Windows inventory became package authority")
	}
	b.CollectionProfile = enrollmentcrypto.CollectionProfile
	if f.m.MatchesBinding(b) {
		t.Fatal("basic inventory became package authority")
	}
}
