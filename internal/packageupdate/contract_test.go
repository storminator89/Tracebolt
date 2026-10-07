package packageupdate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/packageplan"
)

var ctx = context.Background()

const at int64 = 1700000000
const actor = "operator_11111111111111111111111111111111"

func fixture(t *testing.T) (Record, PrepareRequest, Preview) {
	t.Helper()
	raw, e := os.ReadFile("../packageplan/testdata/plan.json")
	if e != nil {
		t.Fatal(e)
	}
	p, e := packageplan.Decode(ctx, raw)
	if e != nil {
		t.Fatal(e)
	}
	b := Binding{"manager_11111111111111111111111111111111", p.EndpointID, p.IncarnationDigest, p.RootPolicyDigest, "production-tls"}
	r, e := New(b, at)
	if e != nil {
		t.Fatal(e)
	}
	req := PrepareRequest{"update_11111111111111111111111111111111", []Selection{{"sample-bin", "amd64"}}}
	v, e := DescribePreview(ctx, b, req, actor, p, []Source{{p.Packages[0].Archive.SourceIdentityDigest, "Synthetic fixture repository", "trixie", "main"}})
	if e != nil {
		t.Fatal(e)
	}
	return r, req, v
}
func ready(t *testing.T) (Record, Preview) {
	t.Helper()
	r, req, p := fixture(t)
	r, e := Prepare(ctx, r, req, actor, at)
	if e != nil {
		t.Fatal(e)
	}
	r, e = AttachPreview(ctx, r, p, at+1)
	if e != nil {
		t.Fatal(e)
	}
	return r, p
}
func approved(t *testing.T) (Record, Preview) {
	t.Helper()
	r, p := ready(t)
	r, e := Approve(ctx, r, ApprovalRequest{p.RequestID, p.Digest}, actor, at+2)
	if e != nil {
		t.Fatal(e)
	}
	return r, p
}
func TestInertLifecycleExactRetriesAndCanonicalReload(t *testing.T) {
	r, req, p := fixture(t)
	r, e := Prepare(ctx, r, req, actor, at)
	if e != nil {
		t.Fatal(e)
	}
	again, e := Prepare(ctx, r, req, actor, at+1)
	if e != nil || len(again.Jobs) != 1 || again.Jobs[0].CreatedAt != at {
		t.Fatal("prepare retry", e)
	}
	r, e = AttachPreview(ctx, again, p, at+2)
	if e != nil {
		t.Fatal(e)
	}
	r, e = Approve(ctx, r, ApprovalRequest{p.RequestID, p.Digest}, actor, at+3)
	if e != nil {
		t.Fatal(e)
	}
	r, e = Approve(ctx, r, ApprovalRequest{p.RequestID, p.Digest}, actor, at+4)
	if e != nil || r.Jobs[0].ApprovedAt != at+3 {
		t.Fatal("approval retry", e)
	}
	raw, e := Encode(ctx, r)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "fixture-record.json")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	raw, e = os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	reloaded, e := Decode(ctx, raw)
	if e != nil {
		t.Fatal(e)
	}
	raw2, e := Encode(ctx, reloaded)
	if e != nil || !bytes.Equal(raw, raw2) {
		t.Fatal("lost exact durable description", e)
	}
	r, e = ClaimForFixture(ctx, reloaded, p.RequestID, p.Digest, at+5)
	if e != nil || r.Jobs[0].State != DeliveryUnknown {
		t.Fatal(e)
	}
	r, e = ClaimForFixture(ctx, r, p.RequestID, p.Digest, at+6)
	if e != nil || r.Jobs[0].ClaimedAt != at+5 {
		t.Fatal("claim retry", e)
	}
	r, e = Observe(ctx, r, at+600)
	if e != nil || r.Jobs[0].State != DeliveryUnknown {
		t.Fatal("expiry invented a stopped outcome", e)
	}
	r, e = Revoke(ctx, r, at+601)
	if e != nil || r.Jobs[0].State != DeliveryUnknown {
		t.Fatal("revocation invented cancellation", e)
	}
}
func TestSelectionAndActorCannotChangeOnRetry(t *testing.T) {
	r, req, _ := fixture(t)
	r, e := Prepare(ctx, r, req, actor, at)
	if e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*PrepareRequest){func(q *PrepareRequest) { q.Packages[0].Name = "different" }, func(q *PrepareRequest) { q.Packages[0].Architecture = "arm64" }} {
		q := PrepareRequest{req.RequestID, append([]Selection(nil), req.Packages...)}
		change(&q)
		if _, e = Prepare(ctx, r, q, actor, at+1); !errors.Is(e, ErrConflict) {
			t.Fatal(e)
		}
	}
	if _, e = Prepare(ctx, r, req, "operator_22222222222222222222222222222222", at+1); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
}
func TestImmutableSnapshotAndEvidenceBinding(t *testing.T) {
	r, req, p := fixture(t)
	r, e := Prepare(ctx, r, req, actor, at)
	if e != nil {
		t.Fatal(e)
	}
	req.Packages[0].Name = "changed"
	if r.Jobs[0].Request.Packages[0].Name != "sample-bin" {
		t.Fatal("aliased selection")
	}
	out, e := AttachPreview(ctx, r, p, at+1)
	if e != nil {
		t.Fatal(e)
	}
	p.Sources[0].Label = "changed"
	p.Plan.Packages[0].To.Version = "999"
	if out.Jobs[0].Preview.Sources[0].Label == "changed" || out.Jobs[0].Preview.Plan.Packages[0].To.Version == "999" || r.Jobs[0].Preview != nil {
		t.Fatal("aliased preview/snapshot")
	}
	before, _ := Encode(ctx, out)
	if _, e = Approve(ctx, out, ApprovalRequest{out.Jobs[0].Request.RequestID, actionpermit.Digest([]byte("wrong"))}, actor, at+2); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	after, _ := Encode(ctx, out)
	if !bytes.Equal(before, after) {
		t.Fatal("failed write mutated original")
	}
}
func TestPreviewRejectsMismatchedSelectionOrProvenance(t *testing.T) {
	_, req, p := fixture(t)
	cases := map[string]func(*Preview){
		"source label":   func(v *Preview) { v.Sources[0].Label = "changed" },
		"plan version":   func(v *Preview) { v.Plan.Packages[0].To.Version = "3.0" },
		"archive":        func(v *Preview) { v.Plan.Packages[0].Archive.SHA256 = actionpermit.Digest([]byte("changed")) },
		"source mapping": func(v *Preview) { v.Plan.Packages[0].To.SourceVersion = "2.0" },
		"actor":          func(v *Preview) { v.ActorID = "operator_22222222222222222222222222222222" },
		"policy":         func(v *Preview) { v.Binding.RootPolicyDigest = actionpermit.Digest([]byte("changed")) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(p)
			var v Preview
			_ = json.Unmarshal(raw, &v)
			change(&v)
			if validatePreview(ctx, v, req, actor, p.Binding) == nil {
				t.Fatal("accepted changed immutable preview")
			}
		})
	}
	q := req
	q.Packages = []Selection{{"other-package", "amd64"}}
	if _, e := DescribePreview(ctx, p.Binding, q, actor, p.Plan, p.Sources); e == nil {
		t.Fatal("accepted expanded solver selection")
	}
	sources := append(append([]Source(nil), p.Sources...), Source{actionpermit.Digest([]byte("extra")), "Extra", "trixie", "main"})
	if _, e := DescribePreview(ctx, p.Binding, req, actor, p.Plan, sources); e == nil {
		t.Fatal("accepted unrelated source")
	}
}
func TestExpiryRevocationAndMonotonicTime(t *testing.T) {
	r, p := ready(t)
	if _, e := Approve(ctx, r, ApprovalRequest{p.RequestID, p.Digest}, actor, at+60); !errors.Is(e, ErrExpired) {
		t.Fatal("deadline", e)
	}
	// Inventory original age can expire before the preview's outer deadline.
	if _, e := Approve(ctx, r, ApprovalRequest{p.RequestID, p.Digest}, actor, at+51); !errors.Is(e, ErrExpired) {
		t.Fatal("original inventory age", e)
	}
	if _, e := Observe(ctx, r, at); !errors.Is(e, ErrInvalid) {
		t.Fatal("clock rollback", e)
	}
	r, e := Revoke(ctx, r, at+2)
	if e != nil || r.Jobs[0].State != Revoked {
		t.Fatal(e)
	}
	if _, e = Approve(ctx, r, ApprovalRequest{p.RequestID, p.Digest}, actor, at+3); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	r, p = approved(t)
	r, e = Observe(ctx, r, at+60)
	if e != nil || r.Jobs[0].State != Expired {
		t.Fatal(e)
	}
	r, e = Approve(ctx, r, ApprovalRequest{p.RequestID, p.Digest}, actor, at+61)
	if e != nil || r.Jobs[0].State != Expired || r.Jobs[0].ApprovedAt != at+2 {
		t.Fatal("retry created renewed approval", e)
	}
}
func TestStrictRecordWireAndStateValidation(t *testing.T) {
	r, _ := approved(t)
	raw, e := Encode(ctx, r)
	if e != nil {
		t.Fatal(e)
	}
	bad := [][]byte{nil, append([]byte(" "), raw...), append(bytes.Clone(raw), '\n'), bytes.Replace(raw, []byte(`"version":`), []byte(`"extra":0,"version":`), 1), bytes.Replace(raw, []byte(`"revision":"4"`), []byte(`"revision":4`), 1), bytes.Replace(raw, []byte(`"state":"approved"`), []byte(`"state":"succeeded"`), 1), bytes.Repeat([]byte(" "), MaxRecordBytes+1)}
	for i, b := range bad {
		if _, e = Decode(ctx, b); e == nil {
			t.Fatalf("wire %d accepted", i)
		}
	}
	for _, change := range []func(*Record){func(v *Record) { v.Jobs[0].ApprovedAt = at + 60 }, func(v *Record) { v.Jobs[0].State = DeliveryUnknown }, func(v *Record) { v.ClockFloor = at }, func(v *Record) { v.Jobs[0].Sequence = 2 }} {
		b, _ := Encode(ctx, r)
		v, _ := Decode(ctx, b)
		change(&v)
		if Validate(ctx, v) == nil {
			t.Fatal("accepted corrupt lifecycle")
		}
	}
}
func TestPrepareBoundsAndCanonicalOrdering(t *testing.T) {
	_, req, _ := fixture(t)
	for _, p := range [][]Selection{nil, {{"a", "amd64"}}, {{"sample-bin", "any"}}, {{"sample-bin", "linux-any"}}, {{"sample-bin", "source"}}, {{"sample-bin", "amd64"}, {"sample-bin", "amd64"}}} {
		q := req
		q.Packages = p
		if ValidatePrepare(q) == nil {
			t.Fatal("accepted invalid selection", p)
		}
	}
	q := req
	q.Packages = []Selection{{"aa", "amd64"}, {"aa-extra", "amd64"}, {"bb", "amd64"}}
	if e := ValidatePrepare(q); e != nil {
		t.Fatal("must match package-plan ordering", e)
	}
	q.Packages = make([]Selection, 33)
	if ValidatePrepare(q) == nil {
		t.Fatal("selection widened")
	}
	if packageplan.MaxPlanBytes != 128<<10 {
		t.Fatal("package plan bound changed")
	}
}
func TestManagerCannotBeEnabledAndNeverInventsStatus(t *testing.T) {
	r, req, p := fixture(t)
	m := Manager{}
	v, e := m.View(ctx, r.Binding.DeviceID, time.Unix(at, 0).UTC())
	if e != nil || v.Available || v.Preview != nil || v.Job != nil || v.Reason != "native_adapter_unavailable" {
		t.Fatal(v, e)
	}
	if e = m.Prepare(ctx, r.Binding.DeviceID, actor, req); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	if e = m.Approve(ctx, r.Binding.DeviceID, actor, ApprovalRequest{p.RequestID, p.Digest}); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	c, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = m.View(c, r.Binding.DeviceID, time.Unix(at, 0).UTC()); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e = m.View(ctx, "agent_"+strings.Repeat("x", 32), time.Unix(at, 0).UTC()); e == nil {
		t.Fatal("invalid device")
	}
}
func FuzzDecodeRecord(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		r, e := Decode(ctx, raw)
		if e == nil {
			out, e := Encode(ctx, r)
			if e != nil || !bytes.Equal(raw, out) {
				t.Fatal("noncanonical decode")
			}
		}
	})
}

func TestReloadRejectsAuthorityAfterOriginalRevocation(t *testing.T) {
	r, p := approved(t)
	r, e := ClaimForFixture(ctx, r, p.RequestID, p.Digest, at+3)
	if e != nil {
		t.Fatal(e)
	}
	r, e = Revoke(ctx, r, at+4)
	if e != nil {
		t.Fatal(e)
	}
	for _, revokedAt := range []int64{at - 1, at + 1, at + 2} {
		changed := r
		changed.RevokedAt = revokedAt
		if Validate(ctx, changed) == nil {
			t.Fatal("accepted authority after recorded revocation", revokedAt)
		}
	}
}
