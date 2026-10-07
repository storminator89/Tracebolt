package packageupdate

import (
	"bytes"
	"crypto/ed25519"
	"localrmm/internal/actionpermit"
	"localrmm/internal/packagepermit"
	"testing"
)

func nativeFixture(t *testing.T) (Record, PrepareRequest, Preview, ed25519.PrivateKey) {
	t.Helper()
	r, req, p := fixture(t)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{37}, 32))
	n, e := NewNative(r.Binding, key.Public().(ed25519.PublicKey), at)
	if e != nil {
		t.Fatal(e)
	}
	return n, req, p, key
}
func signedNative(t *testing.T, r Record, req PrepareRequest, p *Preview, key ed25519.PrivateKey, now int64) []byte {
	t.Helper()
	permit := packagepermit.Permit{Version: packagepermit.Version, Action: packagepermit.Prepare, ManagerID: r.Binding.ManagerID, KeyID: actionpermit.Digest(r.PublicKey), EndpointID: r.Binding.DeviceID, IncarnationDigest: r.Binding.IncarnationDigest, RootPolicyDigest: r.Binding.RootPolicyDigest, JobID: req.RequestID, Sequence: 1, ActorID: actor, IssuedAt: now, NotBefore: now, StartDeadline: now + 120, Selection: []packagepermit.Selection{{Name: req.Packages[0].Name, Architecture: req.Packages[0].Architecture}}}
	if p != nil {
		permit.Action = packagepermit.Execute
		permit.Plan = &p.Plan
		permit.PlanDigest = p.PlanDigest
		permit.PreviewDigest = p.Digest
		permit.StartDeadline = p.Plan.ExpiresAt
	}
	raw, e := packagepermit.Sign(ctx, permit, key)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func nativePrepared(t *testing.T) (Record, PrepareRequest, Preview, ed25519.PrivateKey) {
	t.Helper()
	r, req, p, key := nativeFixture(t)
	raw := signedNative(t, r, req, nil, key, at)
	n, e := PrepareNative(ctx, r, req, actor, at, raw)
	if e != nil || ValidateSuccessor(ctx, r, n) != nil {
		t.Fatal(e)
	}
	r = n
	n, e = ClaimPreparation(ctx, r, req.RequestID, actionpermit.Digest(raw), at+1)
	if e != nil || ValidateSuccessor(ctx, r, n) != nil {
		t.Fatal(e)
	}
	return n, req, p, key
}
func TestNativeClaimsAreBoundToSignedAuthority(t *testing.T) {
	r, req, p, key := nativePrepared(t)
	n, e := AttachPreview(ctx, r, p, at+2)
	if e != nil || ValidateSuccessor(ctx, r, n) != nil {
		t.Fatal(e)
	}
	r = n
	raw := signedNative(t, r, req, &p, key, at+3)
	n, e = ApproveNative(ctx, r, ApprovalRequest{req.RequestID, p.Digest}, actor, at+3, raw)
	if e != nil || ValidateSuccessor(ctx, r, n) != nil {
		t.Fatal(e)
	}
	r = n
	if _, e = ClaimForFixture(ctx, r, req.RequestID, p.Digest, at+4); e == nil {
		t.Fatal("native claimed through simulation")
	}
	n, e = ClaimExecution(ctx, r, req.RequestID, p.Digest, at+4)
	if e != nil || ValidateSuccessor(ctx, r, n) != nil {
		t.Fatal(e)
	}
	r = n
	changed := r
	changed.Jobs = append([]Job(nil), r.Jobs...)
	changed.Jobs[0].ExecutionEnvelope = bytes.Clone(raw)
	changed.Jobs[0].ExecutionEnvelope[len(raw)-10] ^= 1
	if Validate(ctx, changed) == nil {
		t.Fatal("tampered authority accepted")
	}
	n, e = Observe(ctx, r, at+500)
	if e != nil || n.Jobs[0].State != DeliveryUnknown {
		t.Fatal("claimed job expired/replayed", e)
	}
}
func TestNativeLostPreparationRemainsFencedAndUnclaimedExpires(t *testing.T) {
	r, req, _, _ := nativePrepared(t)
	n, e := MarkPreparationUncertain(ctx, r, req.RequestID, at+2)
	if e != nil || ValidateSuccessor(ctx, r, n) != nil || n.Jobs[0].State != NeedsIntervention {
		t.Fatal(e)
	}
	if terminal(n.Jobs[0]) {
		t.Fatal("uncertainty permits replacement")
	}
	r, req, _, key := nativeFixture(t)
	raw := signedNative(t, r, req, nil, key, at)
	r, e = PrepareNative(ctx, r, req, actor, at, raw)
	if e != nil {
		t.Fatal(e)
	}
	n, e = Observe(ctx, r, at+120)
	if e != nil || ValidateSuccessor(ctx, r, n) != nil || n.Jobs[0].State != PreparationFailed {
		t.Fatal("unclaimed authority never expires", e)
	}
}
