package packagepermit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"localrmm/internal/actionpermit"
	"localrmm/internal/packageplan"
	"os"
	"testing"
)

func fixture(t *testing.T) (Permit, Pins, ed25519.PrivateKey) {
	t.Helper()
	raw, e := os.ReadFile("../packageplan/testdata/plan.json")
	if e != nil {
		t.Fatal(e)
	}
	p, e := packageplan.Decode(context.Background(), raw)
	if e != nil {
		t.Fatal(e)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{19}, 32))
	pub := key.Public().(ed25519.PublicKey)
	sel := []Selection{{p.Packages[0].Name, p.Packages[0].Architecture}}
	permit := Permit{Version: Version, Action: Execute, ManagerID: "manager_11111111111111111111111111111111", KeyID: actionpermit.Digest(pub), EndpointID: p.EndpointID, IncarnationDigest: p.IncarnationDigest, RootPolicyDigest: p.RootPolicyDigest, JobID: "update_11111111111111111111111111111111", Sequence: 1, ActorID: "operator_11111111111111111111111111111111", PreviewDigest: actionpermit.Digest([]byte("preview")), IssuedAt: p.CreatedAt, NotBefore: p.CreatedAt, StartDeadline: p.ExpiresAt, Selection: sel, Plan: &p}
	permit.PlanDigest, _ = packageplan.Digest(context.Background(), p)
	return permit, Pins{permit.ManagerID, permit.EndpointID, permit.IncarnationDigest, permit.RootPolicyDigest, pub, sel}, key
}
func TestCanonicalSignedPackagePermitAndIsolation(t *testing.T) {
	p, pins, key := fixture(t)
	ctx := context.Background()
	raw, e := Sign(ctx, p, key)
	if e != nil {
		t.Fatal(e)
	}
	got, e := Verify(ctx, raw, pins, p.IssuedAt)
	if e != nil || got.PlanDigest != p.PlanDigest {
		t.Fatal(e)
	}
	if _, e = actionpermit.Decode(raw); e == nil {
		t.Fatal("package envelope accepted as service")
	}
	for _, b := range [][]byte{append([]byte(" "), raw...), append(bytes.Clone(raw), '\n'), bytes.Replace(raw, []byte(`"sequence":"1"`), []byte(`"sequence":1`), 1), bytes.Repeat([]byte("x"), MaxEnvelopeBytes+1)} {
		if _, _, e = Decode(ctx, b); e == nil {
			t.Fatal("noncanonical envelope")
		}
	}
	raw[len(raw)-10] ^= 1
	if _, e = Verify(ctx, raw, pins, p.IssuedAt); e == nil {
		t.Fatal("tampered signature")
	}
}
func TestPackagePreparationAndExecutionBounds(t *testing.T) {
	p, pins, key := fixture(t)
	ctx := context.Background()
	for _, now := range []int64{p.IssuedAt - 1, p.StartDeadline} {
		raw, _ := Sign(ctx, p, key)
		if _, e := Verify(ctx, raw, pins, now); !errors.Is(e, ErrExpired) {
			t.Fatal(e)
		}
	}
	p.Action = Prepare
	p.Plan = nil
	p.PlanDigest = ""
	p.PreviewDigest = ""
	raw, e := Sign(ctx, p, key)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Verify(ctx, raw, pins, p.IssuedAt); e != nil {
		t.Fatal(e)
	}
	p.PreviewDigest = actionpermit.Digest([]byte("unexpected"))
	if _, e = Sign(ctx, p, key); e == nil {
		t.Fatal("prepare carried approval")
	}
}
func TestPackagePinsAndAllowedIdentitiesAreExact(t *testing.T) {
	p, pins, key := fixture(t)
	ctx := context.Background()
	raw, _ := Sign(ctx, p, key)
	for _, mutate := range []func(*Pins){func(x *Pins) { x.EndpointID = "agent_22222222222222222222222222222222" }, func(x *Pins) { x.RootPolicyDigest = actionpermit.Digest([]byte("changed")) }, func(x *Pins) { x.Allowed = []Selection{{"different", "amd64"}} }, func(x *Pins) {
		x.PublicKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{23}, 32)).Public().(ed25519.PublicKey)
	}} {
		x := pins
		mutate(&x)
		if _, e := Verify(ctx, raw, x, p.IssuedAt); e == nil {
			t.Fatal("changed pins")
		}
	}
}
