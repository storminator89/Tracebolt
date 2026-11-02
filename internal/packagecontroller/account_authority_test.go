//go:build linux

package packagecontroller

import (
	"context"
	"errors"
	"testing"

	"localrmm/internal/operatorauth"
	"localrmm/internal/packagewire"
)

func TestAccountEpochCannotReactivatePreparedPackage(t *testing.T) {
	f := fixture(t)
	current := uint64(7)
	held := 0
	denied := errors.New("retired account epoch")
	if err := f.m.ConfigureAccountAuthority(func(ctx context.Context, a string, epoch uint64, caps ...operatorauth.Capability) (context.Context, func(), error) {
		if !f.m.mu.TryLock() {
			t.Fatal("account lease acquired beneath controller lock")
		}
		f.m.mu.Unlock()
		if a != actor || epoch != current {
			return ctx, nil, denied
		}
		held++
		return ctx, func() { held-- }, nil
	}); err != nil {
		t.Fatal(err)
	}
	// The legacy boolean must never be consulted beneath a live account lease.
	f.m.actor = func(string, operatorauth.Capability) bool { t.Fatal("legacy bool inside lease"); return false }
	epochCtx := operatorauth.WithApprovalEpoch(ctx, 7)
	if err := f.m.Prepare(epochCtx, f.config.EndpointID, actor, f.req); err != nil {
		t.Fatal(err)
	}
	d, err := f.m.Peek(ctx, f.config.EndpointID, f.config.IncarnationDigest)
	if err != nil {
		t.Fatal(err)
	}
	current = 8 // revoke and regrant; old epoch remains retired
	if _, release, err := f.m.ClaimWithAdmission(ctx, f.config.EndpointID, f.config.IncarnationDigest, d.Identity); !errors.Is(err, denied) || release != nil {
		t.Fatal("old preparation revived", err)
	}
	if err := f.m.Prepare(operatorauth.WithApprovalEpoch(ctx, current), f.config.EndpointID, actor, f.req); err == nil {
		t.Fatal("old request was retagged")
	}
	after, err := f.m.Peek(ctx, f.config.EndpointID, f.config.IncarnationDigest)
	if err != nil || after.Identity != d.Identity || after.State != "pending" || held != 0 {
		t.Fatal("denial consumed or changed old delivery", err)
	}
}

func TestPackageClaimLeaseSurvivesUntilTransportRelease(t *testing.T) {
	f := fixture(t)
	held := 0
	if err := f.m.ConfigureAccountAuthority(func(ctx context.Context, a string, epoch uint64, caps ...operatorauth.Capability) (context.Context, func(), error) {
		if a != actor || epoch != 7 {
			t.Fatal("wrong immutable actor epoch")
		}
		held++
		return ctx, func() { held-- }, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.m.Prepare(operatorauth.WithApprovalEpoch(ctx, 7), f.config.EndpointID, actor, f.req); err != nil {
		t.Fatal(err)
	}
	d, err := f.m.Peek(ctx, f.config.EndpointID, f.config.IncarnationDigest)
	if err != nil {
		t.Fatal(err)
	}
	g, release, err := f.m.ClaimWithAdmission(ctx, f.config.EndpointID, f.config.IncarnationDigest, d.Identity)
	if err != nil || release == nil {
		t.Fatal(err)
	}
	if held != 1 || g.Identity != d.Identity {
		t.Fatal("claim released before transport handoff")
	}
	release()
	if held != 0 {
		t.Fatal("lease leaked")
	}
	var again packagewire.Grant
	again, err = f.m.Claim(ctx, f.config.EndpointID, f.config.IncarnationDigest, d.Identity)
	if err == nil || len(again.Envelope) != 0 || held != 0 {
		t.Fatal("consumed grant replayed", err)
	}
}
