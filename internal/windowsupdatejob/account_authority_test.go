package windowsupdatejob

import (
	"bytes"
	"context"
	"errors"
	"localrmm/internal/actionpermit"
	"localrmm/internal/operatorauth"
	"strings"
	"sync"
	"testing"
	"time"
)

type accountGateFixture struct {
	mu    sync.RWMutex
	epoch uint64
}

func (g *accountGateFixture) admit(ctx context.Context, actor string, epoch uint64, caps ...operatorauth.Capability) (context.Context, func(), error) {
	g.mu.RLock()
	if epoch == 0 || epoch != g.epoch {
		g.mu.RUnlock()
		return ctx, nil, ErrAuthority
	}
	return ctx, g.mu.RUnlock, nil
}
func accountApprovedFixture(t *testing.T) (*workflowFixture, *accountGateFixture) {
	t.Helper()
	f := fixture(t)
	g := &accountGateFixture{epoch: 7}
	if e := f.m.ConfigureAccountAuthority(g.admit); e != nil {
		t.Fatal(e)
	}
	ctx := operatorauth.WithApprovalEpoch(context.Background(), 7)
	if e := f.m.Request(ctx, f.consent.Binding.DeviceID, f.actor, f.id, f.source.value.Selection); e != nil {
		t.Fatal(e)
	}
	p := f.m.record.Jobs[0].Preview
	if e := f.m.Approve(ctx, f.consent.Binding.DeviceID, f.actor, p.ID, p.Digest, true); e != nil {
		t.Fatal(e)
	}
	return f, g
}
func TestAccountEpochRegrantCannotReviveApproval(t *testing.T) {
	f, g := accountApprovedFixture(t)
	r, e := DecodeRecord(f.store.files["jobs.json"])
	if e != nil {
		t.Fatal(e)
	}
	if r.Jobs[0].AuthorityEpoch != 7 {
		t.Fatal("approval epoch not durable")
	}
	raw := append([]byte(nil), r.Jobs[0].Envelope...)
	g.mu.Lock()
	g.epoch = 8
	g.mu.Unlock()
	// Reopening preserves epoch even if no poll observed the intervening revocation.
	f.m, e = Open(f.store, f.guard, f.source, f.key, func() time.Time { return f.at })
	if e != nil {
		t.Fatal(e)
	}
	if e = f.m.ConfigureAccountAuthority(g.admit); e != nil {
		t.Fatal(e)
	}
	if _, e = f.m.Claim(context.Background(), f.id); !errors.Is(e, ErrAuthority) {
		t.Fatalf("claim: %v", e)
	}
	if _, e = f.m.BeginResponseAdmission(context.Background(), raw); !errors.Is(e, ErrAuthority) {
		t.Fatalf("handoff: %v", e)
	}
	if f.m.record.Jobs[0].State != "approved" {
		t.Fatal("denied claim changed consume state")
	}
}
func TestAccountLeaseDrainsClaimAndResponse(t *testing.T) {
	f, g := accountApprovedFixture(t)
	entered := make(chan struct{})
	proceed := make(chan struct{})
	f.guard.before = func(int) { close(entered); <-proceed }
	done := make(chan error, 1)
	go func() { _, e := f.m.Claim(context.Background(), f.id); done <- e }()
	<-entered
	if g.mu.TryLock() {
		g.mu.Unlock()
		t.Fatal("claim does not hold account lease")
	}
	close(proceed)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	f.guard.before = nil
	raw := f.m.record.Jobs[0].Envelope
	release, e := f.m.BeginResponseAdmission(context.Background(), raw)
	if e != nil {
		t.Fatal(e)
	}
	if g.mu.TryLock() {
		g.mu.Unlock()
		t.Fatal("response does not hold account lease")
	}
	release()
	release()
	if !g.mu.TryLock() {
		t.Fatal("response lease leaked")
	}
	g.epoch++
	g.mu.Unlock()
	if _, e = f.m.BeginResponseAdmission(context.Background(), raw); !errors.Is(e, ErrAuthority) {
		t.Fatal("retired epoch admitted")
	}
}
func TestLiveAuthorityRejectsLegacyApproval(t *testing.T) {
	f := fixture(t)
	raw := f.approve(t)
	g := &accountGateFixture{epoch: 1}
	if e := f.m.ConfigureAccountAuthority(g.admit); e != nil {
		t.Fatal(e)
	}
	if _, e := f.m.Claim(context.Background(), f.id); !errors.Is(e, ErrAuthority) {
		t.Fatalf("legacy claim: %v", e)
	}
	if _, e := f.m.BeginResponseAdmission(context.Background(), raw); !errors.Is(e, ErrAuthority) {
		t.Fatalf("legacy handoff: %v", e)
	}
}

func TestAccountRegrantDoesNotTriggerParkedSchedule(t *testing.T) {
	f := scheduleFixture(t)
	g := &accountGateFixture{epoch: 7}
	if e := f.m.ConfigureAccountAuthority(g.admit); e != nil {
		t.Fatal(e)
	}
	ctx := operatorauth.WithApprovalEpoch(context.Background(), 7)
	if e := f.m.Request(ctx, f.consent.Binding.DeviceID, f.actor, f.id, f.source.value.Selection); e != nil {
		t.Fatal(e)
	}
	scheduleReport(t, f, nil)
	p := f.m.record.Jobs[0].Preview
	start, end := f.at.Unix()+120, f.at.Unix()+600
	if e := f.m.Schedule(ctx, f.consent.Binding.DeviceID, f.actor, f.id, p.Digest, start, end, true); e != nil {
		t.Fatal(e)
	}
	g.mu.Lock()
	g.epoch = 8
	g.mu.Unlock()
	f.at = f.at.Add(120 * time.Second)
	if _, e := f.m.Pending(context.Background()); e != nil {
		t.Fatal(e)
	}
	j := f.m.record.Jobs[0]
	if j.State != "schedule_blocked" || j.Reason != "schedule_authority_revoked" || len(j.Envelope) != 0 {
		t.Fatalf("old schedule revived: state=%s reason=%s", j.State, j.Reason)
	}
	r, e := DecodeRecord(f.store.files["jobs.json"])
	if e != nil {
		t.Fatal(e)
	}
	if r.Jobs[0].State != "schedule_blocked" || r.Jobs[0].AuthorityEpoch != 7 {
		t.Fatal("revocation terminalization not durable")
	}
}

func TestAccountRetirementUsesIndependentCurrentActorEpoch(t *testing.T) {
	f := reusableManagerFixture(t, false)
	reusableApprovedResult(t, f, "succeeded") // Original approval predates live accounts.
	other := "operator_" + strings.Repeat("8", 32)
	g := &accountGateFixture{epoch: 7}
	if e := f.m.ConfigureAccountAuthority(g.admit); e != nil {
		t.Fatal(e)
	}
	j := f.m.record.Jobs[0]
	ctx := operatorauth.WithApprovalEpoch(context.Background(), 7)
	before := f.m.record
	if e := f.m.Retire(ctx, f.consent.Binding.DeviceID, other, j.ID, j.Occurrence, actionpermit.Digest(j.Envelope), actionpermit.Digest(j.ResultReport), true); e != nil {
		t.Fatal(e)
	}
	if e := CheckAccountTransition(before, f.m.record); e != nil {
		t.Fatal(e)
	}
	if f.m.record.Jobs[0].RetireAuthorityEpoch != 7 || f.m.record.Jobs[0].AuthorityEpoch != 0 {
		t.Fatal("retirement rebound original approval")
	}
	raw, e := f.m.ClaimRetirement(context.Background(), j.ID)
	if e != nil {
		t.Fatal(e)
	}
	p, e := VerifyRetirement(raw, f.m.PublicKey())
	if e != nil || p.ActorID != other {
		t.Fatal("wrong retirement actor", e)
	}
	release, e := f.m.BeginResponseAdmission(context.Background(), raw)
	if e != nil {
		t.Fatal(e)
	}
	release()
	g.mu.Lock()
	g.epoch = 8
	g.mu.Unlock()
	if _, e = f.m.ClaimRetirement(context.Background(), j.ID); !errors.Is(e, ErrAuthority) {
		t.Fatal("retirement revived", e)
	}
}

func TestAccountTransitionCannotRebindApproval(t *testing.T) {
	f, _ := accountApprovedFixture(t)
	before, e := DecodeRecord(f.m.raw)
	if e != nil {
		t.Fatal(e)
	}
	after, e := DecodeRecord(f.m.raw)
	if e != nil {
		t.Fatal(e)
	}
	after.Jobs[0].AuthorityEpoch++
	if e = CheckAccountTransition(before, after); !errors.Is(e, ErrIntegrity) {
		t.Fatalf("epoch rewrite accepted: %v", e)
	}
}

func TestAccountMetadataPreservesSignedPermitBytes(t *testing.T) {
	legacy := fixture(t)
	want := legacy.approve(t)
	live, _ := accountApprovedFixture(t)
	if !bytes.Equal(want, live.m.record.Jobs[0].Envelope) {
		t.Fatal("account metadata changed signed endpoint protocol")
	}
}
