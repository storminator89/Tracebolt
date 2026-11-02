package windowsmanagedmsimanager

import (
	"context"
	"errors"
	"localrmm/internal/operatorauth"
	msi "localrmm/internal/windowsmanagedmsi"
	"sync"
	"testing"
)

type epochAuthority struct {
	mu    sync.RWMutex
	epoch uint64
}

func (a *epochAuthority) admit(ctx context.Context, actor string, epoch uint64, caps ...operatorauth.Capability) (context.Context, func(), error) {
	a.mu.RLock()
	if epoch == 0 || epoch != a.epoch {
		a.mu.RUnlock()
		return ctx, nil, operatorauth.ErrForbidden
	}
	return ctx, a.mu.RUnlock, nil
}
func TestAccountEpochDeliveryCannotReviveAfterRegrant(t *testing.T) {
	m, s, _, actor, n := managerFixture(t)
	auth := &epochAuthority{epoch: 1}
	if err := m.ConfigureAccountAuthority(auth.admit); err != nil {
		t.Fatal(err)
	}
	ctx := operatorauth.WithApprovalEpoch(context.Background(), 1)
	if err := m.ReserveUpload(ctx, actor, managerSelection(), msi.Digest([]byte("acceptance"))); err != nil {
		t.Fatal(err)
	}
	s.r.Artifact.Offset = s.r.Artifact.Package.Size
	s.r.Artifact.PrefixDigest = s.r.Artifact.Package.SHA256
	s.r.Artifact.LastChunkDigest = msi.Digest([]byte("complete"))
	s.r.Artifact.CompletedAt = *n
	if err := m.Deliver(ctx, actor, "transfer_77777777777777777777777777777777", true); err != nil {
		t.Fatal(err)
	}
	digest := msi.Digest(s.r.DeliveryPermit)
	if s.r.AccountEpochs[digest] != 1 {
		t.Fatal("approval epoch not persisted")
	}
	out, err := m.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	auth.mu.Lock()
	auth.epoch = 3
	auth.mu.Unlock()
	if _, err = m.Poll(context.Background()); !errors.Is(err, msi.ErrAuthority) {
		t.Fatalf("old permit revived: %v", err)
	}
	if err = m.CheckRelease(context.Background(), out.Permit, ""); !errors.Is(err, msi.ErrAuthority) {
		t.Fatalf("old response released: %v", err)
	}
	if s.r.AccountEpochs[digest] != 1 {
		t.Fatal("approval epoch rewritten")
	}
}
func TestAccountEpochLegacyPermitDeniedInLiveMode(t *testing.T) {
	m, s, _, _, _ := managerImportedFixture(t)
	if len(s.r.AccountEpochs) != 0 {
		t.Fatal("legacy fixture unexpectedly bound")
	}
	if err := m.ConfigureAccountAuthority((&epochAuthority{epoch: 1}).admit); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.BeginResponseAdmission(context.Background(), s.r.DeliveryPermit, ""); !errors.Is(err, msi.ErrAuthority) {
		t.Fatalf("legacy permit adopted: %v", err)
	}
}
func TestAccountLeaseProofExpiresOnRelease(t *testing.T) {
	a := &epochAuthority{epoch: 9}
	ctx, release, err := leaseAccount(context.Background(), a.admit, "actor", 9, capsFor("install", false))
	if err != nil {
		t.Fatal(err)
	}
	if !hasAccountHold(ctx, "actor", 9, capsFor("install", false)) {
		t.Fatal("missing hold")
	}
	release()
	release()
	if hasAccountHold(ctx, "actor", 9, capsFor("install", false)) {
		t.Fatal("released proof reused")
	}
}

func TestAccountEpochScheduleCannotReviveAfterRegrant(t *testing.T) {
	m, s, _, actor, n, q, _ := scheduledManagerFixture(t)
	authority := &epochAuthority{epoch: 1}
	if err := m.ConfigureAccountAuthority(authority.admit); err != nil {
		t.Fatal(err)
	}
	ctx := operatorauth.WithApprovalEpoch(context.Background(), 1)
	if err := m.Schedule(ctx, actor, q); err != nil {
		t.Fatal(err)
	}
	r := s.members[m.binding.DeviceID].r
	key := r.Schedule.Approval.Digest
	if r.AccountEpochs[key] != 1 {
		t.Fatal("scheduled approval epoch not durable")
	}
	raw, err := msi.EncodeRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := msi.DecodeRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	s.members[m.binding.DeviceID].r = restored
	authority.mu.Lock()
	authority.epoch = 3
	authority.mu.Unlock()
	*n = q.StartAt
	if _, err = m.Poll(context.Background()); !errors.Is(err, msi.ErrAuthority) {
		t.Fatalf("old scheduled approval revived: %v", err)
	}
	r = s.members[m.binding.DeviceID].r
	if r.AccountEpochs[key] != 1 || r.Schedule.ReadinessIssuedAt != 0 || len(r.InstallPermit) != 0 {
		t.Fatal("withdrawn schedule issued new authority")
	}
}

func TestAccountLeaseSerializesWithdrawalUntilHandoff(t *testing.T) {
	a := &epochAuthority{epoch: 1}
	ctx, release, err := leaseAccount(context.Background(), a.admit, "actor", 1, capsFor("deliver", false))
	if err != nil {
		t.Fatal(err)
	}
	started, done := make(chan struct{}), make(chan struct{})
	go func() { close(started); a.mu.Lock(); a.epoch = 2; a.mu.Unlock(); close(done) }()
	<-started
	if !hasAccountHold(ctx, "actor", 1, capsFor("deliver", false)) {
		t.Fatal("handoff lost hold")
	}
	select {
	case <-done:
		t.Fatal("withdrawal passed held response lease")
	default:
	}
	release()
	<-done
	if _, _, err := leaseAccount(context.Background(), a.admit, "actor", 1, capsFor("deliver", false)); !errors.Is(err, msi.ErrAuthority) {
		t.Fatal("retired epoch admitted", err)
	}
}
