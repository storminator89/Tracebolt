package windowsmanagedmsimanager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"localrmm/internal/enrollmentstate"
	msi "localrmm/internal/windowsmanagedmsi"
	"testing"
	"time"
)

type memoryStore struct {
	r                msi.Record
	current          msi.Current
	now              *int64
	calls            int
	failCall         int
	afterCommit      func()
	commitClockFloor int64
}

func (s *memoryStore) WindowsManagedMSIEnrollmentBinding() enrollmentstate.Binding {
	return enrollmentstate.Binding{InstanceID: s.current.Binding.ManagerID, Profile: "tls", CollectionProfile: "windows-inventory-v1"}
}
func (s *memoryStore) ReadRegisteredWindowsManagedMSI(ctx context.Context, b msi.Binding, k ed25519.PublicKey) (msi.Record, error) {
	raw, _ := msi.EncodeRecord(s.r)
	return msi.DecodeRecord(raw)
}
func (s *memoryStore) WindowsManagedMSITransaction(ctx context.Context, b msi.Binding, k ed25519.PublicKey, at time.Time, fn func(*msi.Record, msi.Current, time.Time) error) (msi.Record, time.Time, error) {
	s.calls++

	raw, _ := msi.EncodeRecord(s.r)
	next, _ := msi.DecodeRecord(raw)
	next.ClockFloor = *s.now
	if e := fn(&next, s.current, time.Unix(*s.now, 0)); e != nil {
		return msi.Record{}, at, e
	}
	if e := msi.CheckFinal(ctx); e != nil {
		return msi.Record{}, at, e
	}
	if e := msi.Transition(s.r, next); e != nil {
		return msi.Record{}, at, e
	}
	if e := msi.FinalDeadline(s.r, next, s.current, *s.now); e != nil {
		return msi.Record{}, at, e
	}
	if s.failCall == s.calls {
		return msi.Record{}, at, msi.ErrUncertain
	}
	next.ClockFloor = max(next.ClockFloor, s.commitClockFloor)
	s.r = next
	if s.afterCommit != nil {
		s.afterCommit()
	}
	return next, at, nil
}
func managerFixture(t *testing.T) (*Manager, *memoryStore, ed25519.PrivateKey, string, *int64) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, 32))
	executor := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{18}, 32))
	b := msi.Binding{ManagerID: "manager_11111111111111111111111111111111", DeviceID: "agent_22222222222222222222222222222222", IncarnationDigest: msi.Digest([]byte("original")), ExecutorID: "executor_33333333333333333333333333333333", ExecutorKeyID: msi.Digest(executor.Public().(ed25519.PublicKey)), KeyID: msi.Digest(key.Public().(ed25519.PublicKey)), DeliveryGrantID: "grant_44444444444444444444444444444444", InstallGrantID: "grant_55555555555555555555555555555555"}
	n := int64(1800000000)
	g := msi.Grant{Version: msi.GrantVersion, Binding: b, DeliveryEnabled: true, InstallEnabled: true, DeliveryAcknowledged: true, InstallAcknowledged: true, ServiceRiskAcknowledged: true, ExpiresAt: n + 7200}
	r, e := msi.NewRecord(g, key.Public().(ed25519.PublicKey), executor.Public().(ed25519.PublicKey), n)
	if e != nil {
		t.Fatal(e)
	}
	s := &memoryStore{r: r, current: msi.Current{Binding: b, LeafDigest: msi.Digest([]byte("leaf")), LeafGeneration: 1, LeafNotBefore: n - 3600, LeafNotAfter: n + 7200, Enabled: true}, now: &n}
	m := &Manager{store: s, binding: b, key: key, spool: &Spool{}, now: func() time.Time { return time.Unix(n, 0) }, configurationCheck: func() error { return nil }}
	actor := "operator_66666666666666666666666666666666"
	if e = m.ConfigureOperatorPolicy(func(a string) bool { return a == actor }, func(a string) bool { return a == actor }); e != nil {
		t.Fatal(e)
	}
	return m, s, executor, actor, &n
}
func managerSelection() msi.Selection {
	return msi.Selection{SHA256: msi.Digest([]byte("inert fixture")), Size: 1024, ProductCode: "{11111111-2222-3333-4444-555555555555}", PackageCode: "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}", Version: "1.2.3", Architecture: "amd64", Name: "Inert fixture", TermsReviewDigest: msi.Digest([]byte("terms fixture")), ReviewReference: "source fixture only"}
}
func TestManagedManagerExactLifecycleAndOneAttempt(t *testing.T) {
	m, s, executor, actor, n := managerFixture(t)
	ctx := context.Background()
	sel := managerSelection()
	if e := m.ReserveUpload(ctx, actor, sel, msi.Digest([]byte("acceptance fixture"))); e != nil {
		t.Fatal(e)
	}
	if e := m.Deliver(ctx, actor, "transfer_77777777777777777777777777777777", true); !errors.Is(e, msi.ErrUnavailable) {
		t.Fatal(e)
	}
	s.r.Artifact.Offset = s.r.Artifact.Package.Size
	s.r.Artifact.PrefixDigest = s.r.Artifact.Package.SHA256
	s.r.Artifact.LastChunkDigest = msi.Digest([]byte("synthetic complete"))
	s.r.Artifact.CompletedAt = *n // source fixture only; no actual MSI or upload
	id := "transfer_77777777777777777777777777777777"
	if e := m.Deliver(ctx, actor, id, true); e != nil {
		t.Fatal(e)
	}
	first, e := m.Poll(ctx)
	if e != nil {
		t.Fatal(e)
	}
	again, e := m.Poll(ctx)
	if e != nil || !bytes.Equal(first.Permit, again.Permit) {
		t.Fatal("delivery did not preserve exact resume bytes", e)
	}
	p, _ := msi.VerifyPermit(first.Permit, s.r.PublicKey)
	report := msi.Report{Version: msi.Version, Kind: "delivery", Binding: p.Binding, TransferID: id, PermitDigest: msi.Digest(first.Permit), Package: sel, NativeAcceptanceDigest: p.NativeAcceptanceDigest, CapturedAt: *n, Offset: sel.Size, State: "imported"}
	raw, _ := msi.SignReport(report, executor)
	if e = m.Report(ctx, raw); e != nil {
		t.Fatal(e)
	}
	if e = m.Review(ctx, actor, true, true, false); !errors.Is(e, msi.ErrInvalid) {
		t.Fatal(e)
	}
	if e = m.Review(ctx, actor, true, true, true); e != nil {
		t.Fatal(e)
	}
	readyPermit, e := m.Poll(ctx)
	if e != nil {
		t.Fatal(e)
	}
	duplicate, e := m.Poll(ctx)
	if e != nil || len(duplicate.Permit) != 0 {
		t.Fatal("readiness redelivered", e)
	}
	p, _ = msi.VerifyPermit(readyPermit.Permit, s.r.PublicKey)
	readiness := msi.Readiness{Selection: sel, CapturedAt: *n, PackageVerified: msi.Yes, MachineAbsent: msi.Yes, InstallerBusy: msi.No, NativeAcceptance: msi.Yes, PackageReviewAccepted: msi.Yes, MaintenanceWindowEnd: p.MaintenanceUntil}
	report.Kind = "readiness"
	report.State = "ready"
	report.PermitDigest = msi.Digest(readyPermit.Permit)
	report.Readiness = &readiness
	raw, _ = msi.SignReport(report, executor)
	if e = m.Report(ctx, raw); e != nil {
		t.Fatal(e)
	}
	if e = m.Approve(ctx, actor, msi.Digest(raw), true); e != nil {
		t.Fatal(e)
	}
	install, e := m.Poll(ctx)
	if e != nil || len(install.Permit) == 0 {
		t.Fatal(e)
	}
	duplicate, e = m.Poll(ctx)
	if e != nil || len(duplicate.Permit) != 0 {
		t.Fatal("install replay", e)
	}
	result := msi.Result{ReturnCodeKnown: true, JobID: "software_77777777777777777777777777777777", EnvelopeDigest: msi.Digest(install.Permit), Attempted: true, Outcome: "restart_required", ReturnCode: 3010, RegistrationVerified: msi.Unknown, CompletedAt: *n}
	report.Kind = "result"
	report.State = result.Outcome
	report.PermitDigest = result.EnvelopeDigest
	report.Readiness = nil
	report.Result = &result
	raw, _ = msi.SignReport(report, executor)
	if e = m.Report(ctx, raw); e != nil {
		t.Fatal(e)
	}
	if e = m.Report(ctx, raw); e != nil {
		t.Fatal("exact result receipt retry", e)
	}
	v, e := m.View(ctx)
	if e != nil || v.State != "complete" || v.Result.ReturnCode != 3010 || v.Result.RegistrationVerified != msi.Unknown {
		t.Fatal(e)
	}
	if e = m.Approve(ctx, actor, msi.Digest(s.r.ReadinessReport), true); !errors.Is(e, msi.ErrConsumed) {
		t.Fatal("second install", e)
	}
}
func TestManagedManagerFinalPermissionAndExpiry(t *testing.T) {
	m, s, _, actor, n := managerFixture(t)
	ctx := context.Background()
	if e := m.ReserveUpload(ctx, actor, managerSelection(), msi.Digest([]byte("fixture"))); e != nil {
		t.Fatal(e)
	}
	s.r.Artifact.Offset = s.r.Artifact.Package.Size
	s.r.Artifact.PrefixDigest = s.r.Artifact.Package.SHA256
	s.r.Artifact.LastChunkDigest = msi.Digest([]byte("synthetic complete"))
	s.r.Artifact.CompletedAt = *n
	if e := m.Deliver(ctx, actor, "transfer_77777777777777777777777777777777", true); e != nil {
		t.Fatal(e)
	}
	guarded := msi.WithFinalCheck(ctx, func() error { *n = s.current.LeafNotAfter; return nil })
	if out, e := m.Poll(guarded); e == nil || len(out.Permit) != 0 {
		t.Fatal("expired permit escaped final wait", e)
	}
	*n = s.r.ClockFloor
	m.deliveryAllowed = func(string) bool { return false }
	if _, e := m.Poll(ctx); !errors.Is(e, msi.ErrAuthority) {
		t.Fatal("removed delivery permission", e)
	}
}

func managerImportedFixture(t *testing.T) (*Manager, *memoryStore, ed25519.PrivateKey, string, *int64) {
	t.Helper()
	m, s, executor, actor, n := managerFixture(t)
	ctx := context.Background()
	if e := m.ReserveUpload(ctx, actor, managerSelection(), msi.Digest([]byte("synthetic native acceptance"))); e != nil {
		t.Fatal(e)
	}
	s.r.Artifact.Offset = s.r.Artifact.Package.Size
	s.r.Artifact.PrefixDigest = s.r.Artifact.Package.SHA256
	s.r.Artifact.LastChunkDigest = msi.Digest([]byte("synthetic complete"))
	s.r.Artifact.CompletedAt = *n
	if e := m.Deliver(ctx, actor, "transfer_77777777777777777777777777777777", true); e != nil {
		t.Fatal(e)
	}
	out, e := m.Poll(ctx)
	if e != nil {
		t.Fatal(e)
	}
	p, _ := msi.VerifyPermit(out.Permit, s.r.PublicKey)
	r := msi.Report{Version: msi.Version, Kind: "delivery", Binding: p.Binding, TransferID: p.TransferID, PermitDigest: msi.Digest(out.Permit), Package: p.Package, NativeAcceptanceDigest: p.NativeAcceptanceDigest, CapturedAt: *n, Offset: p.Package.Size, State: "imported"}
	raw, _ := msi.SignReport(r, executor)
	if e = m.Report(ctx, raw); e != nil {
		t.Fatal(e)
	}
	return m, s, executor, actor, n
}
func TestManagedManagerExpiredReadinessNeedsFreshExplicitReview(t *testing.T) {
	m, s, executor, actor, n := managerImportedFixture(t)
	ctx := context.Background()
	if e := m.Review(ctx, actor, true, true, true); e != nil {
		t.Fatal(e)
	}
	old, e := m.Poll(ctx)
	if e != nil {
		t.Fatal(e)
	}
	p, _ := msi.VerifyPermit(old.Permit, s.r.PublicKey)
	*n = p.ExpiresAt
	v, e := m.View(ctx)
	if e != nil || v.State != "intervention_required" || !v.CanReview {
		t.Fatal("lost readiness visibility", e)
	}
	if e = m.Review(ctx, actor, true, true, false); e == nil {
		t.Fatal("implicit maintenance renewal")
	}
	if e = m.Review(ctx, actor, true, true, true); e != nil {
		t.Fatal(e)
	}
	next, e := m.Poll(ctx)
	if e != nil {
		t.Fatal(e)
	}
	q, _ := msi.VerifyPermit(next.Permit, s.r.PublicKey)
	if q.Sequence != p.Sequence+1 || q.IssuedAt != *n {
		t.Fatal("nonmonotonic new review")
	}
	ready := msi.Readiness{Selection: p.Package, CapturedAt: p.IssuedAt, PackageVerified: msi.Yes, MachineAbsent: msi.Yes, InstallerBusy: msi.No, NativeAcceptance: msi.Yes, PackageReviewAccepted: msi.Yes, MaintenanceWindowEnd: p.MaintenanceUntil}
	report := msi.Report{Version: msi.Version, Kind: "readiness", Binding: p.Binding, TransferID: p.TransferID, PermitDigest: msi.Digest(old.Permit), Package: p.Package, NativeAcceptanceDigest: p.NativeAcceptanceDigest, CapturedAt: p.IssuedAt, Offset: p.Package.Size, State: "ready", Readiness: &ready}
	raw, _ := msi.SignReport(report, executor)
	if e = m.Report(ctx, raw); e == nil {
		t.Fatal("old readiness satisfied fresh review")
	}
}
func TestManagedManagerLateInterventionIsNotImportOrInstall(t *testing.T) {
	m, s, executor, actor, n := managerFixture(t)
	s.r.Grant.ExpiresAt = *n + 172800
	s.current.LeafNotAfter = *n + 172800
	ctx := context.Background()
	if e := m.ReserveUpload(ctx, actor, managerSelection(), msi.Digest([]byte("synthetic native"))); e != nil {
		t.Fatal(e)
	}
	s.r.Artifact.Offset = s.r.Artifact.Package.Size
	s.r.Artifact.PrefixDigest = s.r.Artifact.Package.SHA256
	s.r.Artifact.LastChunkDigest = msi.Digest([]byte("synthetic complete"))
	s.r.Artifact.CompletedAt = *n
	if e := m.Deliver(ctx, actor, "transfer_77777777777777777777777777777777", true); e != nil {
		t.Fatal(e)
	}
	out, e := m.Poll(ctx)
	if e != nil {
		t.Fatal(e)
	}
	p, _ := msi.VerifyPermit(out.Permit, s.r.PublicKey)
	*n = p.ExpiresAt + 1
	report := msi.Report{Version: msi.Version, Kind: "delivery", Binding: p.Binding, TransferID: p.TransferID, PermitDigest: msi.Digest(out.Permit), Package: p.Package, NativeAcceptanceDigest: p.NativeAcceptanceDigest, CapturedAt: *n, Offset: p.Package.Size, State: "imported"}
	raw, _ := msi.SignReport(report, executor)
	if e = m.Report(ctx, raw); !errors.Is(e, msi.ErrExpired) {
		t.Fatal("late successful import", e)
	}
	report.State = "intervention_required"
	raw, _ = msi.SignReport(report, executor)
	if e = m.Report(ctx, raw); e != nil {
		t.Fatal(e)
	}
	v, e := m.View(ctx)
	if e != nil || v.State != "intervention_required" || v.CanReview {
		t.Fatal(e)
	}
	if e = m.Review(ctx, actor, true, true, true); e == nil {
		t.Fatal("intervention granted readiness")
	}
}

func TestManagedManagerReleaseRechecksAfterCommitWait(t *testing.T) {
	for _, change := range []string{"permit", "grant", "leaf", "operator", "configuration", "session", "canceled", "final_guard_wait", "committed_floor"} {
		t.Run(change, func(t *testing.T) {
			m, s, _, actor, n := managerImportedFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if e := m.Review(ctx, actor, true, true, true); e != nil {
				t.Fatal(e)
			}
			out, e := m.Poll(ctx)
			if e != nil || len(out.Permit) == 0 {
				t.Fatal(e)
			}
			p, e := msi.VerifyPermit(out.Permit, s.r.PublicKey)
			if e != nil {
				t.Fatal(e)
			}
			if change == "committed_floor" {
				s.commitClockFloor = *n + 5
			}
			claim := s.r.ReadinessClaimedAt
			finalDenied := false
			ctx = msi.WithFinalCheck(ctx, func() error {
				if finalDenied {
					if change == "final_guard_wait" {
						*n = p.ExpiresAt
						return nil
					}
					return msi.ErrAuthority
				}
				return nil
			})
			s.afterCommit = func() {
				switch change {
				case "committed_floor":
					*n += 4
				case "permit":
					*n = p.ExpiresAt
				case "grant":
					*n = s.r.Grant.ExpiresAt
				case "leaf":
					*n = s.current.LeafNotAfter
				case "operator":
					m.installAllowed = func(string) bool { return false }
				case "configuration":
					m.configurationCheck = func() error { return msi.ErrAuthority }
				case "session", "final_guard_wait":
					finalDenied = true
				case "canceled":
					cancel()
				}
			}
			if e = m.CheckRelease(ctx, out.Permit, ""); e == nil {
				t.Fatal("authority escaped post-commit wait")
			}
			if s.r.ReadinessClaimedAt != claim || !bytes.Equal(s.r.ReadinessPermit, out.Permit) {
				t.Fatal("refusal changed durable claim")
			}
		})
	}
}
