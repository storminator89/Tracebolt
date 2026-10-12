package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"localrmm/internal/enrollmentstate"
	msi "localrmm/internal/windowsmanagedmsi"
)

func scheduledManagedStoreGrant(f windowsSoftwareStoreFixture) msi.Grant {
	g := managedStoreGrant(f)
	g.Version = msi.ScheduledGrantVersion
	g.ReusableAcknowledged = true
	g.ScheduledEnabled = true
	g.ScheduledAcknowledged = true
	g.MutationPlanDigest = msi.Digest([]byte("fresh exact scheduled MSI plan"))
	g.PeerBindingDigest = msi.Digest([]byte("separate background WUA peer"))
	return g
}

func TestManagedMSIScheduledFreshStoreWorklistAndRestart(t *testing.T) {
	f, g, a, dispatch := savedMSIStoreFixture(t, true)
	ctx := context.Background()
	key := f.key.Public().(ed25519.PublicKey)
	before, err := f.store.ReadRegisteredWindowsManagedMSI(ctx, g.Binding, key)
	if err != nil || !before.Grant.Scheduled() || before.SchedulePolicyFloor != 0 || before.Jobs.Sequence != 0 || before.TransferID != "" {
		t.Fatal("fresh scheduled registration", err)
	}
	if err = savedMSIDispatch(f, g, a, dispatch, ctx); err != nil {
		t.Fatal("exact saved worklist delivery", err)
	}
	original, journal := savedMSIRetirementState(t, f, g)
	if original.Jobs.Sequence != 1 || original.TransferID != dispatch.Request.TransferID || journal.Worklists[0].Batches[0].Items[0].State != "issued" {
		t.Fatal("scheduled worklist lost atomic delivery evidence")
	}
	if err = f.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(f.path, f.fixture.config, f.fixture.issuerDER)
	if err != nil {
		t.Fatal("scheduled reopen", err)
	}
	defer reopened.Close()
	f.store = reopened
	after, saved := savedMSIRetirementState(t, f, g)
	if !reflect.DeepEqual(original, after) || !reflect.DeepEqual(journal, saved) {
		t.Fatal("reopen changed scheduled record or worklist")
	}
	if err = savedMSIDispatch(f, g, a, dispatch, ctx); err == nil {
		t.Fatal("restart repeated an issued delivery")
	}
}

func TestManagedMSIScheduledRegistryDoesNotAdoptManualReusable(t *testing.T) {
	for _, scheduledFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "manual-first", true: "scheduled-first"}[scheduledFirst], func(t *testing.T) {
			f := newWindowsSoftwareStoreFixture(t, false)
			ctx := context.Background()
			key := f.key.Public().(ed25519.PublicKey)
			second := additionalSoftwareIdentity(t, fullSoftwareFixture{f: f.fixture, s: f.store, path: f.path, at: f.at}, 2)
			a := scheduledManagedStoreGrant(f)
			if !scheduledFirst {
				a.Version = msi.ReusableGrantVersion
				a.ScheduledEnabled, a.ScheduledAcknowledged = false, false
			}
			if err := f.store.SetupWindowsManagedMSICreateOnly(ctx, key, f.executor.Public().(ed25519.PublicKey), a, f.at); !errors.Is(err, msi.ErrInvalid) {
				t.Fatal("reusable/scheduled singleton admitted", err)
			}
			if err := f.store.SetupWindowsManagedMSIFleetCreateOnly(ctx, key, f.executor.Public().(ed25519.PublicKey), a, f.at, false); err != nil {
				t.Fatal(err)
			}
			b := a
			b.Binding.DeviceID = second.snap.Approval.DeviceID
			b.Binding.IncarnationDigest = "sha256:" + second.cert.CertificateHash()
			b.Binding.ExecutorID = id("executor", 14)
			b.Binding.DeliveryGrantID = id("grant", 16)
			b.Binding.InstallGrantID = id("grant", 17)
			executor := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{119}, 32)).Public().(ed25519.PublicKey)
			b.Binding.ExecutorKeyID = msi.Digest(executor)
			if scheduledFirst {
				b.Version = msi.ReusableGrantVersion
				b.ScheduledEnabled, b.ScheduledAcknowledged = false, false
			} else {
				b.Version = msi.ScheduledGrantVersion
				b.ScheduledEnabled, b.ScheduledAcknowledged = true, true
			}
			before, err := f.store.ReadRegisteredWindowsManagedMSI(ctx, a.Binding, key)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.store.SetupWindowsManagedMSIFleetCreateOnly(ctx, key, executor, b, f.at, true); !errors.Is(err, msi.ErrConflict) {
				t.Fatal("mixed reusable registry admitted", err)
			}
			after, err := f.store.ReadRegisteredWindowsManagedMSI(ctx, a.Binding, key)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("rejected mixed registration changed original record", err)
			}
			bindings, err := f.store.WindowsManagedMSIFleetBindings(ctx, key)
			if err != nil || len(bindings) != 1 || bindings[0] != a.Binding {
				t.Fatal("rejected registration changed roster", err)
			}
			// The same previously unused binding can still be deliberately created
			// under the original homogeneous profile; failed admission adopts nothing.
			b.Version = a.Version
			b.ScheduledEnabled, b.ScheduledAcknowledged = a.ScheduledEnabled, a.ScheduledAcknowledged
			if err = f.store.SetupWindowsManagedMSIFleetCreateOnly(ctx, key, executor, b, f.at, true); err != nil {
				t.Fatal("matching fresh registration", err)
			}
		})
	}
}

func managedScheduledRecord(t *testing.T, f windowsSoftwareStoreFixture) ([]byte, msi.Record, int64) {
	t.Helper()
	var raw []byte
	var rejected int64
	if err := f.store.db.QueryRow(`SELECT body,rejected_clock_floor FROM enrollment_windows_managed_msi_records WHERE invitation_id=?`, f.snapshot.InvitationID).Scan(&raw, &rejected); err != nil {
		t.Fatal(err)
	}
	r, err := msi.DecodeRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	return raw, r, rejected
}

func TestManagedMSISchedulePolicyLegacyBytesRemainUnchanged(t *testing.T) {
	f, g, _, _ := savedMSIStoreFixture(t)
	ctx := context.Background()
	key := f.key.Public().(ed25519.PublicKey)
	before, _, _ := managedScheduledRecord(t, f)
	at := f.at.Add(time.Second)
	r, err := f.store.ReconcileWindowsManagedMSISchedulePolicy(ctx, g.Binding, key, func() time.Time { return at }, func(string) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	after, _, rejected := managedScheduledRecord(t, f)
	body, _ := json.Marshal(r)
	if !bytes.Equal(before, after) || !bytes.Equal(before, body) || r.SchedulePolicyFloor != 0 || rejected != at.Unix() {
		t.Fatal("policy setup promoted legacy bytes or lost rejection floor")
	}
}

// All evidence is signed inert metadata. The fixture performs no MSI inspection,
// installation, native admission, host enrollment, or service operation.
func newManagedScheduledStoreFixture(t *testing.T, baselineOnly ...bool) (windowsSoftwareStoreFixture, msi.Grant) {
	t.Helper()
	f, g, a, delivered := savedMSIStoreFixture(t, true)
	ctx := context.Background()
	key := f.key.Public().(ed25519.PublicKey)
	if err := savedMSIDispatch(f, g, a, delivered, ctx); err != nil {
		t.Fatal("deliver exact scheduled assignment", err)
	}
	for _, step := range []string{"claim-delivery", "imported", "review", "claim-readiness", "ready", "schedule"} {
		if step == "schedule" && len(baselineOnly) == 1 && baselineOnly[0] {
			break
		}
		_, _, err := f.store.WindowsManagedMSITransaction(ctx, g.Binding, key, f.at, func(r *msi.Record, c msi.Current, at time.Time) error {
			var err error
			switch step {
			case "claim-delivery":
				r.DeliveryClaimedAt = at.Unix()
			case "imported":
				r.DeliveryReport, err = savedMSIStoreReport(f, r.DeliveryPermit, "delivery", at.Unix())
			case "review":
				p := msi.PermitForGrant(msi.Permit{Version: msi.Version, Kind: "readiness", TransferID: r.TransferID, Binding: g.Binding, LeafDigest: c.LeafDigest, Package: a.Package, NativeAcceptanceDigest: a.NativeAcceptanceDigest, ActorID: delivered.ActorID, IssuedAt: at.Unix(), ExpiresAt: at.Unix() + 60, Sequence: 1, MaintenanceUntil: at.Unix() + 600, PackageReviewAccepted: true, TermsAccepted: true, SynchronousReviewDigest: msi.SynchronousReviewDigest(a.Package, a.NativeAcceptanceDigest)}, g, r.Jobs.Sequence, a)
				r.ReadinessPermit, err = msi.SignPermit(p, f.key)
			case "claim-readiness":
				r.ReadinessClaimedAt = at.Unix()
			case "ready":
				r.ReadinessReport, err = savedMSIStoreReport(f, r.ReadinessPermit, "readiness", at.Unix())
			case "schedule":
				q := msi.ScheduleRequest{ArtifactID: msi.ArtifactIdentity(a), ArtifactRetiredCount: r.ArtifactRetiredCount, BindingDigest: msi.BindingDigest(g.Binding), TransferID: r.TransferID, JobSequence: r.Jobs.Sequence, ReadinessDigest: msi.Digest(r.ReadinessReport), StartAt: at.Unix() + 120, EndAt: at.Unix() + 300, PackageReviewAccepted: true, TermsAccepted: true, ServiceRiskAccepted: true, SynchronousActionsAccepted: true, ScheduleAccepted: true}
				approval := msi.ScheduleApproval{Version: msi.ScheduleVersion, Request: q, RequestDigest: msi.ScheduleRequestDigest(q), ActorID: delivered.ActorID, ApprovedAt: at.Unix(), GrantDigest: msi.GrantDigest(g), LeafDigest: c.LeafDigest, LeafExpiresAt: c.LeafNotAfter, BaselinePermitDigest: msi.Digest(r.ReadinessPermit)}
				approval.Digest = approval.CanonicalDigest()
				r.Schedule = &msi.ScheduledIntent{Approval: approval, BaselinePermit: bytes.Clone(r.ReadinessPermit), BaselineReport: bytes.Clone(r.ReadinessReport), State: "scheduled"}
			}
			return err
		})
		if err != nil {
			t.Fatal(step, err)
		}
	}
	return f, g
}

func TestManagedMSISchedulePolicyStartupTerminalizesExpiredAndRevoked(t *testing.T) {
	for _, kind := range []string{"expired", "revoked", "rollback"} {
		t.Run(kind, func(t *testing.T) {
			f, g := newManagedScheduledStoreFixture(t)
			ctx := context.Background()
			key := f.key.Public().(ed25519.PublicKey)
			_, before, _ := managedScheduledRecord(t, f)
			at := f.at.Add(2 * time.Second)
			floor := at.Unix()
			switch kind {
			case "expired":
				at = time.Unix(f.snapshot.Intent.NotAfter+1, 0).UTC()
				floor = at.Unix()
			case "revoked":
				control := f.fixture.control(f.snapshot, 211)
				control.Now = f.at.Unix() + 1
				if _, err := f.store.Terminate(ctx, enrollmentstate.TerminalCommand{Control: control, State: enrollmentstate.Revoked}); err != nil {
					t.Fatal(err)
				}
			case "rollback":
				floor = at.Unix() + 10
				guard := msi.WithFinalCheck(ctx, func() error { return msi.ErrAuthority })
				if _, _, err := f.store.WindowsManagedMSITransaction(guard, g.Binding, key, time.Unix(floor, 0).UTC(), func(*msi.Record, msi.Current, time.Time) error { return nil }); !errors.Is(err, msi.ErrAuthority) {
					t.Fatal("save rejected trusted floor", err)
				}
			}
			after, err := f.store.ReconcileWindowsManagedMSISchedulePolicy(ctx, g.Binding, key, func() time.Time { return at }, func(string) bool { return false })
			if err != nil {
				t.Fatal("unavailable member blocked startup terminalization", err)
			}
			_, persisted, rejected := managedScheduledRecord(t, f)
			before.SchedulePolicyFloor = floor
			before.Schedule.State, before.Schedule.OutcomeAt = "blocked", floor
			if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(after, persisted) || rejected != floor {
				t.Fatal("terminalization changed original authority, evidence, or floor")
			}
			if err = f.store.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(f.path, f.fixture.config, f.fixture.issuerDER)
			if err != nil {
				t.Fatal("policy-only time corrupted enrollment history", err)
			}
			defer reopened.Close()
			f.store = reopened
			restored, err := reopened.ReconcileWindowsManagedMSISchedulePolicy(ctx, g.Binding, key, func() time.Time { return at.Add(time.Second) }, func(string) bool { return true })
			if err != nil || restored.Schedule.State != "blocked" || restored.Schedule.OutcomeAt != floor || restored.Schedule.Approval != after.Schedule.Approval || restored.ClockFloor != after.ClockFloor {
				t.Fatal("restored actor revived original schedule or renewed authority", err)
			}
		})
	}
}

func TestManagedMSISchedulePolicyRejectedTransactionsKeepTerminalization(t *testing.T) {
	for _, kind := range []string{"callback", "final-policy", "final-expiry", "revoked", "expired", "clock-rollback"} {
		t.Run(kind, func(t *testing.T) {
			f, g := newManagedScheduledStoreFixture(t)
			key := f.key.Public().(ed25519.PublicKey)
			_, before, _ := managedScheduledRecord(t, f)
			at := f.at.Add(2 * time.Second)
			allowed := false
			ctx := msi.WithSchedulePolicy(context.Background(), func(string) bool { return allowed })
			clock := at
			want := msi.ErrAuthority
			callback := func(*msi.Record, msi.Current, time.Time) error { return nil }
			floor := at.Unix()
			switch kind {
			case "callback":
				want = msi.ErrConflict
				callback = func(r *msi.Record, _ msi.Current, _ time.Time) error { r.Schedule = nil; return want }
			case "final-policy":
				allowed = true
				ctx = msi.WithFinalCheck(WithOverviewClock(ctx, func() time.Time { return clock }), func() error {
					allowed = false
					clock = clock.Add(time.Second)
					return msi.ErrAuthority
				})
				floor++
			case "final-expiry":
				allowed = true
				want = msi.ErrExpired
				floor = g.ExpiresAt
				ctx = msi.WithFinalCheck(WithOverviewClock(ctx, func() time.Time { return clock }), func() error {
					allowed = false
					clock = time.Unix(g.ExpiresAt, 0).UTC()
					return nil
				})
			case "revoked":
				control := f.fixture.control(f.snapshot, 211)
				control.Now = f.at.Unix() + 1
				if _, err := f.store.Terminate(context.Background(), enrollmentstate.TerminalCommand{Control: control, State: enrollmentstate.Revoked}); err != nil {
					t.Fatal(err)
				}
			case "expired":
				want = msi.ErrExpired
				at = time.Unix(g.ExpiresAt, 0).UTC()
				floor = at.Unix()
			case "clock-rollback":
				want = msi.ErrExpired
				floor = at.Unix() + 10
				guard := msi.WithFinalCheck(context.Background(), func() error { return msi.ErrAuthority })
				if _, _, err := f.store.WindowsManagedMSITransaction(guard, g.Binding, key, time.Unix(floor, 0).UTC(), callback); !errors.Is(err, msi.ErrAuthority) {
					t.Fatal(err)
				}
			}
			out, _, err := f.store.WindowsManagedMSITransaction(ctx, g.Binding, key, at, callback)
			if !errors.Is(err, want) || !reflect.DeepEqual(out, msi.Record{}) {
				t.Fatal("rejected transaction returned evidence or wrong error", err)
			}
			_, after, rejected := managedScheduledRecord(t, f)
			before.SchedulePolicyFloor = floor
			before.Schedule.State, before.Schedule.OutcomeAt = "blocked", floor
			if !reflect.DeepEqual(before, after) || rejected != floor {
				t.Fatal("rejected transaction lost original terminalization or changed evidence")
			}
			allowed = true
			restored, err := f.store.ReconcileWindowsManagedMSISchedulePolicy(context.Background(), g.Binding, key, func() time.Time { return time.Unix(floor+1, 0).UTC() }, func(string) bool { return true })
			if err != nil || restored.Schedule.State != "blocked" || restored.Schedule.OutcomeAt != floor || restored.Schedule.Approval != before.Schedule.Approval || len(restored.InstallPermit) != 0 {
				t.Fatal("actor restoration revived original schedule", err)
			}
		})
	}
}

func TestManagedMSIScheduledRequiresFreshWorklistMarker(t *testing.T) {
	f := newWindowsSoftwareStoreFixture(t, false)
	g := scheduledManagedStoreGrant(f)
	marker := &windowsManagedMSISetupMarker{Version: windowsManagedMSIFleetSetupVersion, Grant: g, InitializedAt: f.at, WorklistsVersion: msi.WorklistVersion}
	if !validWindowsManagedMSISetupMarker(f.snapshot, marker) {
		t.Fatal("valid fresh scheduled marker rejected")
	}
	marker.WorklistsVersion = ""
	if validWindowsManagedMSISetupMarker(f.snapshot, marker) {
		t.Fatal("scheduled grant adopted historical unmarked worklist profile")
	}
	marker.Grant.Version = msi.ReusableGrantVersion
	marker.Grant.ScheduledEnabled, marker.Grant.ScheduledAcknowledged = false, false
	if !validWindowsManagedMSISetupMarker(f.snapshot, marker) {
		t.Fatal("legacy unmarked reusable profile lost compatibility")
	}
}

func issueManagedScheduledStorePermit(t *testing.T, f *windowsSoftwareStoreFixture, g msi.Grant, claimed bool) {
	t.Helper()
	_, original, _ := managedScheduledRecord(t, *f)
	f.at = time.Unix(original.Schedule.Approval.Request.StartAt, 0).UTC()
	key := f.key.Public().(ed25519.PublicKey)
	steps := []string{"due-readiness", "claim-readiness", "ready", "shared-idle", "approve"}
	if claimed {
		steps = append(steps, "claim-install")
	}
	for _, step := range steps {
		_, _, err := f.store.WindowsManagedMSITransaction(context.Background(), g.Binding, key, f.at, func(r *msi.Record, _ msi.Current, at time.Time) error {
			var err error
			switch step {
			case "due-readiness":
				p, e := msi.VerifyPermit(r.Schedule.BaselinePermit, key)
				if e != nil {
					return e
				}
				p.Sequence++
				p.IssuedAt = at.Unix()
				p.ExpiresAt = min(at.Unix()+60, r.Schedule.Approval.Request.EndAt)
				p.MaintenanceUntil = r.Schedule.Approval.Request.EndAt
				p.ScheduleDigest = r.Schedule.Approval.Digest
				p.ScheduleStartAt = r.Schedule.Approval.Request.StartAt
				p.ScheduleEndAt = r.Schedule.Approval.Request.EndAt
				r.ReadinessPermit, err = msi.SignPermit(p, f.key)
				r.ReadinessClaimedAt, r.ReadinessReport = 0, nil
				r.Schedule.State, r.Schedule.ReadinessIssuedAt = "readiness_issued", at.Unix()
			case "claim-readiness":
				r.ReadinessClaimedAt = at.Unix()
			case "ready":
				r.ReadinessReport, err = savedMSIStoreReport(*f, r.ReadinessPermit, "readiness", at.Unix())
			case "shared-idle":
				r.MutationReport, err = savedMSIStoreReport(*f, r.DeliveryPermit, "mutation", at.Unix())
			case "approve":
				p, e := msi.VerifyPermit(r.ReadinessPermit, key)
				if e != nil {
					return e
				}
				p.Kind = "install"
				p.ReadinessDigest = msi.Digest(r.ReadinessReport)
				r.InstallPermit, err = msi.SignPermit(p, f.key)
				r.Schedule.State, r.Schedule.PermitIssuedAt = "permit_issued", at.Unix()
			case "claim-install":
				r.InstallClaimedAt = at.Unix()
			}
			return err
		})
		if err != nil {
			t.Fatal(step, err)
		}
	}
}

func TestManagedMSISchedulePolicyRetainsIssuedPermitAndClaim(t *testing.T) {
	for _, claimed := range []bool{false, true} {
		t.Run(map[bool]string{false: "issued", true: "claimed"}[claimed], func(t *testing.T) {
			f, g := newManagedScheduledStoreFixture(t)
			issueManagedScheduledStorePermit(t, &f, g, claimed)
			_, before, _ := managedScheduledRecord(t, f)
			at := f.at.Add(time.Second)
			after, err := f.store.ReconcileWindowsManagedMSISchedulePolicy(context.Background(), g.Binding, f.key.Public().(ed25519.PublicKey), func() time.Time { return at }, func(string) bool { return false })
			if err != nil {
				t.Fatal(err)
			}
			before.SchedulePolicyFloor = at.Unix()
			before.Schedule.State, before.Schedule.OutcomeAt = "blocked", at.Unix()
			if !reflect.DeepEqual(before, after) || len(after.InstallPermit) == 0 || (after.InstallClaimedAt != 0) != claimed {
				t.Fatal("terminalization changed issued execution evidence")
			}
		})
	}
}

func TestManagedMSISchedulePolicyStartupRequiresExactRegisteredAuthority(t *testing.T) {
	for _, kind := range []string{"binding", "key", "final-check", "clock-rollback"} {
		t.Run(kind, func(t *testing.T) {
			f, g := newManagedScheduledStoreFixture(t)
			before, _, rejectedBefore := managedScheduledRecord(t, f)
			ctx := context.Background()
			binding := g.Binding
			key := f.key.Public().(ed25519.PublicKey)
			at := f.at.Add(time.Second)
			now := func() time.Time { return at }
			switch kind {
			case "binding":
				binding.DeliveryGrantID = id("grant", 25)
			case "key":
				key = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{119}, 32)).Public().(ed25519.PublicKey)
			case "final-check":
				ctx = msi.WithFinalCheck(ctx, func() error { return msi.ErrAuthority })
			case "clock-rollback":
				now = func() time.Time { previous := at; at = at.Add(-time.Second); return previous }
			}
			called := false
			out, err := f.store.ReconcileWindowsManagedMSISchedulePolicy(ctx, binding, key, now, func(string) bool { called = true; return false })
			if err == nil || called || !reflect.DeepEqual(out, msi.Record{}) {
				t.Fatal("invalid startup admission evaluated policy or exposed evidence", err)
			}
			after, _, rejectedAfter := managedScheduledRecord(t, f)
			if !bytes.Equal(before, after) || rejectedBefore != rejectedAfter {
				t.Fatal("rejected startup changed saved schedule")
			}
		})
	}
}

func TestManagedMSISchedulePolicyCannotInventFutureFloor(t *testing.T) {
	f, g := newManagedScheduledStoreFixture(t)
	before, _, _ := managedScheduledRecord(t, f)
	key := f.key.Public().(ed25519.PublicKey)
	_, _, err := f.store.WindowsManagedMSITransaction(context.Background(), g.Binding, key, f.at, func(r *msi.Record, _ msi.Current, at time.Time) error {
		r.SchedulePolicyFloor = at.Unix() + 1
		return nil
	})
	if !errors.Is(err, msi.ErrInvalid) {
		t.Fatal("callback invented unobserved policy floor", err)
	}
	after, _, rejected := managedScheduledRecord(t, f)
	if !bytes.Equal(before, after) || rejected != f.at.Unix() {
		t.Fatal("rejected future policy time escaped rollback")
	}
}
