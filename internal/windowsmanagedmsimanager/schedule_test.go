package windowsmanagedmsimanager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	msi "localrmm/internal/windowsmanagedmsi"
	fence "localrmm/internal/windowsmutationfence"
	"sync"
	"testing"
	"time"
)

func (s *fleetMemoryStore) ReconcileWindowsManagedMSISchedulePolicy(ctx context.Context, b msi.Binding, k ed25519.PublicKey, now func() time.Time, allowed func(string) bool) (msi.Record, error) {
	r := s.members[b.DeviceID].r
	raw, _ := msi.EncodeRecord(r)
	next, e := msi.DecodeRecord(raw)
	if e != nil {
		return r, e
	}
	if e = msi.TerminalizeSchedulePolicy(&next, now().Unix(), allowed); e != nil {
		return r, e
	}
	if e = msi.Transition(r, next); e != nil {
		return r, e
	}
	s.members[b.DeviceID].r = next
	return next, nil
}
func scheduledManagerFixture(t *testing.T) (*Manager, *fleetMemoryStore, ed25519.PrivateKey, string, *int64, msi.ScheduleRequest, []byte) {
	t.Helper()
	m, s, k, actor, n, _ := reusableManagerFixture(t)
	g := s.members[m.binding.DeviceID].r.Grant
	g.Version = msi.ScheduledGrantVersion
	g.ScheduledEnabled = true
	g.ScheduledAcknowledged = true
	r, e := msi.NewRecord(g, m.key.Public().(ed25519.PublicKey), k.Public().(ed25519.PublicKey), *n)
	if e != nil {
		t.Fatal(e)
	}
	s.members[m.binding.DeviceID].r = r
	if e = m.ConfigureSchedulePolicy(context.Background(), func(a string) bool { return a == actor }); e != nil {
		t.Fatal(e)
	}
	art := reusableManagerUpload(t, m, actor, 'S')
	ctx := context.Background()
	transfer := "transfer_77777777777777777777777777777777"
	if e = m.DeliverArtifact(ctx, actor, transfer, true, art, msi.BindingDigest(m.binding)); e != nil {
		t.Fatal(e)
	}
	delivered, e := m.Poll(ctx)
	if e != nil {
		t.Fatal(e)
	}
	reusableManagerReport(t, m, k, delivered.Permit, "delivery", *n)
	if e = m.Review(ctx, actor, true, true, true, true); e != nil {
		t.Fatal(e)
	}
	baseline, e := m.Poll(ctx)
	if e != nil {
		t.Fatal(e)
	}
	report := reusableManagerReport(t, m, k, baseline.Permit, "readiness", *n)
	q := msi.ScheduleRequest{ArtifactID: art, BindingDigest: msi.BindingDigest(m.binding), TransferID: transfer, JobSequence: 1, ReadinessDigest: msi.Digest(report), StartAt: *n + 60, EndAt: *n + 180, PackageReviewAccepted: true, TermsAccepted: true, ServiceRiskAccepted: true, SynchronousActionsAccepted: true, ScheduleAccepted: true}
	return m, s, k, actor, n, q, delivered.Permit
}
func TestScheduledMSIExactWindowRestartAndSavedOutcome(t *testing.T) {
	m, s, k, actor, n, q, delivery := scheduledManagerFixture(t)
	ctx := context.Background()
	wrong := q
	wrong.ArtifactRetiredCount++
	if e := m.Schedule(ctx, actor, wrong); !errors.Is(e, msi.ErrConflict) {
		t.Fatal("occurrence substitution", e)
	}
	if e := m.Schedule(ctx, actor, q); e != nil {
		t.Fatal(e)
	}
	saved := s.members[m.binding.DeviceID].r
	digest := saved.Schedule.Approval.Digest
	v, e := m.View(ctx)
	if e != nil || v.Schedule == nil || v.Schedule.Digest != digest || v.Schedule.RequestDigest != msi.ScheduleRequestDigest(q) || v.CanReview {
		t.Fatal("lost POST GET reconciliation", v, e)
	}
	if e = m.Schedule(ctx, actor, q); !errors.Is(e, msi.ErrConsumed) {
		t.Fatal("schedule replay", e)
	}
	if p, e := m.Poll(ctx); e != nil || len(p.Permit) != 0 {
		t.Fatal("before window", e)
	}
	// Reopen from signed, encoded evidence. No live browser session survives.
	restarted, e := open(ctx, s, m.binding, bytes.Clone(m.key), m.spool, m.now, m.configurationCheck, m.artifact)
	if e != nil {
		t.Fatal(e)
	}
	if e = restarted.ConfigureOperatorPolicy(m.deliveryAllowed, m.installAllowed); e != nil {
		t.Fatal(e)
	}
	if e = restarted.ConfigureSchedulePolicy(ctx, m.schedulePolicy); e != nil {
		t.Fatal(e)
	}
	m = restarted
	*n = q.StartAt
	ready, e := m.Poll(ctx)
	if e != nil || len(ready.Permit) == 0 {
		t.Fatal("one fresh readiness", e)
	}
	rp, e := msi.VerifyPermit(ready.Permit, s.members[m.binding.DeviceID].r.PublicKey)
	if e != nil || rp.Sequence != 2 || rp.ScheduleDigest != digest || rp.MaintenanceUntil != q.EndAt || len(ready.Permit) > 8192 {
		t.Fatal("bounded signed readiness", rp, e)
	}
	if again, e := m.Poll(ctx); e != nil || len(again.Permit) != 0 {
		t.Fatal("readiness replay", e)
	}
	reusableManagerReport(t, m, k, ready.Permit, "readiness", *n)
	if p, e := m.Poll(ctx); e != nil || len(p.Permit) != 0 {
		t.Fatal("missing shared status issued", e)
	}
	reusableManagerReport(t, m, k, delivery, "mutation", *n)
	install, e := m.Poll(ctx)
	if e != nil || len(install.Permit) == 0 {
		t.Fatal("installation issuance", e)
	}
	if e = m.CheckRelease(ctx, install.Permit, ""); e != nil {
		t.Fatal(e)
	}
	if e = m.CancelSchedule(ctx, actor, digest); !errors.Is(e, msi.ErrConsumed) {
		t.Fatal("cancel claimed work", e)
	}
	if again, e := m.Poll(ctx); e != nil || len(again.Permit) != 0 {
		t.Fatal("native replay", e)
	}
	reusableManagerReport(t, m, k, install.Permit, "result", *n)
	v, e = m.View(ctx)
	if e != nil || v.State != "complete" || v.Result == nil || v.Result.Outcome != "succeeded" || v.Schedule.Digest != digest || v.Schedule.PermitIssuedAt != q.StartAt {
		t.Fatal("saved exact outcome", v, e)
	}
	if len(s.members[m.binding.DeviceID].r.RetirePermit) != 0 || s.artifact.Retired {
		t.Fatal("scheduling performed cleanup")
	}
}
func TestScheduledMSICancelSerializesWithIssuance(t *testing.T) {
	for _, race := range []bool{false, true} {
		t.Run(map[bool]string{false: "before_window", true: "with_issuance"}[race], func(t *testing.T) {
			m, s, k, actor, n, q, delivery := scheduledManagerFixture(t)
			ctx := context.Background()
			if e := m.Schedule(ctx, actor, q); e != nil {
				t.Fatal(e)
			}
			digest := s.members[m.binding.DeviceID].r.Schedule.Approval.Digest
			if !race {
				if e := m.CancelSchedule(ctx, actor, digest); e != nil {
					t.Fatal(e)
				}
				*n = q.StartAt
				if p, e := m.Poll(ctx); e != nil || len(p.Permit) != 0 {
					t.Fatal(e)
				}
				return
			}
			*n = q.StartAt
			p, e := m.Poll(ctx)
			if e != nil {
				t.Fatal(e)
			}
			reusableManagerReport(t, m, k, p.Permit, "readiness", *n)
			reusableManagerReport(t, m, k, delivery, "mutation", *n)
			start := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(2)
			var cancelErr, pollErr error
			var out msi.PollResponse
			go func() { defer wg.Done(); <-start; cancelErr = m.CancelSchedule(ctx, actor, digest) }()
			go func() { defer wg.Done(); <-start; out, pollErr = m.Poll(ctx) }()
			close(start)
			wg.Wait()
			if pollErr != nil {
				t.Fatal(pollErr)
			}
			r := s.members[m.binding.DeviceID].r
			if cancelErr == nil {
				if r.Schedule.State != "canceled" || len(out.Permit) != 0 || len(r.InstallPermit) != 0 {
					t.Fatal("cancel lost serialization")
				}
			} else if !errors.Is(cancelErr, msi.ErrConsumed) || len(out.Permit) == 0 || r.Schedule.State != "permit_issued" {
				t.Fatal("issuance/cancel result", cancelErr, r.Schedule.State)
			}
		})
	}
}
func TestScheduledMSIRevocationFactsWindowAndBusyFence(t *testing.T) {
	for _, change := range []string{"actor", "leaf", "expiry", "facts", "busy", "stale_shared", "before_window_shared"} {
		t.Run(change, func(t *testing.T) {
			m, s, k, actor, n, q, delivery := scheduledManagerFixture(t)
			ctx := context.Background()
			if e := m.Schedule(ctx, actor, q); e != nil {
				t.Fatal(e)
			}
			*n = q.StartAt
			p, e := m.Poll(ctx)
			if e != nil {
				t.Fatal(e)
			}
			rp, _ := msi.VerifyPermit(p.Permit, s.members[m.binding.DeviceID].r.PublicKey)
			if change == "facts" {
				r := msi.Report{Version: rp.Version, JobSequence: rp.JobSequence, Kind: "readiness", Binding: rp.Binding, TransferID: rp.TransferID, PermitDigest: msi.Digest(p.Permit), Package: rp.Package, NativeAcceptanceDigest: rp.NativeAcceptanceDigest, CapturedAt: *n, Offset: rp.Package.Size, State: "already_registered", Readiness: &msi.Readiness{Selection: rp.Package, CapturedAt: *n, PackageVerified: msi.Yes, MachineAbsent: msi.No, InstallerBusy: msi.No, NativeAcceptance: msi.Yes, PackageReviewAccepted: msi.Yes, MaintenanceWindowEnd: q.EndAt}}
				raw, _ := msi.SignReport(r, k)
				if e = m.Report(ctx, raw); e != nil {
					t.Fatal(e)
				}
			} else {
				reusableManagerReport(t, m, k, p.Permit, "readiness", *n)
			}
			dp, _ := msi.VerifyPermit(delivery, s.members[m.binding.DeviceID].r.PublicKey)
			at := *n
			status := fence.Status{Active: true, Phase: "idle", Revision: 10}
			if change == "busy" {
				status = fence.Status{Active: true, Blocked: true, Domain: fence.CachedWUA, JobID: "update_88888888888888888888888888888888", Phase: "dispatch_intent", Revision: 10, Retained: 1, Recovery: "intervention_required"}
			}
			if change == "stale_shared" {
				at -= 60
			}
			if change == "before_window_shared" {
				at--
			}
			shared := msi.Report{Version: dp.Version, JobSequence: dp.JobSequence, Kind: "mutation", Binding: dp.Binding, TransferID: dp.TransferID, PermitDigest: msi.Digest(delivery), Package: dp.Package, NativeAcceptanceDigest: dp.NativeAcceptanceDigest, CapturedAt: at, Offset: dp.Package.Size, State: status.Phase, Mutation: &status}
			raw, _ := msi.SignReport(shared, k)
			if e = m.Report(ctx, raw); e != nil {
				t.Fatal("shared", e)
			}
			if change == "actor" {
				m.schedulePolicy = func(string) bool { return false }
			}
			if change == "leaf" {
				s.members[m.binding.DeviceID].current.LeafDigest = msi.Digest([]byte("renewed"))
			}
			if change == "expiry" {
				*n = rp.ExpiresAt
			}
			if out, e := m.Poll(ctx); e != nil || len(out.Permit) != 0 {
				t.Fatal("unauthorized dispatch", e)
			}
			r := s.members[m.binding.DeviceID].r
			if change == "actor" {
				m.schedulePolicy = func(string) bool { return true }
				if out, e := m.Poll(ctx); e != nil || len(out.Permit) != 0 || r.Schedule.State != "blocked" {
					t.Fatal("revival", e)
				}
			}
			if len(r.InstallPermit) != 0 {
				t.Fatal("blocked conditions consumed install")
			}
			if change == "busy" || change == "stale_shared" || change == "before_window_shared" {
				*n = rp.ExpiresAt
				if out, e := m.Poll(ctx); e != nil || len(out.Permit) != 0 || s.members[m.binding.DeviceID].r.Schedule.State != "expired" {
					t.Fatal("readiness regenerated", e)
				}
			}
		})
	}
}
func TestScheduledMSIFinalReleaseRechecksActorAndClock(t *testing.T) {
	for _, change := range []string{"actor", "expiry", "leaf"} {
		t.Run(change, func(t *testing.T) {
			m, s, k, actor, n, q, delivery := scheduledManagerFixture(t)
			ctx := context.Background()
			if e := m.Schedule(ctx, actor, q); e != nil {
				t.Fatal(e)
			}
			*n = q.StartAt
			ready, e := m.Poll(ctx)
			if e != nil {
				t.Fatal(e)
			}
			reusableManagerReport(t, m, k, ready.Permit, "readiness", *n)
			reusableManagerReport(t, m, k, delivery, "mutation", *n)
			out, e := m.Poll(ctx)
			if e != nil {
				t.Fatal(e)
			}
			if change == "actor" {
				m.schedulePolicy = func(string) bool { return false }
			}
			if change == "expiry" {
				p, _ := msi.VerifyPermit(out.Permit, s.members[m.binding.DeviceID].r.PublicKey)
				*n = p.ExpiresAt
			}
			if change == "leaf" {
				s.members[m.binding.DeviceID].current.LeafDigest = msi.Digest([]byte("renewed"))
			}
			if e = m.CheckRelease(ctx, out.Permit, ""); e == nil {
				t.Fatal("released after change")
			}
		})
	}
}

func TestScheduledMSIFinalReleaseAfterCommitAndCleanupAuthority(t *testing.T) {
	for _, change := range []string{"postcommit_actor", "postcommit_shared_age", "cleanup_new_actor", "blocked_late_result_cleanup"} {
		t.Run(change, func(t *testing.T) {
			m, s, k, actor, n, q, delivery := scheduledManagerFixture(t)
			ctx := context.Background()
			if e := m.Schedule(ctx, actor, q); e != nil {
				t.Fatal(e)
			}
			*n = q.StartAt
			if change == "postcommit_shared_age" {
				*n += 2
			}
			ready, e := m.Poll(ctx)
			if e != nil {
				t.Fatal(e)
			}
			reusableManagerReport(t, m, k, ready.Permit, "readiness", *n)
			reusableManagerReport(t, m, k, delivery, "mutation", *n)
			// A later shared capture creates a distinct freshness deadline from readiness.
			*n += 2
			install, e := m.Poll(ctx)
			if e != nil || len(install.Permit) == 0 {
				t.Fatal(e)
			}
			member := s.members[m.binding.DeviceID]
			switch change {
			case "postcommit_actor":
				member.afterCommit = func() { m.schedulePolicy = func(string) bool { return false }; member.afterCommit = nil }
				if e = m.CheckRelease(ctx, install.Permit, ""); !errors.Is(e, msi.ErrAuthority) {
					t.Fatal("released revoked scheduling after commit", e)
				}
				m.schedulePolicy = func(string) bool { return true }
				if member.r.Schedule.State != "blocked" {
					t.Fatal("late revocation not durable")
				}
			case "postcommit_shared_age":
				// Set the saved shared report one second before fresh readiness, still in
				// window. Its age then expires before the short readiness-bound permit.
				raw := member.r.MutationReport
				report, _ := msi.VerifyReport(raw, member.r.ExecutorPublicKey)
				report.CapturedAt = q.StartAt
				member.r.MutationReport, _ = msi.SignReport(report, k)
				member.afterCommit = func() { *n = q.StartAt + 60; member.afterCommit = nil }
				if e = m.CheckRelease(ctx, install.Permit, ""); e == nil {
					t.Fatal("released after final freshness expiry")
				}
			default:
				if change == "blocked_late_result_cleanup" {
					m.schedulePolicy = func(string) bool { return false }
					if e = m.CheckRelease(ctx, install.Permit, ""); e == nil {
						t.Fatal("revoked release")
					}
				}
				reusableManagerReport(t, m, k, install.Permit, "result", *n)
				m.schedulePolicy = func(string) bool { return false }
				other := "operator_88888888888888888888888888888888"
				m.installAllowed = func(a string) bool { return a == other }
				v, e := m.View(ctx)
				if e != nil || v.Result == nil {
					t.Fatal("old scheduler stranded result", e)
				}
				if e = m.Retire(ctx, other, v.ResultDigest, true); e != nil {
					t.Fatal("old scheduler stranded explicit cleanup", e)
				}
				cleanup, e := m.Poll(ctx)
				if e != nil || len(cleanup.Permit) == 0 {
					t.Fatal("terminal schedule suppressed cleanup", e)
				}
				p, e := msi.VerifyPermit(cleanup.Permit, member.r.PublicKey)
				if e != nil || p.Kind != "retire" || p.ActorID != other || p.ScheduleDigest != "" {
					t.Fatal("cleanup inherited schedule authority", e)
				}
				if e = m.CheckRelease(ctx, cleanup.Permit, ""); e != nil {
					t.Fatal("cleanup final release", e)
				}
			}
		})
	}
}
