package windowsmanagedmsimanager

import (
	"context"
	"errors"
	msi "localrmm/internal/windowsmanagedmsi"
	fence "localrmm/internal/windowsmutationfence"
	"testing"
)

func TestCoordinatedApprovalRequiresFreshIdleStatusWithoutConsuming(t *testing.T) {
	for _, state := range []string{"missing", "blocked", "unknown", "stale", "idle"} {
		t.Run(state, func(t *testing.T) {
			m, s, key, actor, n := managerFixture(t)
			s.r.Grant.Version = msi.CoordinatedGrantVersion
			s.r.Grant.MutationPlanDigest = msi.Digest([]byte("plan"))
			s.r.Grant.PeerBindingDigest = msi.Digest([]byte("peer"))
			ctx := context.Background()
			sel := managerSelection()
			if e := m.ReserveUpload(ctx, actor, sel, msi.Digest([]byte("native"))); e != nil {
				t.Fatal(e)
			}
			s.r.Artifact.Offset = sel.Size
			s.r.Artifact.PrefixDigest = sel.SHA256
			s.r.Artifact.LastChunkDigest = msi.Digest([]byte("chunk"))
			s.r.Artifact.CompletedAt = *n
			if e := m.Deliver(ctx, actor, "transfer_77777777777777777777777777777777", true); e != nil {
				t.Fatal(e)
			}
			delivery, e := m.Poll(ctx)
			if e != nil {
				t.Fatal(e)
			}
			dp, _ := msi.VerifyPermit(delivery.Permit, s.r.PublicKey)
			report := msi.Report{Version: msi.Version, Kind: "delivery", Binding: dp.Binding, TransferID: dp.TransferID, PermitDigest: msi.Digest(delivery.Permit), Package: sel, NativeAcceptanceDigest: dp.NativeAcceptanceDigest, CapturedAt: *n, Offset: sel.Size, State: "imported"}
			raw, _ := msi.SignReport(report, key)
			if e = m.Report(ctx, raw); e != nil {
				t.Fatal(e)
			}
			if e = m.Review(ctx, actor, true, true, true); !errors.Is(e, msi.ErrAuthority) {
				t.Fatal("missing synchronous attestation accepted", e)
			}
			if e = m.Review(ctx, actor, true, true, true, true); e != nil {
				t.Fatal(e)
			}
			readiness, e := m.Poll(ctx)
			if e != nil {
				t.Fatal(e)
			}
			rp, _ := msi.VerifyPermit(readiness.Permit, s.r.PublicKey)
			if rp.SynchronousReviewDigest != msi.SynchronousReviewDigest(sel, dp.NativeAcceptanceDigest) {
				t.Fatal("review did not bind exact bytes/native evidence")
			}
			changed := rp
			changed.NativeAcceptanceDigest = msi.Digest([]byte("changed native review"))
			if changed.Validate() == nil {
				t.Fatal("attestation reused for changed native evidence")
			}
			report.Kind = "readiness"
			report.State = "ready"
			report.PermitDigest = msi.Digest(readiness.Permit)
			report.Readiness = &msi.Readiness{Selection: sel, CapturedAt: *n, PackageVerified: msi.Yes, MachineAbsent: msi.Yes, InstallerBusy: msi.No, NativeAcceptance: msi.Yes, PackageReviewAccepted: msi.Yes, MaintenanceWindowEnd: rp.MaintenanceUntil}
			ready, _ := msi.SignReport(report, key)
			if e = m.Report(ctx, ready); e != nil {
				t.Fatal(e)
			}
			if state != "missing" {
				status := fence.Status{Active: true, Phase: "idle", Revision: 7, Retained: 1}
				if state == "blocked" {
					status.Blocked = true
					status.Domain = fence.CachedWUA
					status.JobID = "update_88888888888888888888888888888888"
					status.Phase = "dispatch_intent"
					status.Recovery = "intervention_required"
				}
				if state == "unknown" {
					status = fence.Status{Blocked: true, Phase: "unavailable", Recovery: "intervention_required"}
				}
				report.Kind = "mutation"
				report.State = status.Phase
				report.PermitDigest = msi.Digest(delivery.Permit)
				report.Readiness = nil
				report.Mutation = &status
				if state == "stale" {
					report.CapturedAt -= 60
				}
				shared, _ := msi.SignReport(report, key)
				if e = m.Report(ctx, shared); e != nil {
					t.Fatal(e)
				}
			}
			e = m.Approve(ctx, actor, msi.Digest(ready), true)
			if state == "idle" {
				if e != nil || len(s.r.InstallPermit) == 0 {
					t.Fatal(e)
				}
			} else if !errors.Is(e, msi.ErrUnavailable) || len(s.r.InstallPermit) != 0 {
				t.Fatal("unavailable fence consumed approval", e)
			}
		})
	}
}
