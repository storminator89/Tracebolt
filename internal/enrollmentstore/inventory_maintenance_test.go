package enrollmentstore

import (
	"context"
	"errors"
	"localrmm/internal/completeoverview"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/overviewgeneration"
	"localrmm/internal/overviewledger"
	"localrmm/internal/overviewwire"
	"testing"
	"time"
)

func TestCompleteOverviewSteadyMinuteCadenceRetainsPagesAndCleans(t *testing.T) {
	_, s, _, snap, cert := overviewFixture(t)
	ctx := context.Background()
	base := time.Unix(testNow+10, 0).UTC()
	// The same trusted loop must also reclaim retired package generations without
	// changing their original cadence, 15-minute cursor window or durable floor.
	old, pm, pc := completeGeneration(t, snap.Approval.DeviceID, 1, 513, base)
	promoteComplete(t, s, snap, cert, old, pm, pc, base)
	current, pm, pc := completeGeneration(t, snap.Approval.DeviceID, 2, 513, base.Add(time.Second))
	promoteComplete(t, s, snap, cert, current, pm, pc, base.Add(time.Second))
	var slot uint64
	removed := 0
	var last OverviewBinding
	var lastManifest overviewgeneration.Manifest
	var now time.Time
	for seq := uint64(1); seq <= 28; seq++ {
		now = base.Add(2*time.Second + time.Duration(seq-1)*time.Minute)
		b, m, c := overviewGeneration(t, snap.Approval.DeviceID, seq, 513, now)
		promoteOverview(t, s, snap, cert, b, m, c, now)
		last, lastManifest = b, m
		source := completeoverview.Empty(id("sample", 998), now, completeoverview.ReasonReadFailed)
		count := uint64(1)
		source.Volumes.Meta = completeoverview.SectionMeta{GenerationID: source.GenerationID, Coverage: completeoverview.Complete, Reason: completeoverview.ReasonNone, ObservedCount: &count, CountExact: true, FieldCoverage: completeoverview.FieldCoverage{Denied: 1}}
		source.Volumes.Items = []completeoverview.Volume{{ID: "mount_1", MountPoint: "/", Filesystem: "ext4", Kind: "local", FilesystemGroup: "fs_8_1", CapacityScope: "agent-mount-namespace", Measurement: completeoverview.Observation{Status: completeoverview.Denied, Reason: completeoverview.ReasonPermissionDenied}}}
		id, _ := overviewwire.GenerationID(snap.Approval.DeviceID, "volumes", seq)
		vm, vc, e := overviewgeneration.Build(ctx, source, "volumes", id, nil)
		if e != nil {
			t.Fatal(e)
		}
		hash, _ := overviewgeneration.ManifestDigest(vm)
		promoteOverview(t, s, snap, cert, OverviewBinding{"volumes", seq, id, hash}, vm, vc, now)
		// Emulate the exact one-step-per-second trusted manager cadence, with no sleeps
		// and no host sources. Each step is a separate real authority transaction.
		for second := 1; second < 60; second++ {
			result, e := s.MaintainInventoryStep(ctx, slot, now.Add(time.Duration(second)*time.Second))
			slot++
			if e != nil {
				t.Fatal(seq, second, e)
			}
			if result.RowsDeleted > 256 || result.ChunksDeleted > 16 {
				t.Fatal("maintenance batch exceeded bound")
			}
			if result.GenerationRemoved {
				removed++
			}
		}
		view, e := s.OverviewView(ctx, snap.Approval.DeviceID, now.Add(59*time.Second))
		if e != nil || view.Processes.CompleteBinding != b || view.Volumes.CompleteBinding.Sequence != seq {
			t.Fatal("cadence stalled or crossed sections", seq, e)
		}
		var generations int64
		if s.db.QueryRow(`SELECT generations FROM co_budget WHERE scope=?`, overviewDevice(snap.Approval.DeviceID, "processes")).Scan(&generations) != nil || generations > 18 {
			t.Fatal("retention allowance exceeded")
		}
	}
	if removed < 20 {
		t.Fatal("trusted loop did not reclaim old generations", removed)
	}
	var packageGenerations int64
	if s.db.QueryRow(`SELECT generations FROM fi_budget WHERE scope=?`, snap.Approval.DeviceID).Scan(&packageGenerations) != nil || packageGenerations != 1 {
		t.Fatal("package retired generation stranded", packageGenerations)
	}
	// Expired/retired reclaim never resets the floor, refreshes capture age, or
	// turns a new failed capture into zero; a later successful capture can continue.
	failureID, _ := overviewwire.GenerationID(snap.Approval.DeviceID, "processes", 29)
	failureAt := now.Add(time.Minute)
	if _, e := s.OverviewFailure(ctx, snap.InvitationID, cert.CertificateHash(), OverviewFailureReport{Section: "processes", Sequence: 29, GenerationID: failureID, AttemptedAt: failureAt, Reason: "timeout"}, failureAt); e != nil {
		t.Fatal(e)
	}
	view, e := s.OverviewView(ctx, snap.Approval.DeviceID, failureAt)
	if e != nil || view.Processes.CompleteBinding != last || !view.Processes.Complete.Manifest.CaptureStartedAt.Equal(lastManifest.CaptureStartedAt) || view.Processes.Failure == nil {
		t.Fatal("maintenance changed original completed age", e)
	}
	if _, e := s.OverviewBegin(ctx, snap.InvitationID, cert.CertificateHash(), last, lastManifest, failureAt); !errors.Is(e, overviewledger.ErrConflict) {
		t.Fatal("cleanup reset floor", e)
	}
}

func TestCompleteOverviewMaintenanceRequiresTrustedBindingAfterRevocation(t *testing.T) {
	_, s, _, snap, cert := overviewFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	b, m, c := overviewGeneration(t, snap.Approval.DeviceID, 1, 513, at)
	promoteOverview(t, s, snap, cert, b, m, c, at)
	next, m, c := overviewGeneration(t, snap.Approval.DeviceID, 2, 20, at.Add(time.Second))
	promoteOverview(t, s, snap, cert, next, m, c, at.Add(time.Second))
	ctrl := control(snap, 91)
	ctrl.Now = at.Add(2 * time.Second).Unix()
	if _, e := s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: ctrl, State: enrollmentstate.Revoked}); e != nil {
		t.Fatal(e)
	}
	if result, e := s.MaintainInventoryStep(ctx, 1, at.Add(3*time.Second)); e != nil || result.RowsDeleted != 0 {
		t.Fatal("revocation shortened cursor retention", e)
	}
	for n := 0; n < 3; n++ {
		result, e := s.MaintainInventoryStep(ctx, 1, at.Add(16*time.Minute))
		if e != nil || result.RowsDeleted > 256 {
			t.Fatal(e)
		}
	}
	var n int
	if s.db.QueryRow(`SELECT count(*) FROM co_generations WHERE device=?`, overviewDevice(snap.Approval.DeviceID, "processes")).Scan(&n) != nil || n != 1 {
		t.Fatal("trusted revoked reclaim failed", n)
	}
	if _, e := s.OverviewView(ctx, snap.Approval.DeviceID, at.Add(16*time.Minute)); !errors.Is(e, enrollmentstate.ErrState) {
		t.Fatal("maintenance relaxed read authority", e)
	}
}
