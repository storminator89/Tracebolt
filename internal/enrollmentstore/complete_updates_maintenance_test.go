package enrollmentstore

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"localrmm/internal/enrollmentstate"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/inventorywire"
)

func TestCompleteUpdatesMaintenanceDomainIsOptIn(t *testing.T) {
	_, s, _, snap, _ := completeFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	for slot := uint64(0); slot < 6; slot++ {
		result, e := s.MaintainInventoryStep(ctx, slot, at)
		if e != nil || result.DeviceID != snap.Approval.DeviceID || result.Section != []string{"packages", "processes", "volumes"}[slot%3] {
			t.Fatal("old schema cadence changed", slot, result, e)
		}
	}
	if e := s.InitializeCompleteUpdates(ctx); e != nil {
		t.Fatal(e)
	}
	for slot := uint64(0); slot < 8; slot++ {
		result, e := s.MaintainInventoryStep(ctx, slot, at)
		if e != nil || result.DeviceID != snap.Approval.DeviceID || result.Section != []string{"packages", "processes", "volumes", "cached_updates"}[slot%4] || result.RowsDeleted != 0 || result.ChunksDeleted != 0 {
			t.Fatal("optional domain fairness", slot, result, e)
		}
	}
}

func TestCompleteUpdatesMaintenanceBoundedRetirementRestartAndFloor(t *testing.T) {
	f, s, path, snap, cert := completeUpdatesFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	old, m, c := updatesGenerationFixture(t, snap.Approval.DeviceID, 1, 2300, at)
	promoteCompleteUpdates(t, s, snap, cert, old, m, c, at)
	cursor, e := s.CompleteUpdatesPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 10}, at)
	if e != nil {
		t.Fatal(e)
	}
	next, nm, nc := updatesGenerationFixture(t, snap.Approval.DeviceID, 2, 1, at.Add(time.Second))
	promoteCompleteUpdates(t, s, snap, cert, next, nm, nc, at.Add(time.Second))
	before := at.Add(14 * time.Minute)
	result, e := s.MaintainInventoryStep(ctx, 3, before)
	if e != nil || result.RowsDeleted != 0 || result.ChunksDeleted != 0 || result.GenerationRemoved {
		t.Fatal("live cursor generation reclaimed", result, e)
	}
	if p, e := s.CompleteUpdatesPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 10, Cursor: cursor.NextCursor}, before); e != nil || p.Binding != old {
		t.Fatal("maintenance broke retained cursor", e)
	}
	now := at.Add(inventoryledger.CursorTTL + time.Second)
	totalRows, totalChunks, removed := 0, 0, false
	for step := 0; step < 10; step++ {
		result, e = s.MaintainInventoryStep(ctx, 3, now)
		if e != nil || result.Section != "cached_updates" || result.RowsDeleted > inventoryledger.MaxCleanupRows || result.ChunksDeleted > inventoryledger.MaxCleanupChunks {
			t.Fatal("unbounded cleanup", result, e)
		}
		totalRows += result.RowsDeleted
		totalChunks += result.ChunksDeleted
		if step == 0 {
			if result.RowsDeleted != 256 || result.ChunksDeleted != 16 || result.GenerationRemoved {
				t.Fatal("first cleanup not fixed bounded batch", result)
			}
			var reserved int
			if e = s.db.QueryRow(`SELECT sum(declared_rows) FROM enrollment_complete_updates_generations`).Scan(&reserved); e != nil || reserved != 2301 {
				t.Fatal("partial cleanup released declared reservation", reserved, e)
			}
			s.Close()
			s = f.open(t, path)
		}
		if result.GenerationRemoved {
			removed = true
			break
		}
	}
	if !removed || totalRows != 2300 || totalChunks != len(c) {
		t.Fatal("cleanup lost exact accounting", removed, totalRows, totalChunks)
	}
	var remaining int
	if e = s.db.QueryRow(`SELECT count(*) FROM enrollment_complete_updates_generations`).Scan(&remaining); e != nil || remaining != 1 {
		t.Fatal("current generation reclaimed", remaining, e)
	}
	v, e := s.CompleteUpdatesView(ctx, snap.Approval.DeviceID, now)
	if e != nil || v.CompleteBinding != next || v.Sequence != 2 || !reflect.DeepEqual(v.Complete.Manifest, nm) {
		t.Fatal("cleanup changed current metadata", e)
	}
	if _, e = s.CompleteUpdatesBegin(ctx, snap.InvitationID, cert.CertificateHash(), old, m, now); !errors.Is(e, inventoryledger.ErrConflict) {
		t.Fatal("cleanup reset authority floor", e)
	}
	p, e := s.CompleteUpdatesPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 10}, now)
	if e != nil || p.Binding != next || p.TotalRows != 1 {
		t.Fatal("cleanup stranded current page", e)
	}
}

func TestCompleteUpdatesMaintenanceExpiredCurrentKeepsMetadataAndFloor(t *testing.T) {
	f, s, path, snap, cert := completeUpdatesFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	old, m, c := updatesGenerationFixture(t, snap.Approval.DeviceID, 1, 513, at.Add(-time.Hour))
	promoteCompleteUpdates(t, s, snap, cert, old, m, c, at)
	expired := m.CollectedAt.Add(inventoryledger.ObservationTTL)
	if result, e := s.MaintainInventoryStep(ctx, 3, expired.Add(-time.Nanosecond)); e != nil || result.RowsDeleted != 0 {
		t.Fatal("capture age shortened", result, e)
	}
	for i := 0; i < 3; i++ {
		result, e := s.MaintainInventoryStep(ctx, 3, expired)
		if e != nil || result.RowsDeleted > 256 || result.ChunksDeleted > 16 || result.GenerationRemoved != (i == 2) {
			t.Fatal("expired current reclaim", i, result, e)
		}
		s.Close()
		s = f.open(t, path)
		view, e := s.CompleteUpdatesView(ctx, snap.Approval.DeviceID, expired)
		if e != nil || view.Complete == nil || view.Complete.State != "expired" || view.CompleteBinding != old || !reflect.DeepEqual(view.Complete.Manifest, m) || !view.Complete.ExpiresAt.Equal(expired) {
			t.Fatalf("cleanup/restart lost original current metadata: %+v %v", view, e)
		}
	}
	var rows int
	if e := s.db.QueryRow(`SELECT count(*) FROM enrollment_complete_updates_rows`).Scan(&rows); e != nil || rows != 0 {
		t.Fatal("expired rows retained", rows, e)
	}
	if _, e := s.CompleteUpdatesBegin(ctx, snap.InvitationID, cert.CertificateHash(), old, m, expired); e == nil {
		t.Fatal("expired authority floor reused")
	}
	next, nm, nc := updatesGenerationFixture(t, snap.Approval.DeviceID, 2, 0, expired.Add(time.Second))
	promoteCompleteUpdates(t, s, snap, cert, next, nm, nc, expired.Add(time.Second))
	p, e := s.CompleteUpdatesPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 10}, expired.Add(time.Second))
	if e != nil || p.Binding != next || p.TotalRows != 0 || !p.Exhausted {
		t.Fatal("expired cleanup blocked fresh capture", e)
	}
}

func TestCompleteUpdatesMaintenanceExpiredStagingAndAbortedFloor(t *testing.T) {
	f, s, path, snap, cert := completeUpdatesFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	b, m, c := updatesGenerationFixture(t, snap.Approval.DeviceID, 1, 700, at)
	stageCompleteUpdates(t, s, snap, cert, b, m, c[:3], at)
	expired := at.Add(inventoryledger.StagingTTL)
	for i := 0; i < 2; i++ {
		r, e := s.MaintainInventoryStep(ctx, 3, expired)
		if e != nil || r.RowsDeleted > 256 || r.ChunksDeleted > 16 {
			t.Fatal("staging cleanup", e)
		}
	}
	s.Close()
	s = f.open(t, path)
	view, e := s.CompleteUpdatesView(ctx, snap.Approval.DeviceID, expired)
	if e != nil || view.Transfer == nil || view.Transfer.State != "expired" || view.Complete != nil || view.Sequence != 1 {
		t.Fatalf("staging expiry erased metadata: %+v %v", view, e)
	}
	if _, e = s.CompleteUpdatesBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, expired); e == nil {
		t.Fatal("expired staging replay accepted")
	}
	next, nm, nc := updatesGenerationFixture(t, snap.Approval.DeviceID, 2, 300, expired)
	stageCompleteUpdates(t, s, snap, cert, next, nm, nc[:1], expired)
	if e = s.CompleteUpdatesAbort(ctx, snap.InvitationID, cert.CertificateHash(), next, expired); e != nil {
		t.Fatal(e)
	}
	r, e := s.MaintainInventoryStep(ctx, 3, expired)
	if e != nil || !r.GenerationRemoved || r.RowsDeleted != len(nc[0].Items) {
		t.Fatal("aborted reservation stranded", r, e)
	}
	s.Close()
	s = f.open(t, path)
	if _, e = s.CompleteUpdatesBegin(ctx, snap.InvitationID, cert.CertificateHash(), next, nm, expired); !errors.Is(e, inventoryledger.ErrConflict) {
		t.Fatal("aborted cleanup reset floor", e)
	}
	generation, _ := inventorywire.CachedUpdatesGenerationID(snap.Approval.DeviceID, 3)
	failure := InventoryFailureReport{Sequence: 3, GenerationID: generation, AttemptedAt: expired, Reason: "source_missing"}
	if _, e = s.CompleteUpdatesFailure(ctx, snap.InvitationID, cert.CertificateHash(), failure, expired); e != nil {
		t.Fatal("cleanup prevented next failure receipt", e)
	}
}

func TestCompleteUpdatesMaintenanceAfterRevocationNeverGrantsRead(t *testing.T) {
	_, s, _, snap, cert := completeUpdatesFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	b, m, c := updatesGenerationFixture(t, snap.Approval.DeviceID, 1, 513, at)
	promoteCompleteUpdates(t, s, snap, cert, b, m, c, at)
	next, nm, nc := updatesGenerationFixture(t, snap.Approval.DeviceID, 2, 1, at.Add(time.Second))
	promoteCompleteUpdates(t, s, snap, cert, next, nm, nc, at.Add(time.Second))
	revoke := control(snap, 88)
	revoke.Now = at.Add(2 * time.Second).Unix()
	if _, e := s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: revoke, State: enrollmentstate.Revoked}); e != nil {
		t.Fatal(e)
	}
	if r, e := s.MaintainInventoryStep(ctx, 3, at.Add(3*time.Second)); e != nil || r.RowsDeleted != 0 {
		t.Fatal("revocation shortened retention", r, e)
	}
	now := at.Add(16 * time.Minute)
	for i := 0; i < 3; i++ {
		if r, e := s.MaintainInventoryStep(ctx, 3, now); e != nil || r.RowsDeleted > 256 {
			t.Fatal("revocation stranded retired generation", r, e)
		}
	}
	if _, e := s.CompleteUpdatesView(ctx, snap.Approval.DeviceID, now); !errors.Is(e, enrollmentstate.ErrState) {
		t.Fatal("cleanup relaxed read authority", e)
	}
	if _, e := s.CompleteUpdatesPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 10}, now); !errors.Is(e, enrollmentstate.ErrState) {
		t.Fatal("cleanup exposed revoked rows", e)
	}
}
