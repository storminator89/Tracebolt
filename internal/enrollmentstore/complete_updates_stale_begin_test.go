package enrollmentstore

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"localrmm/internal/enrollmentstate"
	"localrmm/internal/inventoryledger"
)

func TestCompleteUpdatesNeverAdmittedStaleBeginCanRetireAfterRestart(t *testing.T) {
	for _, retainComplete := range []bool{false, true} {
		name := "fresh_authority"
		if retainComplete {
			name = "preserved_complete"
		}
		t.Run(name, func(t *testing.T) {
			f, s, path, snap, cert := completeUpdatesFixture(t)
			ctx := context.Background()
			admitted := time.Unix(testNow+10, 0).UTC()
			seq := uint64(1)
			var previous InventoryBinding
			if retainComplete {
				b, m, c := updatesGenerationFixture(t, snap.Approval.DeviceID, 1, 20, admitted)
				promoteCompleteUpdates(t, s, snap, cert, b, m, c, admitted)
				previous = b
				seq++
			}
			captured := admitted.Add(-inventoryledger.ObservationTTL - time.Hour)
			b, m, chunks := updatesGenerationFixture(t, snap.Approval.DeviceID, seq, 700, captured)
			// No unauthenticated attempt may consume this durable sequence.
			if _, e := s.CompleteUpdatesBegin(ctx, snap.InvitationID, strings.Repeat("f", 64), b, m, admitted); !errors.Is(e, enrollmentstate.ErrProof) {
				t.Fatal("stale admission skipped leaf proof", e)
			}
			before, e := s.CompleteUpdatesView(ctx, snap.Approval.DeviceID, admitted)
			if e != nil || before.Sequence != seq-1 {
				t.Fatal("unauthorized stale begin advanced floor", e)
			}
			receipt, e := s.CompleteUpdatesBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, admitted)
			if !errors.Is(e, inventoryledger.ErrConflict) || receipt != (inventoryledger.BeginReceipt{}) {
				t.Fatal("stale begin was not durably rejected", e)
			}
			for _, table := range []string{"enrollment_complete_updates_generations", "enrollment_complete_updates_rows", "enrollment_complete_updates_chunks"} {
				var n int
				if e = s.db.QueryRow(`SELECT count(*) FROM `+table+` WHERE generation=?`, b.GenerationID).Scan(&n); e != nil || n != 0 {
					t.Fatal("stale begin reserved payload", table, n, e)
				}
			}
			if e = s.Close(); e != nil {
				t.Fatal(e)
			}
			s = f.open(t, path)
			status, e := s.CompleteUpdatesStatus(ctx, snap.InvitationID, cert.CertificateHash(), b, admitted.Add(time.Second))
			if e != nil || status.Sequence != seq || status.Transfer == nil || status.Transfer.State != "failed" || !reflect.DeepEqual(status.Transfer.Manifest, m) || !status.Transfer.StartedAt.Equal(admitted) || !status.Transfer.ExpiresAt.Equal(admitted.Add(inventoryledger.StagingTTL)) || status.Transfer.AcceptedChunks != 0 || status.Transfer.AcceptedRows != 0 || !status.Transfer.CompletedAt.IsZero() {
				t.Fatal("restart lost truthful terminal admission", e)
			}
			if status.CompleteBinding != previous || retainComplete != (status.Complete != nil) {
				t.Fatal("stale rejection replaced prior complete")
			}
			if _, e = s.CompleteUpdatesBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, admitted.Add(2*time.Second)); !errors.Is(e, inventoryledger.ErrConflict) {
				t.Fatal("rejected begin replay admitted", e)
			}
			retry, e := s.CompleteUpdatesStatus(ctx, snap.InvitationID, cert.CertificateHash(), b, admitted.Add(2*time.Second))
			if e != nil || !reflect.DeepEqual(status.Transfer, retry.Transfer) {
				t.Fatal("retry refreshed terminal receipt facts", e)
			}
			if _, e = s.CompleteUpdatesAppend(ctx, snap.InvitationID, cert.CertificateHash(), b, chunks[0], admitted.Add(2*time.Second)); !errors.Is(e, inventoryledger.ErrConflict) {
				t.Fatal("tombstone accepted rows", e)
			}
			if _, e = s.CompleteUpdatesFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, admitted.Add(2*time.Second)); !errors.Is(e, inventoryledger.ErrConflict) {
				t.Fatal("tombstone fabricated completion", e)
			}
			if e = s.CompleteUpdatesAbort(ctx, snap.InvitationID, cert.CertificateHash(), b, admitted.Add(3*time.Second)); e != nil {
				t.Fatal("terminal rejection cannot ack abort", e)
			}
			if e = s.CompleteUpdatesAbort(ctx, snap.InvitationID, cert.CertificateHash(), b, admitted.Add(4*time.Second)); e != nil {
				t.Fatal("abort ack replay failed", e)
			}
			next, nm, nc := updatesGenerationFixture(t, snap.Approval.DeviceID, seq+1, 20, admitted.Add(5*time.Second))
			promoteCompleteUpdates(t, s, snap, cert, next, nm, nc, admitted.Add(5*time.Second))
			page, e := s.CompleteUpdatesPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 100}, admitted.Add(5*time.Second))
			if e != nil || page.Binding != next || len(page.Items) != 20 {
				t.Fatal("stale work retirement blocked next sequence", e)
			}
			if _, e = s.CompleteUpdatesBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, admitted.Add(5*time.Second)); !errors.Is(e, inventoryledger.ErrConflict) {
				t.Fatal("old floor became reusable", e)
			}
		})
	}
}

func TestCompleteUpdatesStaleBeginDoesNotBypassLifecycleOrAllowStalePending(t *testing.T) {
	_, s, _, snap, cert := completeUpdatesFixture(t)
	ctx := context.Background()
	now := time.Unix(testNow+10, 0).UTC()
	b, m, _ := updatesGenerationFixture(t, snap.Approval.DeviceID, 1, 20, now.Add(-25*time.Hour))
	candidate := completeUpdatesRecord{Binding: b, Manifest: &m, State: "pending", StartedAt: now, LastAt: now}
	if validCompleteUpdatesRecord(snap, candidate) {
		t.Fatal("stale pending record accepted")
	}
	candidate.State = "aborted"
	if !validCompleteUpdatesRecord(snap, candidate) {
		t.Fatal("terminal stale record rejected")
	}
	c := control(snap, 91)
	c.Now = now.Unix()
	if _, e := s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: c, State: enrollmentstate.Revoked}); e != nil {
		t.Fatal(e)
	}
	if _, e := s.CompleteUpdatesBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, now); !errors.Is(e, enrollmentstate.ErrState) {
		t.Fatal("revoked stale begin advanced floor", e)
	}
	var n int
	if e := s.db.QueryRow(`SELECT count(*) FROM enrollment_complete_updates_authority`).Scan(&n); e != nil || n != 0 {
		t.Fatal("revoked stale begin persisted metadata", n, e)
	}
}
