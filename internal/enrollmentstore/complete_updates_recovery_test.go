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
	"localrmm/internal/inventorywire"
)

func TestCompleteUpdatesLostFinalizeReceiptSurvivesRetentionAndCleanup(t *testing.T) {
	for _, cleanup := range []bool{false, true} {
		name := "retained_payload"
		if cleanup {
			name = "physical_cleanup_and_restart"
		}
		t.Run(name, func(t *testing.T) {
			f, s, path, snap, cert := completeUpdatesFixture(t)
			ctx := context.Background()
			admitted := time.Unix(testNow+10, 0).UTC()
			// Keep the current credential valid while the original capture reaches its
			// independent 24-hour retention. Admission never replaces that capture age.
			captured := admitted.Add(-inventoryledger.ObservationTTL + 5*time.Minute)
			b, m, chunks := updatesGenerationFixture(t, snap.Approval.DeviceID, 1, 700, captured)
			stageCompleteUpdates(t, s, snap, cert, b, m, chunks, admitted)
			original, e := s.CompleteUpdatesFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, admitted.Add(time.Second))
			if e != nil {
				t.Fatal(e)
			}
			expired := captured.Add(inventoryledger.ObservationTTL)
			if cleanup {
				for batch := 0; batch < 3; batch++ {
					result, e := s.MaintainInventoryStep(ctx, 3, expired)
					if e != nil || result.RowsDeleted > 256 || result.ChunksDeleted > 16 {
						t.Fatal("bounded cleanup", result, e)
					}
					status, e := s.CompleteUpdatesStatus(ctx, snap.InvitationID, cert.CertificateHash(), b, expired)
					if e != nil || status.Transfer == nil || status.Transfer.State != "expired" || status.Transfer.AcceptedChunks != m.ChunkCount || status.Transfer.AcceptedRows != uint64(m.CandidateCount) {
						t.Fatal("partial cleanup lost completed status facts", e)
					}
				}
				var n int
				for _, table := range []string{"enrollment_complete_updates_generations", "enrollment_complete_updates_rows", "enrollment_complete_updates_chunks"} {
					if e = s.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); e != nil || n != 0 {
						t.Fatal("physical generation survived cleanup", table, n, e)
					}
				}
				if e = s.Close(); e != nil {
					t.Fatal(e)
				}
				s = f.open(t, path)
			}
			status, e := s.CompleteUpdatesStatus(ctx, snap.InvitationID, cert.CertificateHash(), b, expired)
			if e != nil || status.Transfer == nil || status.Transfer.State != "expired" || !status.Transfer.CompletedAt.Equal(original.CompletedAt) || status.Transfer.AcceptedChunks != m.ChunkCount || status.Transfer.AcceptedRows != uint64(m.CandidateCount) || status.Complete == nil || !status.Complete.Manifest.CollectedAt.Equal(captured) {
				t.Fatal("lost receipt cannot be resolved from status", e)
			}
			got, e := s.CompleteUpdatesFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, expired)
			if e != nil || !reflect.DeepEqual(got, original) {
				t.Fatalf("finalize receipt not recovered unchanged: %+v %v", got, e)
			}
			page, e := s.CompleteUpdatesPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 100}, expired)
			if e == nil || len(page.Items) != 0 {
				t.Fatal("receipt retry exposed expired rows", e)
			}
			if _, e = s.CompleteUpdatesFinalize(ctx, snap.InvitationID, strings.Repeat("f", 64), b, expired); !errors.Is(e, enrollmentstate.ErrProof) {
				t.Fatal("receipt retry bypassed leaf authority", e)
			}
			if cleanup {
				var n int
				if e = s.db.QueryRow(`SELECT count(*) FROM enrollment_complete_updates_generations`).Scan(&n); e != nil || n != 0 {
					t.Fatal("receipt retry recreated payload generation", n, e)
				}
			}
			next, nm, nc := updatesGenerationFixture(t, snap.Approval.DeviceID, 2, 20, expired.Add(time.Second))
			promoteCompleteUpdates(t, s, snap, cert, next, nm, nc, expired.Add(time.Second))
			if _, e = s.CompleteUpdatesFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, expired.Add(time.Second)); !errors.Is(e, inventoryledger.ErrConflict) {
				t.Fatal("old acknowledgement bypassed current floor", e)
			}
			current, e := s.CompleteUpdatesPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 100}, expired.Add(time.Second))
			if e != nil || current.Binding != next || len(current.Items) != 20 {
				t.Fatal("recovered acknowledgement blocked next sequence", e)
			}
			control := control(snap, 91)
			control.Now = expired.Add(2 * time.Second).Unix()
			if _, e = s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: control, State: enrollmentstate.Revoked}); e != nil {
				t.Fatal(e)
			}
			if _, e = s.CompleteUpdatesFinalize(ctx, snap.InvitationID, cert.CertificateHash(), next, expired.Add(2*time.Second)); !errors.Is(e, enrollmentstate.ErrState) {
				t.Fatal("receipt retry bypassed revocation", e)
			}
		})
	}
}

func TestCompleteUpdatesUnsupportedFailureRetainsReceiptAcrossRestart(t *testing.T) {
	f, s, path, snap, cert := completeUpdatesFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	generation, e := inventorywire.CachedUpdatesGenerationID(snap.Approval.DeviceID, 1)
	if e != nil {
		t.Fatal(e)
	}
	failure := InventoryFailureReport{Sequence: 1, GenerationID: generation, AttemptedAt: at, Reason: "not_supported"}
	if failure.valid() {
		t.Fatal("unsupported reason widened legacy package failures")
	}
	receipt, e := s.CompleteUpdatesFailure(ctx, snap.InvitationID, cert.CertificateHash(), failure, at)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s = f.open(t, path)
	view, e := s.CompleteUpdatesView(ctx, snap.Approval.DeviceID, at.Add(time.Second))
	if e != nil || view.Complete != nil || view.Failure == nil || *view.Failure != receipt || view.Status != "unavailable" {
		t.Fatal("unsupported failure lost on restart", e)
	}
	retry, e := s.CompleteUpdatesFailure(ctx, snap.InvitationID, cert.CertificateHash(), failure, at.Add(2*time.Second))
	if e != nil || retry != receipt {
		t.Fatal("unsupported failure retry refreshed receipt", e)
	}
	failure.Reason = "unknown_reason"
	if _, e = s.CompleteUpdatesFailure(ctx, snap.InvitationID, cert.CertificateHash(), failure, at.Add(3*time.Second)); !errors.Is(e, enrollmentstate.ErrInvalid) {
		t.Fatal("unrecognized update failure reason accepted", e)
	}
}

func TestCompleteUpdatesPendingCaptureRetentionBeforeLeaseRemainsAbortable(t *testing.T) {
	f, s, path, snap, cert := completeUpdatesFixture(t)
	ctx := context.Background()
	admitted := time.Unix(testNow+10, 0).UTC()
	captured := admitted.Add(-inventoryledger.ObservationTTL + 5*time.Minute)
	b, m, chunks := updatesGenerationFixture(t, snap.Approval.DeviceID, 1, 700, captured)
	stageCompleteUpdates(t, s, snap, cert, b, m, chunks, admitted)
	expired := captured.Add(inventoryledger.ObservationTTL)
	for phase := 0; phase < 4; phase++ {
		if phase > 0 {
			result, e := s.MaintainInventoryStep(ctx, 3, expired)
			if e != nil || result.RowsDeleted > 256 || result.ChunksDeleted > 16 {
				t.Fatal("pending capture cleanup", e)
			}
		}
		if e := s.Close(); e != nil {
			t.Fatal(e)
		}
		s = f.open(t, path)
		status, e := s.CompleteUpdatesStatus(ctx, snap.InvitationID, cert.CertificateHash(), b, expired)
		if e != nil || status.Transfer == nil || status.Transfer.State != "failed" || !status.Transfer.CompletedAt.IsZero() || !status.Transfer.ExpiresAt.Equal(admitted.Add(inventoryledger.StagingTTL)) {
			t.Fatal("expired source is not abortable under original lease", e)
		}
		if _, e = s.CompleteUpdatesFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, expired); e == nil {
			t.Fatal("expired source promoted")
		}
	}
	if e := s.CompleteUpdatesAbort(ctx, snap.InvitationID, cert.CertificateHash(), b, expired); e != nil {
		t.Fatal("physically cleaned pending cannot abort", e)
	}
	next, nm, nc := updatesGenerationFixture(t, snap.Approval.DeviceID, 2, 20, expired.Add(time.Second))
	promoteCompleteUpdates(t, s, snap, cert, next, nm, nc, expired.Add(time.Second))
}
