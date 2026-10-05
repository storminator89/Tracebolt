package enrollmentstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"localrmm/internal/enrollmentstate"
	"localrmm/internal/inventoryledger"
)

func TestCompleteUpdatesFinalizeRechecksClockAfterStream(t *testing.T) {
	_, s, _, snap, cert := completeUpdatesFixture(t)
	base := time.Unix(testNow+10, 0).UTC()
	b, m, chunks := updatesGenerationFixture(t, snap.Approval.DeviceID, 1, 1301, base)
	stageCompleteUpdates(t, s, snap, cert, b, m, chunks, base)
	n := 0
	ctx := WithCompleteUpdatesClock(context.Background(), func() time.Time {
		n++
		if n == 1 {
			return base.Add(inventoryledger.StagingTTL - time.Second)
		}
		return base.Add(inventoryledger.StagingTTL)
	})
	if _, e := s.CompleteUpdatesFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, base); !errors.Is(e, inventoryledger.ErrExpired) {
		t.Fatal("stream crossed stage expiry", e)
	}
	view, e := s.CompleteUpdatesView(context.Background(), snap.Approval.DeviceID, base.Add(inventoryledger.StagingTTL))
	if e != nil || view.Complete != nil || view.Transfer == nil || view.Transfer.State != "expired" {
		t.Fatal("expired stream became complete", e)
	}
}
func TestCompleteUpdatesOutputClockWithholdsCrossedCursor(t *testing.T) {
	_, s, _, snap, cert := completeUpdatesFixture(t)
	base := time.Unix(testNow+10, 0).UTC()
	b, m, chunks := updatesGenerationFixture(t, snap.Approval.DeviceID, 1, 1301, base)
	promoteCompleteUpdates(t, s, snap, cert, b, m, chunks, base)
	n := 0
	ctx := WithCompleteUpdatesClock(context.Background(), func() time.Time {
		n++
		if n == 1 {
			return base
		}
		return base.Add(inventoryledger.CursorTTL)
	})
	page, e := s.CompleteUpdatesPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 100}, base)
	if !errors.Is(e, inventoryledger.ErrCursorExpired) || len(page.Items) != 0 || page.NextCursor != "" {
		t.Fatal("expired postcommit output escaped", e)
	}
}
func TestCompleteUpdatesTerminationCannotPrecedeAcceptedReceipt(t *testing.T) {
	_, s, _, snap, cert := completeUpdatesFixture(t)
	base := time.Unix(testNow+10, 0).UTC()
	b, m, _ := updatesGenerationFixture(t, snap.Approval.DeviceID, 1, 20, base)
	if _, e := s.CompleteUpdatesBegin(context.Background(), snap.InvitationID, cert.CertificateHash(), b, m, base); e != nil {
		t.Fatal(e)
	}
	c := control(snap, 91)
	c.Now = base.Add(-time.Second).Unix()
	if _, e := s.Terminate(context.Background(), enrollmentstate.TerminalCommand{Control: c, State: enrollmentstate.Revoked}); !errors.Is(e, ErrStorage) {
		t.Fatal("stale termination committed", e)
	}
	if _, e := s.CompleteUpdatesStatus(context.Background(), snap.InvitationID, cert.CertificateHash(), b, base); e != nil {
		t.Fatal("failed lifecycle transaction poisoned store", e)
	}
}

func TestCompleteUpdatesOutputClockWithholdsCrossedPendingStatus(t *testing.T) {
	_, s, _, snap, cert := completeUpdatesFixture(t)
	base := time.Unix(testNow+10, 0).UTC()
	b, m, _ := updatesGenerationFixture(t, snap.Approval.DeviceID, 1, 20, base)
	if _, e := s.CompleteUpdatesBegin(context.Background(), snap.InvitationID, cert.CertificateHash(), b, m, base); e != nil {
		t.Fatal(e)
	}
	n := 0
	ctx := WithCompleteUpdatesClock(context.Background(), func() time.Time {
		n++
		if n == 1 {
			return base
		}
		return base.Add(inventoryledger.StagingTTL)
	})
	status, e := s.CompleteUpdatesStatus(ctx, snap.InvitationID, cert.CertificateHash(), b, base)
	if !errors.Is(e, inventoryledger.ErrExpired) || status.Transfer != nil {
		t.Fatal("stale pending output escaped", e)
	}
}
