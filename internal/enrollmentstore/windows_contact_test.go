package enrollmentstore

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentstate"
	"testing"
	"time"
)

func TestWindowsContactUsesOriginalAcceptedReceiptOnly(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f, s, path, snap, cert := activeWindowsStore(t, profile)
			ctx := context.Background()
			at := time.Unix(testNow+10, 0).UTC()
			inputs, err := s.WindowsContactInputs(ctx, at)
			if err != nil || len(inputs) != 1 || !inputs[0].Authorized || !inputs[0].ReceivedAt.IsZero() || inputs[0].Sequence != 0 {
				t.Fatal("unobserved identity must have no invented contact", err)
			}
			raw := windowsStoreFrame(t, 1, at)
			first, err := s.SaveObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, at)
			if err != nil {
				t.Fatal(err)
			}
			s.Close()
			s = f.open(t, path)
			retry, err := s.SaveObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, at.Add(3*time.Minute))
			if err != nil || !retry.Duplicate {
				t.Fatal("exact retry", err)
			}
			inputs, err = s.WindowsContactInputs(ctx, at.Add(3*time.Minute))
			if err != nil || len(inputs) != 1 {
				t.Fatal(err)
			}
			in := inputs[0]
			if !in.Authorized || in.InvitationID != snap.InvitationID || in.CertificateHash != cert.CertificateHash() || !in.AuthorityUntil.Equal(time.Unix(snap.Intent.NotAfter, 0).UTC()) || !in.ReceivedAt.Equal(first.ReceivedAt) || in.Sequence != first.Sequence {
				t.Fatal("contact provenance changed", in)
			}
			if _, err := s.HealthInputs(ctx, map[string][]string{}, at); err == nil {
				t.Fatal("Windows store entered Linux health/AI source")
			}
			if _, err := s.WindowsContactInputs(ctx, at.Add(-time.Nanosecond)); !errors.Is(err, enrollmentstate.ErrInvalid) {
				t.Fatal("future receipt accepted", err)
			}
			later := at.Add(4 * time.Minute)
			if _, err := s.SaveObservation(ctx, snap.InvitationID, cert.CertificateHash(), windowsStoreFrame(t, 2, later), later); err != nil {
				t.Fatal(err)
			}
			inputs, err = s.WindowsContactInputs(ctx, later)
			if err != nil || !inputs[0].ReceivedAt.Equal(later) || inputs[0].Sequence != 2 {
				t.Fatal("advancing accepted receipt lost", err)
			}
			control := control(snap, 20)
			control.Now = later.Add(time.Second).Unix()
			if _, err := s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: control, State: enrollmentstate.Revoked}); err != nil {
				t.Fatal(err)
			}
			inputs, err = s.WindowsContactInputs(ctx, later.Add(time.Second))
			if err != nil || len(inputs) != 1 || inputs[0].Authorized || !inputs[0].ReceivedAt.IsZero() || inputs[0].Sequence != 0 {
				t.Fatal("revocation disclosed contact", err)
			}
		})
	}
}

func TestWindowsContactAuthorityExpiryCancellationAndAdmission(t *testing.T) {
	_, s, _, snap, _ := activeWindowsStore(t, "tls")
	ctx := context.Background()
	for _, now := range []time.Time{time.Unix(snap.UpdatedAt-1, 0).UTC(), time.Unix(snap.Intent.NotBefore-1, 0).UTC(), time.Unix(snap.Intent.NotAfter, 0).UTC()} {
		inputs, err := s.WindowsContactInputs(ctx, now)
		if err == nil && len(inputs) > 0 && inputs[0].Authorized {
			t.Fatal("identity authorized outside current lifetime", now)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.WindowsContactInputs(canceled, time.Unix(testNow+10, 0).UTC()); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored", err)
	}
	s.operationalReads <- struct{}{}
	if _, err := s.WindowsContactInputs(ctx, time.Unix(testNow+10, 0).UTC()); !errors.Is(err, ErrOperationalBusy) {
		t.Fatal("unbounded contact read admission", err)
	}
	<-s.operationalReads
	if _, err := s.WindowsContactInputs(nil, time.Unix(testNow+10, 0).UTC()); !errors.Is(err, enrollmentstate.ErrInvalid) {
		t.Fatal("nil context", err)
	}
	_, linux, _, _, _ := completeFixture(t)
	if _, err := linux.WindowsContactInputs(ctx, time.Unix(testNow+10, 0).UTC()); !errors.Is(err, enrollmentstate.ErrProof) {
		t.Fatal("Linux profile entered Windows contact source", err)
	}
}

func TestWindowsContactSourceReadsDoNotWriteEnrollmentState(t *testing.T) {
	_, s, _, snap, cert := activeWindowsStore(t, "tls")
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	if _, err := s.SaveObservation(ctx, snap.InvitationID, cert.CertificateHash(), windowsStoreFrame(t, 1, at), at); err != nil {
		t.Fatal(err)
	}
	var before, after int64
	if err := s.db.QueryRowContext(ctx, "SELECT total_changes()").Scan(&before); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		inputs, err := s.WindowsContactInputs(ctx, at.Add(time.Duration(i+1)*time.Minute))
		if err != nil || len(inputs) != 1 || !inputs[0].ReceivedAt.Equal(at) || inputs[0].Sequence != 1 {
			t.Fatal("receipt read changed evidence", err)
		}
	}
	if err := s.db.QueryRowContext(ctx, "SELECT total_changes()").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("receipt read wrote enrollment state")
	}
}
