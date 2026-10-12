package enrollmentstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowscontact"
)

func TestWindowsIncidentAuthorityLeaseSerializesConcurrentRevocation(t *testing.T) {
	_, s, _, snap, _ := activeWindowsStore(t, "tls")
	ctx := context.Background()
	now := time.Unix(testNow+10, 0).UTC()
	inputs, e := s.WindowsContactInputs(ctx, now)
	if e != nil || len(inputs) != 1 {
		t.Fatal(e)
	}
	expected := inputs[0]
	entered := make(chan struct{})
	release := make(chan struct{})
	ackDone := make(chan error, 1)
	go func() {
		ackDone <- s.WithWindowsIncidentAuthority(ctx, expected, func() time.Time { return now }, func(guard func(time.Time) error) error { close(entered); <-release; return guard(now) })
	}()
	<-entered
	// Simulate an operator SQLite wait inside the leased callback. Revocation may
	// be requested but cannot complete until acknowledgement's guarded commit ends.
	waits := s.db.Stats().WaitCount
	revoked := make(chan error, 1)
	go func() {
		c := control(snap, 20)
		c.Now = now.Unix()
		_, err := s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: c, State: enrollmentstate.Revoked})
		revoked <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for s.db.Stats().WaitCount == waits && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s.db.Stats().WaitCount == waits {
		close(release)
		t.Fatal("revocation did not wait on authority lease")
	}
	select {
	case err := <-revoked:
		close(release)
		t.Fatal("revocation completed inside acknowledgement lease", err)
	default:
	}
	close(release)
	if err := <-ackDone; err != nil {
		t.Fatal(err)
	}
	if err := <-revoked; err != nil {
		t.Fatal(err)
	}
	called := false
	e = s.WithWindowsIncidentAuthority(ctx, expected, func() time.Time { return now }, func(func(time.Time) error) error { called = true; return nil })
	if e == nil || called {
		t.Fatal("revoked original admission reached acknowledgement callback")
	}
}
func TestWindowsIncidentAuthorityLeaseAfterWaitExpiryAndBindings(t *testing.T) {
	_, s, _, _, _ := activeWindowsStore(t, "tls")
	ctx := context.Background()
	now := time.Unix(testNow+10, 0).UTC()
	inputs, e := s.WindowsContactInputs(ctx, now)
	if e != nil {
		t.Fatal(e)
	}
	expected := inputs[0]
	for _, change := range []func(*windowscontact.Input){func(v *windowscontact.Input) { v.CertificateHash = strings.Repeat("f", 64) }, func(v *windowscontact.Input) { v.InvitationID = "invite_" + strings.Repeat("f", 32) }, func(v *windowscontact.Input) { v.AuthorityUntil = v.AuthorityUntil.Add(time.Second) }} {
		wrong := expected
		change(&wrong)
		called := false
		if e = s.WithWindowsIncidentAuthority(ctx, wrong, func() time.Time { return now }, func(func(time.Time) error) error { called = true; return nil }); e == nil || called {
			t.Fatal("replacement/leaf binding accepted")
		}
	}
	// The locked authority guard samples its clock again after a caller's wait.
	e = s.WithWindowsIncidentAuthority(ctx, expected, func() time.Time { return now }, func(guard func(time.Time) error) error { now = expected.AuthorityUntil; return guard(now) })
	if !errors.Is(e, enrollmentstate.ErrProof) {
		t.Fatal("expired locked credential accepted", e)
	}
}
func TestWindowsIncidentAuthorityLeaseReadOnly(t *testing.T) {
	_, s, _, _, _ := activeWindowsStore(t, "tls")
	ctx := context.Background()
	now := time.Unix(testNow+10, 0).UTC()
	inputs, e := s.WindowsContactInputs(ctx, now)
	if e != nil {
		t.Fatal(e)
	}
	var before, after int64
	s.db.QueryRow("SELECT total_changes()").Scan(&before)
	if e = s.WithWindowsIncidentAuthority(ctx, inputs[0], func() time.Time { return now }, func(guard func(time.Time) error) error { return guard(now) }); e != nil {
		t.Fatal(e)
	}
	s.db.QueryRow("SELECT total_changes()").Scan(&after)
	if before != after {
		t.Fatal("authority lease changed enrollment")
	}
}

func TestWindowsIncidentAuthorityGuardRetainsAcknowledgementClockFloor(t *testing.T) {
	_, s, _, _, _ := activeWindowsStore(t, "tls")
	ctx := context.Background()
	now := time.Unix(testNow+10, 0).UTC()
	inputs, e := s.WindowsContactInputs(ctx, now)
	if e != nil {
		t.Fatal(e)
	}
	e = s.WithWindowsIncidentAuthority(ctx, inputs[0], func() time.Time { return now }, func(guard func(time.Time) error) error {
		// Operator's stamp advanced, then the live authoritative clock rolled back.
		sampled := now.Add(4 * time.Second)
		now = now.Add(time.Second)
		return guard(sampled)
	})
	if !errors.Is(e, enrollmentstate.ErrProof) {
		t.Fatal("rollback behind the operator stamp accepted", e)
	}
}

func TestWindowsIncidentAuthorityLeaseCancellationReleasesLock(t *testing.T) {
	_, s, _, _, _ := activeWindowsStore(t, "tls")
	now := time.Unix(testNow+10, 0).UTC()
	inputs, e := s.WindowsContactInputs(context.Background(), now)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e = s.WithWindowsIncidentAuthority(ctx, inputs[0], func() time.Time { return now }, func(guard func(time.Time) error) error { cancel(); return guard(now) })
	if !errors.Is(e, context.Canceled) {
		t.Fatal("canceled acknowledgement kept authority", e)
	}
	if _, e = s.WindowsContactInputs(context.Background(), now); e != nil {
		t.Fatal("canceled lease did not release enrollment lock", e)
	}
}
