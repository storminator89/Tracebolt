package enrollmentstore

import (
	"context"
	"testing"
	"time"
)

func TestWindowsNotificationAuthorityRejectsReportAdvancedBeforeClaimLease(t *testing.T) {
	_, s, _, snap, cert := activeWindowsStore(t, "tls")
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	if _, e := s.SaveObservation(ctx, snap.InvitationID, cert.CertificateHash(), windowsStoreFrame(t, 1, at), at); e != nil {
		t.Fatal(e)
	}
	inputs, e := s.WindowsCapacityInputs(ctx, at)
	if e != nil || len(inputs) != 1 {
		t.Fatal(e)
	}
	selected := inputs[0].Input
	called := false
	if e = s.WithWindowsNotificationAuthority(ctx, selected, func() time.Time { return at }, func(guard func(time.Time) error) error { called = true; return guard(at) }); e != nil || !called {
		t.Fatal("matching locked receipt rejected", e)
	}
	// Exact reproduction: the dispatcher selected report 1; report 2 commits
	// before it acquires the enrollment lease. Old source evidence must not claim.
	later := at.Add(time.Second)
	if _, e = s.SaveObservation(ctx, snap.InvitationID, cert.CertificateHash(), windowsStoreFrame(t, 2, later), later); e != nil {
		t.Fatal(e)
	}
	called = false
	e = s.WithWindowsNotificationAuthority(ctx, selected, func() time.Time { return later }, func(func(time.Time) error) error { called = true; return nil })
	if e == nil || called {
		t.Fatal("superseded report reached dispatch callback")
	}
	// The legacy acknowledgement lease intentionally retains its identity-only
	// contract; this hardening does not rewrite old API semantics or receipt bytes.
	if e = s.WithWindowsIncidentAuthority(ctx, selected, func() time.Time { return later }, func(guard func(time.Time) error) error { return guard(later) }); e != nil {
		t.Fatal("legacy acknowledgement contract changed", e)
	}
	latest, e := s.WindowsCapacityInputs(ctx, later)
	if e != nil {
		t.Fatal(e)
	}
	var before, after int64
	s.db.QueryRow(`SELECT total_changes()`).Scan(&before)
	if e = s.WithWindowsNotificationAuthority(ctx, latest[0].Input, func() time.Time { return later }, func(guard func(time.Time) error) error { return guard(later) }); e != nil {
		t.Fatal(e)
	}
	s.db.QueryRow(`SELECT total_changes()`).Scan(&after)
	if before != after {
		t.Fatal("dispatch lease wrote enrollment")
	}
}
