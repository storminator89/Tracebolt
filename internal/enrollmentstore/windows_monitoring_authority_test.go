package enrollmentstore

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowscontact"
	"strings"
	"testing"
	"time"
)

func TestWindowsMonitoringAuthorityLeaseFinalClockIdentityAndReadOnly(t *testing.T) {
	for _, which := range []string{"valid", "expired", "rollback", "wrong-original", "wrong-leaf", "duplicate", "too-many"} {
		t.Run(which, func(t *testing.T) {
			_, s, _, _, _ := activeWindowsStore(t, "tls")
			ctx := context.Background()
			now := time.Unix(testNow+10, 0).UTC()
			rows, e := s.WindowsContactInputs(ctx, now)
			if e != nil {
				t.Fatal(e)
			}
			in := rows[0]
			expected := []windowscontact.Input{in}
			switch which {
			case "wrong-original":
				expected[0].CertificateHash = strings.Repeat("f", 64)
			case "wrong-leaf":
				expected[0].AuthorityUntil = in.AuthorityUntil.Add(time.Second)
			case "duplicate":
				expected = append(expected, in)
			case "too-many":
				for len(expected) < 26 {
					expected = append(expected, in)
				}
			}
			var before, after int64
			s.db.QueryRow("SELECT total_changes()").Scan(&before)
			e = s.WithWindowsMonitoringAuthority(ctx, expected, func() time.Time { return now }, func(guard func(time.Time) error) error {
				at := now
				switch which {
				case "expired":
					now = in.AuthorityUntil
				case "rollback":
					now = now.Add(-time.Second)
				}
				return guard(at)
			})
			if which == "valid" && e != nil || which != "valid" && e == nil {
				t.Fatal(which, e)
			}
			s.db.QueryRow("SELECT total_changes()").Scan(&after)
			if before != after {
				t.Fatal("lease changed enrollment")
			}
		})
	}
}
func TestWindowsMonitoringAuthorityLeaseSerializesRevocation(t *testing.T) {
	_, s, _, snap, _ := activeWindowsStore(t, "tls")
	ctx := context.Background()
	now := time.Unix(testNow+10, 0).UTC()
	rows, e := s.WindowsContactInputs(ctx, now)
	if e != nil {
		t.Fatal(e)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- s.WithWindowsMonitoringAuthority(ctx, rows, func() time.Time { return now }, func(guard func(time.Time) error) error { close(entered); <-release; return guard(now) })
	}()
	<-entered
	waits := s.db.Stats().WaitCount
	revoked := make(chan error, 1)
	go func() {
		c := control(snap, 20)
		c.Now = now.Unix()
		_, e := s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: c, State: enrollmentstate.Revoked})
		revoked <- e
	}()
	deadline := time.Now().Add(5 * time.Second)
	for s.db.Stats().WaitCount == waits && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s.db.Stats().WaitCount == waits {
		close(release)
		t.Fatal("revocation did not wait")
	}
	select {
	case e := <-revoked:
		close(release)
		t.Fatal("revocation crossed policy commit", e)
	default:
	}
	close(release)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if e = <-revoked; e != nil {
		t.Fatal(e)
	}
	called := false
	e = s.WithWindowsMonitoringAuthority(ctx, rows, func() time.Time { return now }, func(func(time.Time) error) error { called = true; return nil })
	if e == nil || called {
		t.Fatal("revoked identity reached policy callback")
	}
}
func TestWindowsMonitoringAuthorityCancellation(t *testing.T) {
	_, s, _, _, _ := activeWindowsStore(t, "tls")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	now := time.Unix(testNow+10, 0).UTC()
	rows, e := s.WindowsContactInputs(ctx, now)
	if e != nil {
		t.Fatal(e)
	}
	e = s.WithWindowsMonitoringAuthority(ctx, rows, func() time.Time { return now }, func(guard func(time.Time) error) error { cancel(); return guard(now) })
	if !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e = s.WindowsContactInputs(context.Background(), now); e != nil {
		t.Fatal("canceled lease remained locked", e)
	}
}
