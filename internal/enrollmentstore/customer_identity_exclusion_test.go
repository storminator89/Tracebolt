package enrollmentstore

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentstate"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCustomerIdentityExclusionUsesEnrollmentLease(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native enrollment store requires Linux")
	}
	_, s, _, snap, _ := activeWindowsStore(t, "tls")
	ctx := context.Background()
	now := time.Unix(testNow+10, 0).UTC()
	if err := s.WithCustomerIdentityExclusion(ctx, []string{snap.Approval.DeviceID}, func() time.Time { return now }, func(func(time.Time) error) error { return nil }); !errors.Is(err, enrollmentstate.ErrConflict) {
		t.Fatal("collision admitted", err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	leaseDone := make(chan error, 1)
	go func() {
		leaseDone <- s.WithCustomerIdentityExclusion(ctx, []string{"agent_" + strings.Repeat("f", 32)}, func() time.Time { return now }, func(guard func(time.Time) error) error { close(entered); <-release; return guard(now) })
	}()
	<-entered
	termination := make(chan error, 1)
	go func() {
		c := control(snap, 20)
		c.Now = now.Unix()
		_, err := s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: c, State: enrollmentstate.Revoked})
		termination <- err
	}()
	select {
	case err := <-termination:
		t.Fatal("mutation passed enrollment lease", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-leaseDone; err != nil {
		t.Fatal(err)
	}
	if err := <-termination; err != nil {
		t.Fatal(err)
	}
}
