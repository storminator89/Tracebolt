package main

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"localrmm/internal/enrollmentclient"
	"localrmm/internal/windowsservice"
)

func TestConcurrentStopDoesNotHidePendingAuthorityFailures(t *testing.T) {
	errorsToTest := []error{enrollmentclient.ErrState, enrollmentclient.ErrTerminal, enrollmentclient.ErrServiceDeadline, errors.Join(enrollmentclient.ErrState, context.Canceled)}
	for _, stage := range []string{"inspect", "resume", "mark-ready", "sender"} {
		for n, authority := range errorsToTest {
			t.Run(fmt.Sprintf("%s/%d", stage, n), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				f := &pendingFixture{}
				h := f.hooks()
				switch stage {
				case "inspect":
					h.inspect = func() (enrollmentclient.ServiceState, error) {
						cancel()
						return enrollmentclient.ServiceState{}, authority
					}
				case "resume":
					h.resume = func(context.Context) error { cancel(); return authority }
				case "mark-ready":
					f.active = true
					h.markReady = func() (enrollmentclient.ServiceState, error) {
						cancel()
						return enrollmentclient.ServiceState{}, authority
					}
				case "sender":
					f.active = true
					h.sender = func(context.Context, string) error { cancel(); return authority }
				}
				err := runPendingWindows(ctx, pendingConfig, f.signal, h)
				d := windowsservice.Diagnostic(err)
				if err == nil || d.Reason == windowsservice.ReasonInterrupted || d.Reason == windowsservice.ReasonUnknown || d.ServiceCode == 0 {
					t.Fatal("concurrent stop hid authority failure")
				}
				if !errors.Is(err, authority) && !(errors.Is(authority, context.Canceled) && errors.Is(err, enrollmentclient.ErrState)) {
					t.Fatal("authority error identity not retained")
				}
				if f.waits != 0 {
					t.Fatal("authority failure retried")
				}
			})
		}
	}
}
func TestConcurrentStopAcceptsOnlyCooperativePendingOutcomes(t *testing.T) {
	for n, outcome := range []error{nil, context.Canceled, context.DeadlineExceeded, enrollmentclient.ErrTransport, fmt.Errorf("fixture wrap: %w", context.Canceled)} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := &pendingFixture{}
			h := f.hooks()
			h.resume = func(context.Context) error { cancel(); return outcome }
			if err := runPendingWindows(ctx, pendingConfig, f.signal, h); err != context.Canceled || f.sends != 0 {
				t.Fatal("cooperative stop became failure or sender")
			}
		})
	}
}
func TestConcurrentStopPreservesInvalidHandoffAndMarkerFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &pendingFixture{active: true}
	h := f.hooks()
	h.markReady = func() (enrollmentclient.ServiceState, error) {
		cancel()
		return enrollmentclient.ServiceState{Ready: false, ConfigPath: pendingConfig}, nil
	}
	if err := runPendingWindows(ctx, pendingConfig, f.signal, h); windowsservice.Diagnostic(err).Reason != windowsservice.ReasonHandoffInvalid {
		t.Fatal("invalid handoff hidden by stop")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	f = &pendingFixture{}
	h = f.hooks()
	h.resume = func(context.Context) error { cancel(); return enrollmentclient.ErrServiceDeadline }
	h.stopDeadline = func() error { return errors.Join(enrollmentclient.ErrState, enrollmentclient.ErrServiceDeadline) }
	if err := runPendingWindows(ctx, pendingConfig, f.signal, h); windowsservice.Diagnostic(err).Reason != windowsservice.ReasonStateRejected {
		t.Fatal("marker write failure hidden by expiry/stop")
	}
}
func TestCooperativePendingOutcomeRejectsMixedAndDiagnosedFailures(t *testing.T) {
	for _, err := range []error{errors.Join(errors.New("private failure"), context.Canceled), errors.Join(enrollmentclient.ErrState, enrollmentclient.ErrTransport), windowsservice.Mark(windowsservice.PhaseHandoff, windowsservice.ReasonHandoffInvalid, context.Canceled)} {
		if cooperativePendingOutcome(err) {
			t.Fatal("mixed/diagnosed error accepted as cooperative cancellation")
		}
	}
}
