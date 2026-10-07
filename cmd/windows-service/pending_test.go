package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"localrmm/internal/enrollmentclient"
	"localrmm/internal/windowsservice"
)

const pendingConfig = `C:\Fixture\enrollment\agent.json`

type pendingFixture struct {
	events                                        []string
	resumes, inspects, waits, ready, sends, stops int
	active                                        bool
	now, originalDeadline, approvalAfter          time.Duration
	resumeErrors                                  []error
	inspectFailure                                error
	identityFailure                               error
	markFailure                                   error
	cancel                                        context.CancelFunc
}

func (f *pendingFixture) hooks() pendingHooks {
	return pendingHooks{
		identity: func() error { f.events = append(f.events, "identity"); return f.identityFailure },
		inspect: func() (enrollmentclient.ServiceState, error) {
			f.events = append(f.events, "inspect")
			f.inspects++
			if f.inspectFailure != nil {
				return enrollmentclient.ServiceState{}, f.inspectFailure
			}
			if f.originalDeadline > 0 && f.now >= f.originalDeadline {
				return enrollmentclient.ServiceState{}, enrollmentclient.ErrServiceDeadline
			}
			return enrollmentclient.ServiceState{Ready: f.active, ConfigPath: pendingConfig}, nil
		},
		resume: func(context.Context) error {
			f.events = append(f.events, "resume")
			f.resumes++
			if len(f.resumeErrors) > 0 {
				err := f.resumeErrors[0]
				f.resumeErrors = f.resumeErrors[1:]
				if errors.Is(err, context.DeadlineExceeded) {
					f.now += 15 * time.Minute
				}
				return err
			}
			if f.now < f.approvalAfter {
				f.now = f.approvalAfter
			}
			f.active = true
			return nil
		},
		stopDeadline: func() error { f.events = append(f.events, "expire"); f.stops++; return nil },
		markReady: func() (enrollmentclient.ServiceState, error) {
			f.events = append(f.events, "mark-ready")
			return enrollmentclient.ServiceState{Ready: true, ConfigPath: pendingConfig}, f.markFailure
		},
		sender: func(context.Context, string) error { f.events = append(f.events, "sender"); f.sends++; return nil },
		wait: func(ctx context.Context) error {
			f.events = append(f.events, "wait")
			f.waits++
			f.now += 5 * time.Second
			if f.cancel != nil {
				f.cancel()
				return ctx.Err()
			}
			return nil
		},
	}
}
func (f *pendingFixture) signal() { f.events = append(f.events, "running"); f.ready++ }
func TestPendingTimeoutContinuesWithinOriginalThirtyMinuteAuthority(t *testing.T) {
	f := &pendingFixture{originalDeadline: 30 * time.Minute, approvalAfter: 16 * time.Minute, resumeErrors: []error{context.DeadlineExceeded, enrollmentclient.ErrTransport}}
	if err := runPendingWindows(context.Background(), pendingConfig, f.signal, f.hooks()); err != nil {
		t.Fatal("pending transient error became fatal")
	}
	if f.resumes != 3 || f.waits != 2 || f.ready != 1 || f.sends != 1 || f.stops != 0 || f.originalDeadline != 30*time.Minute || f.now != 16*time.Minute {
		t.Fatal("pending continuity, readiness or original deadline changed")
	}
	want := []string{"identity", "inspect", "running", "resume", "identity", "inspect", "wait", "identity", "inspect", "resume", "identity", "inspect", "wait", "identity", "inspect", "resume", "identity", "inspect", "mark-ready", "sender"}
	if !reflect.DeepEqual(f.events, want) {
		t.Fatal("identity/state not reinspected around bounded retry")
	}
}
func TestPendingOriginalDeadlineIsNeverExtended(t *testing.T) {
	f := &pendingFixture{originalDeadline: 30 * time.Minute, resumeErrors: []error{context.DeadlineExceeded, context.DeadlineExceeded}}
	err := runPendingWindows(context.Background(), pendingConfig, f.signal, f.hooks())
	d := windowsservice.Diagnostic(err)
	if d.Reason != windowsservice.ReasonApprovalExpired || f.resumes != 2 || f.stops != 1 || f.sends != 0 || f.originalDeadline != 30*time.Minute {
		t.Fatal("expiry was retried or extended")
	}
}
func TestPendingCancellationDuringBackoffIsGraceful(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &pendingFixture{originalDeadline: 30 * time.Minute, resumeErrors: []error{context.DeadlineExceeded}, cancel: cancel}
	if err := runPendingWindows(ctx, pendingConfig, f.signal, f.hooks()); !errors.Is(err, context.Canceled) || f.resumes != 1 || f.sends != 0 || f.stops != 0 {
		t.Fatal("stop became retry/failure or reset state")
	}
}
func TestPendingTerminalAndInvalidStatesNeverRetry(t *testing.T) {
	for _, err := range []error{enrollmentclient.ErrTerminal, enrollmentclient.ErrState, enrollmentclient.ErrBootstrap, enrollmentclient.ErrServiceDeadline} {
		f := &pendingFixture{resumeErrors: []error{err}}
		if got := runPendingWindows(context.Background(), pendingConfig, f.signal, f.hooks()); got == nil || f.resumes != 1 || f.waits != 0 || f.sends != 0 {
			t.Fatal("terminal or authority error retried")
		}
	}
}
func TestPendingIdentityLossAfterTimeoutStopsBeforeRetry(t *testing.T) {
	f := &pendingFixture{resumeErrors: []error{context.DeadlineExceeded}}
	h := f.hooks()
	base := h.inspect
	h.inspect = func() (enrollmentclient.ServiceState, error) {
		if f.resumes > 0 {
			f.identityFailure = errors.New("private identity detail")
		}
		return base()
	}
	if err := runPendingWindows(context.Background(), pendingConfig, f.signal, h); windowsservice.Diagnostic(err).Reason != windowsservice.ReasonIdentityRejected || f.resumes != 1 || f.sends != 0 {
		t.Fatal("identity loss permitted another request")
	}
}
func TestPendingRechecksHandoffBeforeSender(t *testing.T) {
	f := &pendingFixture{active: true, markFailure: enrollmentclient.ErrState}
	if err := runPendingWindows(context.Background(), pendingConfig, f.signal, f.hooks()); windowsservice.Diagnostic(err).Reason != windowsservice.ReasonHandoffInvalid || f.resumes != 0 || f.sends != 0 {
		t.Fatal("invalid handoff constructed sender")
	}
}
func TestPendingExpiryDuringBackoffStopsWithoutSecondResume(t *testing.T) {
	f := &pendingFixture{originalDeadline: 15*time.Minute + time.Second, resumeErrors: []error{context.DeadlineExceeded}}
	if err := runPendingWindows(context.Background(), pendingConfig, f.signal, f.hooks()); windowsservice.Diagnostic(err).Reason != windowsservice.ReasonApprovalExpired || f.resumes != 1 || f.waits != 1 || f.stops != 1 {
		t.Fatal("deadline crossed in backoff was ignored")
	}
}

func TestPendingExpiryMarkerSentinelIsExpected(t *testing.T) {
	f := &pendingFixture{inspectFailure: enrollmentclient.ErrServiceDeadline}
	h := f.hooks()
	h.stopDeadline = func() error { f.stops++; return enrollmentclient.ErrServiceDeadline }
	if err := runPendingWindows(context.Background(), pendingConfig, f.signal, h); windowsservice.Diagnostic(err).Reason != windowsservice.ReasonApprovalExpired || f.stops != 1 || f.resumes != 0 {
		t.Fatal("persisted deadline marker sentinel mislabeled")
	}
	h.stopDeadline = func() error { return enrollmentclient.ErrState }
	if err := runPendingWindows(context.Background(), pendingConfig, f.signal, h); windowsservice.Diagnostic(err).Reason != windowsservice.ReasonStateRejected {
		t.Fatal("deadline marker write failure hidden")
	}
}

func TestPendingRetainedStateLossAfterTimeoutStopsImmediately(t *testing.T) {
	f := &pendingFixture{resumeErrors: []error{context.DeadlineExceeded}}
	h := f.hooks()
	base := h.inspect
	h.inspect = func() (enrollmentclient.ServiceState, error) {
		if f.resumes > 0 {
			return enrollmentclient.ServiceState{}, enrollmentclient.ErrState
		}
		return base()
	}
	if err := runPendingWindows(context.Background(), pendingConfig, f.signal, h); windowsservice.Diagnostic(err).Reason != windowsservice.ReasonStateRejected || f.resumes != 1 || f.waits != 0 || f.sends != 0 {
		t.Fatal("missing authority was retried")
	}
}

func TestPendingSuccessfulAttemptWithoutReadyDoesNotSpin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &pendingFixture{cancel: cancel}
	h := f.hooks()
	h.resume = func(context.Context) error { f.resumes++; return nil }
	if err := runPendingWindows(ctx, pendingConfig, f.signal, h); !errors.Is(err, context.Canceled) || f.resumes != 1 || f.waits != 1 || f.sends != 0 {
		t.Fatal("unready successful attempt spun or constructed sender")
	}
}
