package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"localrmm/internal/windowsservice"
)

type lifecycleLeaseFixture struct {
	held                    atomic.Bool
	raw                     []byte
	layout                  windowsservice.Layout
	reads, verifies, closes int
	readErr, closeErr       error
	verifyErrAt             int
	released                bool
}

func newLifecycleLeaseFixture(t *testing.T) *lifecycleLeaseFixture {
	t.Helper()
	f := &lifecycleLeaseFixture{layout: windowsservice.Layout{StateRoot: `C:\ProgramData\Tracebolt\windows-agent`}}
	r := installReceipt{Version: 1, Prepared: true, Service: windowsservice.Receipt{Version: 1, Complete: true, Layout: f.layout, InstallationID: "fixture-owned"}}
	f.raw, _ = json.Marshal(r)
	return f
}
func (f *lifecycleLeaseFixture) open() (windowsservice.Layout, receiptStore, error) {
	if !f.held.CompareAndSwap(false, true) {
		return f.layout, nil, errLifecycle
	}
	f.released = false
	return f.layout, f, nil
}
func (f *lifecycleLeaseFixture) Read(name string) ([]byte, error) {
	if !f.held.Load() || name != "receipt.json" {
		panic("read outside lease")
	}
	f.reads++
	return bytes.Clone(f.raw), f.readErr
}
func (f *lifecycleLeaseFixture) Verify() error {
	if !f.held.Load() {
		panic("verify outside lease")
	}
	f.verifies++
	if f.verifies == f.verifyErrAt {
		return errLifecycle
	}
	return nil
}
func (f *lifecycleLeaseFixture) Close() error {
	if !f.held.Swap(false) {
		panic("duplicate close")
	}
	f.closes++
	f.released = true
	return f.closeErr
}
func (f *lifecycleLeaseFixture) perform(ctx context.Context, r request, _, _ io.Writer) (any, error) {
	return withReceiptLease(ctx, f.open, func(receipt installReceipt, lease receiptStore) (any, error) {
		return serviceLifecycleOperation(ctx, r.mode, receipt.Service, lease, serviceLifecycleSteps{restart: func(_ context.Context, r windowsservice.Receipt, guard windowsservice.LifecycleLease) (windowsservice.RestartResult, error) {
			if !f.held.Load() || r.InstallationID != "fixture-owned" || guard != f {
				panic("restart without exact lease/receipt")
			}
			return windowsservice.RestartResult{Outcome: "running-observed", Phase: "complete", StopAttempted: true, StopRequested: true, StoppedObserved: true, StartAttempted: true, StartRequested: true, RunningObserved: true, StateRetained: true}, nil
		}})
	})
}

func TestRestartCLIExplicitDispatchHoldsLeaseAndEmitsResult(t *testing.T) {
	f := newLifecycleLeaseFixture(t)
	var out, stderr bytes.Buffer
	if code := runWith(context.Background(), []string{"--restart", "--apply"}, &out, &stderr, f.perform); code != 0 || stderr.Len() != 0 {
		t.Fatal(code, stderr.String())
	}
	var got windowsservice.RestartResult
	if json.Unmarshal(out.Bytes(), &got) != nil || got.Outcome != "running-observed" || !got.StopAttempted || !got.StartAttempted || f.closes != 1 || f.verifies != 2 || f.held.Load() {
		t.Fatal(got, f.closes, f.verifies)
	}
}

func TestRestartCLIRejectsImplicitOrExpandedAuthority(t *testing.T) {
	for _, args := range [][]string{nil, {"--restart"}, {"--restart", "--apply=false"}, {"--restart", "--apply", "--start"}, {"--restart", "--apply", "--stop"}, {"--restart", "--apply", "--install"}, {"--restart", "--apply", "--uninstall"}, {"--restart", "--apply", "--basic-readonly"}, {"--restart", "--apply", "--windows-inventory"}, {"--restart", "--apply", "--insecure-http-test"}, {"--restart", "--apply", "--bootstrap-file", "other"}, {"--restart", "--apply", "--service-name", "Spooler"}, {"--restart", "--apply", "--path", "other"}, {"--restart", "--apply", "Spooler"}, {"--restart", "--apply", "--network-endpoints"}} {
		calls := 0
		code := runWith(context.Background(), args, io.Discard, io.Discard, func(context.Context, request, io.Writer, io.Writer) (any, error) { calls++; return nil, nil })
		if code != 2 || calls != 0 {
			t.Fatal(args, code, calls)
		}
	}
}

func TestRestartPartialOutputAndReleaseFailureNeverBecomeSuccess(t *testing.T) {
	private := errors.New("PRIVATE raw native path and content")
	for _, mode := range []string{"control", "release", "post-verify", "receipt"} {
		f := newLifecycleLeaseFixture(t)
		if mode == "release" {
			f.closeErr = private
		}
		if mode == "post-verify" {
			f.verifyErrAt = 2
		}
		if mode == "receipt" {
			f.raw = []byte("foreign")
		}
		var out, stderr bytes.Buffer
		perform := f.perform
		if mode == "control" {
			perform = func(ctx context.Context, _ request, _, _ io.Writer) (any, error) {
				return withReceiptLease(ctx, f.open, func(installReceipt, receiptStore) (any, error) {
					return windowsservice.RestartResult{Outcome: "intervention-required", Phase: "stop", StopAttempted: true, StateRetained: true}, private
				})
			}
		}
		code := runWith(context.Background(), []string{"--restart", "--apply"}, &out, &stderr, perform)
		var got windowsservice.RestartResult
		if code != 1 || json.Unmarshal(out.Bytes(), &got) != nil || got.Outcome == "running-observed" || !got.StateRetained || f.closes != 1 || strings.Contains(out.String()+stderr.String(), "PRIVATE") {
			t.Fatal(mode, code, out.String(), stderr.String())
		}
		if mode == "control" && (!got.StopAttempted || got.StopRequested || got.StartAttempted) {
			t.Fatal(got)
		}
		if mode == "release" && (got.Phase != "lease-release" || !got.RunningObserved) {
			t.Fatal(got)
		}
		if mode == "receipt" && (got.Outcome != "not-requested" || got.StopAttempted) {
			t.Fatal(got)
		}
	}
}

func TestOtherLifecycleErrorStillDiscardsResult(t *testing.T) {
	var out, stderr bytes.Buffer
	code := runWith(context.Background(), []string{"--stop", "--apply"}, &out, &stderr, func(context.Context, request, io.Writer, io.Writer) (any, error) {
		return map[string]string{"private": "MUST NOT EMIT"}, errLifecycle
	})
	if code != 1 || out.Len() != 0 {
		t.Fatal(code, out.String())
	}
}

func TestReceiptLeaseValidationAndCancellationBeforeEffects(t *testing.T) {
	for _, mode := range []string{"missing", "foreign", "unprepared", "staged", "verify", "canceled", "canceled-read"} {
		f := newLifecycleLeaseFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		switch mode {
		case "missing":
			f.readErr = io.EOF
		case "foreign":
			f.raw = []byte(`{"version":999}`)
		case "unprepared":
			f.raw = bytes.Replace(f.raw, []byte(`"prepared":true`), []byte(`"prepared":false`), 1)
		case "staged":
			f.raw = bytes.Replace(f.raw, []byte(`"version":1`), []byte(`"version":2`), 1)
		case "verify":
			f.verifyErrAt = 1
		case "canceled":
			cancel()
		}
		open := f.open
		if mode == "canceled-read" {
			open = func() (windowsservice.Layout, receiptStore, error) { l, s, e := f.open(); cancel(); return l, s, e }
		}
		calls := 0
		_, err := withReceiptLease(ctx, open, func(installReceipt, receiptStore) (any, error) { calls++; return nil, nil })
		if err == nil || calls != 0 || f.held.Load() || mode != "canceled" && f.closes != 1 {
			t.Fatal(mode, err, calls, f.closes)
		}
	}
}

func TestReceiptLeasePreservesPrimaryAndReleaseErrors(t *testing.T) {
	primary, release := errors.New("primary"), errors.New("release")
	f := newLifecycleLeaseFixture(t)
	f.closeErr = release
	_, err := withReceiptLease(context.Background(), f.open, func(installReceipt, receiptStore) (any, error) { return nil, primary })
	if !errors.Is(err, primary) || !errors.Is(err, release) || f.closes != 1 {
		t.Fatal(err)
	}
}

func TestReceiptLeaseExcludesConcurrentLifecycleAndConsent(t *testing.T) {
	f := newLifecycleLeaseFixture(t)
	entered, finish, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		_, err := withReceiptLease(context.Background(), f.open, func(installReceipt, receiptStore) (any, error) { close(entered); <-finish; return nil, nil })
		done <- err
	}()
	<-entered
	for _, mode := range []string{"start", "stop", "restart", "uninstall", "enroll", "events-enable", "volumes-enable", "process-metrics-enable", "network-enable", "service-startup-enable", "event-content-enable", "updates-enable"} {
		calls := 0
		_, err := withReceiptLease(context.Background(), f.open, func(installReceipt, receiptStore) (any, error) { calls++; return nil, nil })
		if err == nil || calls != 0 {
			t.Fatal(mode, "concurrent mutation entered")
		}
	}
	close(finish)
	if err := <-done; err != nil || f.closes != 1 || f.held.Load() {
		t.Fatal(err)
	}
	// A later explicit operation can enter only after the original lease closes.
	_, err := withReceiptLease(context.Background(), f.open, func(installReceipt, receiptStore) (any, error) { return nil, nil })
	if err != nil || f.closes != 2 {
		t.Fatal(err)
	}
}

func TestGUIRemovalSharesLeaseAcrossAllEffectsAndRelease(t *testing.T) {
	for _, releaseFails := range []bool{false, true} {
		f := newLifecycleLeaseFixture(t)
		if releaseFails {
			f.closeErr = errLifecycle
		}
		stops, deletes, observes, completed := 0, 0, 0, false
		assertHeld := func() {
			t.Helper()
			if !f.held.Load() {
				t.Fatal("GUI effect outside lease")
			}
			_, err := withReceiptLease(context.Background(), f.open, func(installReceipt, receiptStore) (any, error) { t.Fatal("restart raced GUI"); return nil, nil })
			if err == nil {
				t.Fatal("concurrent admission")
			}
		}
		s := setupWizardRemovalSteps{
			inspectOwned: func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
				assertHeld()
				state := windowsservice.Running
				if stops > 0 {
					state = windowsservice.Stopped
				}
				return windowsservice.Snapshot{Exists: true, State: state}, nil
			},
			stop: func(context.Context, windowsservice.Receipt) (windowsservice.ApplyResult, error) {
				assertHeld()
				stops++
				return windowsservice.ApplyResult{Requested: true}, nil
			},
			remove: func(context.Context, windowsservice.Receipt) (windowsservice.ApplyResult, error) {
				assertHeld()
				deletes++
				return windowsservice.ApplyResult{Requested: true, DeletePending: true, StateRetained: true}, nil
			},
			inspectRemoval: func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
				assertHeld()
				observes++
				if observes == 1 {
					return windowsservice.Snapshot{Exists: true, State: windowsservice.Stopped}, nil
				}
				return windowsservice.Snapshot{}, nil
			},
			pending: func(error) bool { return false }, wait: func(context.Context) error { assertHeld(); return nil },
		}
		err := setupWizardUninstallWithLease(context.Background(), f.open, s, func(text string) {
			if text == setupRemovalCompletedText {
				if f.held.Load() || !f.released {
					t.Fatal("success before release")
				}
				completed = true
			}
		})
		if (err != nil) != releaseFails || completed == releaseFails || stops != 1 || deletes != 1 || observes != 2 || f.closes != 1 {
			t.Fatal(err, completed, stops, deletes, observes)
		}
	}
}

func TestSetupJournalHeldThroughEffectsAndCloseFailureRetainsResult(t *testing.T) {
	for _, fresh := range []bool{false, true} {
		if !fresh {
			f := &setupFixture{fail: "close"}
			got, err := setup(context.Background(), "fixture", f.operations())
			if err == nil || got == nil {
				t.Fatal("release failure lost effect/result", got, err)
			}
			seenStart := false
			closes := 0
			for _, step := range f.steps {
				if step == "start" {
					seenStart = true
				}
				if step == "close" {
					closes++
					if !seenStart {
						t.Fatal("lease released before lifecycle finished")
					}
				}
			}
			if !seenStart || closes != 1 {
				t.Fatal(f.steps)
			}
		} else {
			f := &readSetupFixture{fail: "close"}
			got, err := setupReadObservation(context.Background(), "fixture", readSetupConsentFixture(), f.hooks())
			if err == nil || got == nil || f.started != 1 || !completeReadSetup(f.record) {
				t.Fatal("fresh release failure lost effect/result", got, err)
			}
			seenStart := false
			closes := 0
			for _, step := range f.steps {
				if step == "start" {
					seenStart = true
				}
				if step == "close" {
					closes++
					if !seenStart {
						t.Fatal("fresh lease released early")
					}
				}
			}
			if closes != 1 {
				t.Fatal(f.steps)
			}
		}
	}
}

func TestRestartPublicDeadlineBeginsBeforeReceiptAcquisition(t *testing.T) {
	f := newLifecycleLeaseFixture(t)
	var out, stderr bytes.Buffer
	code := runWith(context.Background(), []string{"--restart", "--apply"}, &out, &stderr, func(ctx context.Context, r request, out, stderr io.Writer) (any, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > windowsservice.RestartTimeout {
			t.Fatal("missing fixed public deadline")
		}
		open := func() (windowsservice.Layout, receiptStore, error) {
			// The exact same deadline must already exist when lease acquisition begins.
			if d, ok := ctx.Deadline(); !ok || d != deadline {
				t.Fatal("receipt outside public budget")
			}
			return f.open()
		}
		return withReceiptLease(ctx, open, func(installReceipt, receiptStore) (any, error) {
			return windowsservice.RestartResult{Outcome: "running-observed", Phase: "complete", StateRetained: true}, nil
		})
	})
	if code != 0 || f.closes != 1 {
		t.Fatal(code, stderr.String())
	}
}

type leaseDeadlineContext struct {
	context.Context
	deadline time.Time
}

func (c *leaseDeadlineContext) Deadline() (time.Time, bool) { return c.deadline, true }

type expireLeaseStore struct {
	*lifecycleLeaseFixture
	ctx   *leaseDeadlineContext
	point string
}

func (s expireLeaseStore) Read(name string) ([]byte, error) {
	raw, e := s.lifecycleLeaseFixture.Read(name)
	if s.point == "read" {
		s.ctx.deadline = time.Unix(1, 0)
	}
	return raw, e
}
func (s expireLeaseStore) Verify() error {
	e := s.lifecycleLeaseFixture.Verify()
	if s.point == "verify" {
		s.ctx.deadline = time.Unix(1, 0)
	}
	return e
}
func (s expireLeaseStore) Close() error {
	e := s.lifecycleLeaseFixture.Close()
	if s.point == "close" {
		s.ctx.deadline = time.Unix(1, 0)
	}
	return e
}
func TestReceiptLeaseChecksElapsedDeadlineAfterSynchronousWork(t *testing.T) {
	for _, point := range []string{"open", "read", "verify", "close"} {
		f := newLifecycleLeaseFixture(t)
		ctx := &leaseDeadlineContext{context.Background(), time.Now().Add(time.Hour)}
		called := 0
		open := func() (windowsservice.Layout, receiptStore, error) {
			l, _, e := f.open()
			if point == "open" {
				ctx.deadline = time.Unix(1, 0)
			}
			return l, expireLeaseStore{f, ctx, point}, e
		}
		got, err := withReceiptLease(ctx, open, func(installReceipt, receiptStore) (any, error) {
			called++
			return windowsservice.RestartResult{Outcome: "running-observed", Phase: "complete", StopAttempted: true, StartAttempted: true, StateRetained: true}, nil
		})
		if !errors.Is(err, context.DeadlineExceeded) || f.closes != 1 || point != "close" && called != 0 {
			t.Fatal(point, got, err, called)
		}
		if point == "close" && got.(windowsservice.RestartResult).Outcome != "intervention-required" {
			t.Fatal(got)
		}
	}
}

func TestGUILeaseCombinedFailureKeepsPrimaryFiniteDiagnostic(t *testing.T) {
	primary := &removalFailure{step: "stop", original: syscall.Errno(5), detail: syscall.Errno(5)}
	f := newLifecycleLeaseFixture(t)
	f.closeErr = errors.New("PRIVATE close")
	f.verifyErrAt = 2
	_, err := withReceiptLease(context.Background(), f.open, func(installReceipt, receiptStore) (any, error) { return nil, primary })
	text := setupRemovalFailureText(err)
	if !errors.Is(err, syscall.Errno(5)) || !errors.Is(err, f.closeErr) || !strings.Contains(text, "Removal diagnostic: stop; access_denied.") || strings.Contains(text, "PRIVATE") {
		t.Fatal(text)
	}
	for _, hostile := range []error{panicSetupDiagnostic{}, &cycleSetupDiagnostic{}} {
		if text := setupRemovalFailureText(hostile); !strings.Contains(text, "unknown; failed") {
			t.Fatal(text)
		}
	}
}
