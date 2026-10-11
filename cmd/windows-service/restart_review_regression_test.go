package main

import (
	"context"
	"errors"
	"localrmm/internal/windowsservice"
	"strings"
	"syscall"
	"testing"
)

func TestIndependentGUILeasePreservesKnownRemovalFailure(t *testing.T) {
	f := newLifecycleLeaseFixture(t)
	s := setupWizardRemovalSteps{
		inspectOwned: func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
			return windowsservice.Snapshot{Exists: true, State: windowsservice.Running}, nil
		},
		inspectRemoval: func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
			t.Fatal("unexpected removal read")
			return windowsservice.Snapshot{}, nil
		},
		stop: func(context.Context, windowsservice.Receipt) (windowsservice.ApplyResult, error) {
			return windowsservice.ApplyResult{}, syscall.Errno(5)
		},
		remove: func(context.Context, windowsservice.Receipt) (windowsservice.ApplyResult, error) {
			t.Fatal("unexpected delete")
			return windowsservice.ApplyResult{}, nil
		},
		pending: func(error) bool { return false }, wait: func(context.Context) error { t.Fatal("unexpected wait"); return nil },
	}
	err := setupWizardUninstallWithLease(context.Background(), f.open, s, func(string) {})
	if !errors.Is(err, syscall.Errno(5)) {
		t.Fatal("primary error identity lost", err)
	}
	text := setupRemovalFailureText(err)
	if !strings.Contains(text, "Removal diagnostic: stop; access_denied.") {
		t.Fatalf("known GUI failure lost behind lease wrapper: %s", text)
	}
}
func TestIndependentSetupCloseKeepsFirstFailureDiagnosis(t *testing.T) {
	f := &setupFixture{fail: "close"}
	h := f.operations()
	primary := errors.New("primary start failure")
	h.start = func(context.Context, windowsservice.Receipt) (windowsservice.ApplyResult, error) {
		return windowsservice.ApplyResult{Requested: true}, setupFailed("service_start", primary)
	}
	_, err := setup(context.Background(), "fixture", h)
	if !errors.Is(err, primary) {
		t.Fatal("primary identity lost", err)
	}
	stage, _ := setupFailureDiagnostic(err)
	if stage != "service_start" {
		t.Fatalf("primary diagnostic replaced by later cleanup: %s", stage)
	}
}

type independentCancelOnClose struct {
	*lifecycleLeaseFixture
	cancel context.CancelFunc
}

func (s independentCancelOnClose) Close() error { s.cancel(); return s.lifecycleLeaseFixture.Close() }
func TestIndependentReceiptLeaseCancellationDuringCloseCannotSucceed(t *testing.T) {
	f := newLifecycleLeaseFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	open := func() (windowsservice.Layout, receiptStore, error) {
		l, s, e := f.open()
		if e != nil {
			return l, s, e
		}
		return l, independentCancelOnClose{f, cancel}, nil
	}
	got, err := withReceiptLease(ctx, open, func(installReceipt, receiptStore) (any, error) {
		return windowsservice.RestartResult{Outcome: "running-observed", Phase: "complete", StopAttempted: true, StartAttempted: true, RunningObserved: true, StateRetained: true}, nil
	})
	if !errors.Is(err, context.Canceled) || got.(windowsservice.RestartResult).Outcome == "running-observed" {
		t.Fatalf("late lease cancellation reported success: %#v, %v", got, err)
	}
}

type independentSetupCancelOnClose struct {
	setupJournal
	cancel context.CancelFunc
}

func (s independentSetupCancelOnClose) Close() error { s.cancel(); return s.setupJournal.Close() }
func TestIndependentSetupCancellationDuringCloseCannotSucceed(t *testing.T) {
	f := &setupFixture{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := f.operations()
	create := h.createJournal
	h.createJournal = func(l windowsservice.Layout) (setupJournal, error) {
		s, e := create(l)
		return independentSetupCancelOnClose{s, cancel}, e
	}
	_, err := setup(ctx, "fixture", h)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("setup cancellation during final release reported success: %v", err)
	}
}
