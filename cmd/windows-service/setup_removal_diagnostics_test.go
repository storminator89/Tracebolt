package main

import (
	"context"
	"errors"
	"fmt"
	"localrmm/internal/windowsacceptance/setupgate"
	"localrmm/internal/windowsservice"
	"strings"
	"syscall"
	"testing"
)

func TestRemovalFailureEveryStepPreservesCauseAndMutationCounts(t *testing.T) {
	sentinel := errors.New("private error must not escape")
	for _, failure := range []string{"receipt", "owned", "state", "stop", "stop-observe", "stop-state", "stop-wait", "delete", "delete-result", "absence-inspect", "absence-owned", "absence-wait"} {
		t.Run(failure, func(t *testing.T) {
			stopped, deleted := false, false
			stopCalls, deleteCalls, ownedCalls := 0, 0, 0
			steps := setupWizardRemovalSteps{receipt: func() (windowsservice.Receipt, error) {
				if failure == "receipt" {
					return windowsservice.Receipt{}, sentinel
				}
				return windowsservice.Receipt{}, nil
			}, inspectOwned: func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
				ownedCalls++
				if ownedCalls == 1 && failure == "owned" || ownedCalls > 1 && !deleted && failure == "stop-observe" || deleted && failure == "absence-owned" {
					return windowsservice.Snapshot{}, sentinel
				}
				state := windowsservice.Running
				if stopped {
					state = windowsservice.Stopped
				}
				if failure == "state" || stopped && failure == "stop-state" {
					state = windowsservice.StartPending
				}
				if stopped && failure == "stop-wait" {
					state = windowsservice.StopPending
				}
				return windowsservice.Snapshot{Exists: true, State: state}, nil
			}, stop: func(context.Context, windowsservice.Receipt) (windowsservice.ApplyResult, error) {
				stopCalls++
				if failure == "stop" {
					return windowsservice.ApplyResult{}, sentinel
				}
				stopped = true
				return windowsservice.ApplyResult{Requested: true}, nil
			}, remove: func(context.Context, windowsservice.Receipt) (windowsservice.ApplyResult, error) {
				deleteCalls++
				if failure == "delete" {
					return windowsservice.ApplyResult{}, sentinel
				}
				deleted = true
				if failure == "delete-result" {
					return windowsservice.ApplyResult{}, nil
				}
				return windowsservice.ApplyResult{Requested: true, DeletePending: true, StateRetained: true}, nil
			}, inspect: func(context.Context) (windowsservice.Snapshot, error) {
				if failure == "absence-inspect" {
					return windowsservice.Snapshot{}, sentinel
				}
				return windowsservice.Snapshot{Exists: true}, nil
			}, pending: func(error) bool { return false }, wait: func(context.Context) error { return sentinel }}
			err := setupWizardUninstall(context.Background(), steps, func(string) {})
			r, ok := err.(*removalFailure)
			if !ok || r.step != failure {
				t.Fatalf("failure=%s step=%v", failure, r)
			}
			direct := failure == "receipt" || failure == "owned" || failure == "stop" || failure == "stop-observe" || failure == "delete"
			want := error(errSetupRemovalPending)
			if direct {
				want = sentinel
			}
			if !errors.Is(err, want) || r.original != want {
				t.Fatal("public cause changed")
			}
			if stopCalls > 1 || deleteCalls > 1 {
				t.Fatal("mutation repeated")
			}
			if (failure == "receipt" || failure == "owned" || failure == "state") && stopCalls != 0 {
				t.Fatal("stop crossed rejected ownership")
			}
			if strings.HasPrefix(failure, "stop") && deleteCalls != 0 {
				t.Fatal("delete crossed rejected stop")
			}
			text := setupRemovalFailureText(err) + "\r\n\r\n" + "The operation did not complete. Durable changes may exist; files, identity and state are retained. Inspect the retained state before any further action. This wizard will not retry or reset it."
			stage, reason, valid := setupgate.ParseRemovalFailure(text)
			if !valid || stage != "uninstall-failure-"+failure || reason != "failed" || strings.Contains(text, "private") {
				t.Fatal("finite failure lost or leaked")
			}
		})
	}
}
func TestRemovalFailureCancellationAndPrivateFormatting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	hit := func() error { t.Fatal("callback after cancellation"); return nil }
	s := setupWizardRemovalSteps{receipt: func() (windowsservice.Receipt, error) { return windowsservice.Receipt{}, hit() }, inspectOwned: func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
		return windowsservice.Snapshot{}, hit()
	}, inspect: func(context.Context) (windowsservice.Snapshot, error) { return windowsservice.Snapshot{}, hit() }, stop: func(context.Context, windowsservice.Receipt) (windowsservice.ApplyResult, error) {
		return windowsservice.ApplyResult{}, hit()
	}, remove: func(context.Context, windowsservice.Receipt) (windowsservice.ApplyResult, error) {
		return windowsservice.ApplyResult{}, hit()
	}, pending: func(error) bool { return false }, wait: func(context.Context) error { return hit() }}
	err := setupWizardUninstall(ctx, s, func(string) {})
	if !errors.Is(err, context.Canceled) || err.(*removalFailure).step != "context" || removalCause(err) != "canceled" {
		t.Fatal("cancellation changed")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		if strings.Contains(fmt.Sprintf(verb, err), "step:") {
			t.Fatal("wrapper metadata leaked")
		}
	}
}
func TestRemovalFailureCauseFiniteAndHostileSafe(t *testing.T) {
	for err, want := range map[error]string{context.Canceled: "canceled", context.DeadlineExceeded: "deadline", syscall.Errno(5): "access_denied", syscall.Errno(1061): "cannot_accept_control", syscall.Errno(1062): "not_active", syscall.Errno(1051): "dependent_services", syscall.Errno(1072): "delete_pending", syscall.Errno(99999): "failed", panicSetupDiagnostic{}: "failed"} {
		if got := removalCause(err); got != want {
			t.Fatalf("cause got %s want %s", got, want)
		}
	}
	if removalCause(&cycleSetupDiagnostic{}) != "failed" {
		t.Fatal("cycle did not fail closed")
	}
}

func TestRemovalSequencePendingStatesAndFailureWaitKeepSingleMutation(t *testing.T) {
	for _, cancelWait := range []bool{false, true} {
		stopCalls, deleteCalls, ownedCalls, inspectCalls, waitCalls := 0, 0, 0, 0, 0
		pendingError := errors.New("private deletion pending")
		var messages []string
		steps := setupWizardRemovalSteps{
			receipt: func() (windowsservice.Receipt, error) { return windowsservice.Receipt{}, nil },
			inspectOwned: func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
				ownedCalls++
				state := windowsservice.Stopped
				if ownedCalls == 1 {
					state = windowsservice.Running
				} else if ownedCalls < 4 {
					state = windowsservice.StopPending
				}
				return windowsservice.Snapshot{Exists: true, State: state}, nil
			},
			stop: func(context.Context, windowsservice.Receipt) (windowsservice.ApplyResult, error) {
				stopCalls++
				return windowsservice.ApplyResult{Requested: true}, nil
			},
			remove: func(context.Context, windowsservice.Receipt) (windowsservice.ApplyResult, error) {
				deleteCalls++
				return windowsservice.ApplyResult{Requested: true, DeletePending: true, StateRetained: true}, nil
			},
			inspect: func(context.Context) (windowsservice.Snapshot, error) {
				inspectCalls++
				if inspectCalls < 3 {
					return windowsservice.Snapshot{}, pendingError
				}
				return windowsservice.Snapshot{Exists: inspectCalls == 3}, nil
			},
			pending: func(err error) bool { return err == pendingError },
			wait: func(context.Context) error {
				waitCalls++
				if cancelWait && deleteCalls == 1 {
					return context.Canceled
				}
				return nil
			},
		}
		err := setupWizardUninstall(context.Background(), steps, func(s string) { messages = append(messages, s) })
		if stopCalls != 1 || deleteCalls != 1 {
			t.Fatal("stop/delete repeated")
		}
		if cancelWait {
			if !errors.Is(err, errSetupRemovalPending) || errors.Is(err, context.Canceled) || err.(*removalFailure).step != "absence-wait" || removalCause(err.(*removalFailure).detail) != "canceled" {
				t.Fatal("wait cause/public identity lost")
			}
			if strings.Contains(strings.Join(messages, " "), "Service removal confirmed") {
				t.Fatal("failed wait announced absence")
			}
		} else if err != nil || waitCalls != 5 || inspectCalls != 4 || !strings.Contains(messages[len(messages)-1], "Service removal confirmed") {
			t.Fatal("valid pending sequence changed")
		}
	}
}
