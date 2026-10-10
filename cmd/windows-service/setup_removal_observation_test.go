package main

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"testing"

	"localrmm/internal/windowsservice"
)

func TestSetupRemovalUsesReceiptBoundObservationOnlyAfterDelete(t *testing.T) {
	for _, mode := range []string{"absent", "present", "foreign", "access", "pending", "timeout", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			receipt := windowsservice.Receipt{InstallationID: "fixture-owned-installation"}
			deleted, completed := false, false
			owned, deletes, observations, waits := 0, 0, 0, 0
			pending := errors.New("typed pending")
			denied := errors.New("access denied")
			s := setupWizardRemovalSteps{
				receipt: func() (windowsservice.Receipt, error) { return receipt, nil },
				inspectOwned: func(_ context.Context, r windowsservice.Receipt) (windowsservice.Snapshot, error) {
					if deleted || r != receipt {
						t.Fatal("active SID inspection crossed deletion or receipt changed")
					}
					owned++
					return windowsservice.Snapshot{Exists: true, State: windowsservice.Stopped}, nil
				},
				stop: func(context.Context, windowsservice.Receipt) (windowsservice.ApplyResult, error) {
					t.Fatal("stopped service stopped again")
					return windowsservice.ApplyResult{}, nil
				},
				remove: func(_ context.Context, r windowsservice.Receipt) (windowsservice.ApplyResult, error) {
					if r != receipt || deleted || owned != 1 {
						t.Fatal("delete ownership/order changed")
					}
					deleted = true
					deletes++
					return windowsservice.ApplyResult{Requested: true, DeletePending: true, StateRetained: true}, nil
				},
				inspectRemoval: func(_ context.Context, r windowsservice.Receipt) (windowsservice.Snapshot, error) {
					if !deleted || r != receipt {
						t.Fatal("removal observation outside successful delete or receipt changed")
					}
					observations++
					if mode == "access" {
						return windowsservice.Snapshot{}, denied
					}
					if mode == "foreign" {
						return windowsservice.Snapshot{Exists: true, State: windowsservice.Running}, nil
					}
					if mode == "pending" && observations == 1 {
						return windowsservice.Snapshot{}, pending
					}
					if (mode == "present" && observations == 1) || mode == "timeout" || mode == "canceled" {
						return windowsservice.Snapshot{Exists: true, State: windowsservice.Stopped}, nil
					}
					return windowsservice.Snapshot{}, nil
				},
				pending: func(err error) bool { return err == pending },
				wait: func(context.Context) error {
					waits++
					if mode == "timeout" {
						return context.DeadlineExceeded
					}
					if mode == "canceled" {
						return context.Canceled
					}
					return nil
				},
			}
			err := setupWizardUninstall(context.Background(), s, func(text string) {
				if text == "Service removal confirmed. Executable, public bootstrap and all private state remain; manager trust was not revoked. Reinstallation remains blocked." {
					completed = true
				}
			})
			success := mode == "absent" || mode == "present" || mode == "pending"
			if (err == nil) != success || completed != success || deletes != 1 || owned != 1 {
				t.Fatal("removal result or exactly-once ownership changed")
			}
			if mode == "absent" && waits != 0 || mode != "absent" && success && (waits != 1 || observations != 2) {
				t.Fatal("absence/presence observation sequence changed")
			}
			if (mode == "foreign" || mode == "access") && waits != 0 {
				t.Fatal("invalid observation treated as pending")
			}
		})
	}
}

type removalPendingClaim struct{}

func (removalPendingClaim) Error() string { panic("private error text") }
func (removalPendingClaim) Is(error) bool { return true }

type removalPendingCycle struct{}

func (*removalPendingCycle) Error() string   { panic("private error text") }
func (e *removalPendingCycle) Unwrap() error { return e }

type removalPendingPanic struct{}

func (removalPendingPanic) Error() string { panic("private error text") }
func (removalPendingPanic) Unwrap() error { panic("private unwrap") }

func TestSetupRemovalPendingRejectsMixedAndUntrustedCauses(t *testing.T) {
	pending := syscall.Errno(1072)
	if !setupRemovalPending(pending) || !setupRemovalPending(fmt.Errorf("bounded wrapper: %w", pending)) {
		t.Fatal("unambiguous native pending rejected")
	}
	for _, err := range []error{nil, syscall.Errno(5), context.Canceled, errors.Join(pending, syscall.Errno(5)), errors.Join(pending, context.Canceled), errors.Join(pending, context.DeadlineExceeded), errors.Join(pending), fmt.Errorf("wrapper: %w", errors.Join(pending, errors.New("close failed"))), removalPendingClaim{}, &removalPendingCycle{}, removalPendingPanic{}} {
		if setupRemovalPending(err) {
			t.Fatal("mixed or untrusted cause became retryable")
		}
	}
}
