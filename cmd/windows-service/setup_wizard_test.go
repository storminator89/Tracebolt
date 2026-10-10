package main

import (
	"context"
	"errors"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowssetup"
	"reflect"
	"strings"
	"testing"
)

func TestSetupWizardInstallOrderingAndEveryBoundary(t *testing.T) {
	for _, fail := range []string{"", "validate", "preflight", "compatibility", "console", "provision", "install"} {
		var calls []string
		call := func(s string) error {
			calls = append(calls, s)
			if s == fail {
				return errors.New("private error must not be printed")
			}
			return nil
		}
		steps := setupWizardInstallSteps{validate: func([]byte) error { return call("validate") }, preflight: func(context.Context) error { return call("preflight") }, compatibility: func(context.Context, []byte) error { return call("compatibility") }, console: func() (func() error, error) {
			e := call("console")
			return func() error { return call("console-close") }, e
		}, provision: func(context.Context, []byte) (string, func() error, error) {
			e := call("provision")
			return "fixture", func() error { return call("pins-close") }, e
		}, install: func(context.Context, string) error { return call("install") }}
		err := setupWizardInstall(context.Background(), []byte("public-only"), steps, func(s string) {
			if strings.Contains(s, "private error") {
				t.Fatal("cause leaked")
			}
		})
		if (err == nil) != (fail == "") {
			t.Fatalf("wrong result at %s", fail)
		}
		if fail == "compatibility" && !errors.Is(err, windowssetup.ErrCompatibility) {
			t.Fatal("manager blocker lost")
		}
		order := []string{"validate", "preflight", "compatibility", "console", "provision", "install"}
		for i, name := range order {
			if i >= len(calls) {
				break
			}
			if calls[i] != name {
				break
			}
			if name == fail {
				for _, later := range calls[i+1:] {
					if later != "pins-close" && later != "console-close" {
						t.Fatalf("mutation after %s: %v", fail, calls)
					}
				}
				break
			}
		}
		if fail == "" && !reflect.DeepEqual(calls, append(order, "pins-close", "console-close")) {
			t.Fatal(calls)
		}
	}
}
func TestSetupWizardCanceledBeforeApplyIsInert(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	hit := func() error { calls++; return nil }
	s := setupWizardInstallSteps{validate: func([]byte) error { return hit() }, preflight: func(context.Context) error { return hit() }, compatibility: func(context.Context, []byte) error { return hit() }, console: func() (func() error, error) { hit(); return hit, nil }, provision: func(context.Context, []byte) (string, func() error, error) { hit(); return "fixture", hit, nil }, install: func(context.Context, string) error { return hit() }}
	if setupWizardInstall(ctx, nil, s, func(string) {}) == nil || calls != 0 {
		t.Fatal("canceled setup proceeded")
	}
}
func TestSetupWizardRemovalWaitsForExactOwnedStopAndAbsence(t *testing.T) {
	for _, fail := range []string{"", "receipt", "owned", "stop", "remove", "deleted-inspect", "wait"} {
		var calls []string
		state := windowsservice.Running
		deleted := false
		pending := false
		call := func(s string) error {
			calls = append(calls, s)
			if s == fail {
				return errors.New("fixture")
			}
			return nil
		}
		s := setupWizardRemovalSteps{pending: func(error) bool { return false }, receipt: func() (windowsservice.Receipt, error) { return windowsservice.Receipt{}, call("receipt") }, inspectOwned: func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
			return windowsservice.Snapshot{Exists: true, State: state}, call("owned")
		}, stop: func(context.Context, windowsservice.Receipt) (windowsservice.ApplyResult, error) {
			pending = true
			state = windowsservice.StopPending
			return windowsservice.ApplyResult{Requested: true}, call("stop")
		}, wait: func(context.Context) error { state = windowsservice.Stopped; pending = false; return call("wait") }, remove: func(context.Context, windowsservice.Receipt) (windowsservice.ApplyResult, error) {
			if pending || state != windowsservice.Stopped {
				t.Fatal("deleted pending service")
			}
			deleted = true
			return windowsservice.ApplyResult{Requested: true, DeletePending: true, StateRetained: true}, call("remove")
		}, inspectRemoval: func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
			return windowsservice.Snapshot{Exists: !deleted}, call("deleted-inspect")
		}}
		err := setupWizardUninstall(context.Background(), s, func(string) {})
		if (err == nil) != (fail == "") {
			t.Fatalf("wrong removal result %s %v %v", fail, err, calls)
		}
		if (fail == "receipt" || fail == "owned") && deleted {
			t.Fatal("foreign/unreadable state deleted")
		}
	}
}
func TestSetupWizardRejectsSecretAndHTTPBootstrap(t *testing.T) {
	for _, raw := range []string{"", `{"invitationSecret":"not-a-real-secret"}`, `{"profile":"http-test"}`} {
		if _, err := setupWizardPreview([]byte(raw)); err == nil {
			t.Fatal("unsafe input accepted")
		}
	}
	if validateReadSetupConsent(setupWizardConsent()) != nil {
		t.Fatal("wizard broadened coordinator consent")
	}
	for _, need := range []string{"unsigned", "five", "hidden", "Reinstallation remains blocked"} {
		if !strings.Contains(setupWizardDisclosure(), need) {
			t.Fatal("missing disclosure", need)
		}
	}
}

func TestSetupWizardDeletionPendingIsObservedNotRetried(t *testing.T) {
	pendingError := errors.New("typed deletion pending fixture")
	for _, timeout := range []bool{false, true} {
		deletes, waits, inspections := 0, 0, 0
		emittedPending := false
		s := setupWizardRemovalSteps{
			receipt: func() (windowsservice.Receipt, error) { return windowsservice.Receipt{}, nil },
			inspectOwned: func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
				return windowsservice.Snapshot{Exists: true, State: windowsservice.Stopped}, nil
			},
			stop: func(context.Context, windowsservice.Receipt) (windowsservice.ApplyResult, error) {
				t.Fatal("stop repeated for stopped service")
				return windowsservice.ApplyResult{}, nil
			},
			remove: func(context.Context, windowsservice.Receipt) (windowsservice.ApplyResult, error) {
				deletes++
				return windowsservice.ApplyResult{Requested: true, DeletePending: true, StateRetained: true}, nil
			},
			inspectRemoval: func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
				inspections++
				if !emittedPending {
					t.Fatal("pending result not reported before observation")
				}
				if inspections == 1 {
					return windowsservice.Snapshot{}, pendingError
				}
				return windowsservice.Snapshot{}, nil
			},
			pending: func(err error) bool { return err == pendingError },
			wait: func(context.Context) error {
				waits++
				if timeout {
					return context.DeadlineExceeded
				}
				return nil
			},
		}
		err := setupWizardUninstall(context.Background(), s, func(status string) {
			if status == "Service deletion is pending. Waiting for SCM to confirm absence." {
				emittedPending = true
			}
		})
		if (err != nil) != timeout || deletes != 1 || waits != 1 {
			t.Fatal("deletion retried or timeout misreported")
		}
	}
}
