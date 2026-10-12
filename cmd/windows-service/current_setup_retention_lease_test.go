package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"localrmm/internal/windowsacceptance/setupgate"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
)

// Wrap the real portable lifecycle lease. This fixture does not merely lock
// each receipt read: the worker owns its journal through delete-pending and
// absence polling, exactly as the production GUI coordinator does.
type currentRemovalLeaseFixture struct {
	receiptStore
	release func()
}

func (s currentRemovalLeaseFixture) Close() error {
	err := s.receiptStore.Close()
	s.release()
	return err
}

func TestCurrentRetentionDoesNotReopenGUIJournalDuringDeletionPending(t *testing.T) {
	f := newCurrentRetentionFixture(t)
	o, err := f.capture()
	if err != nil {
		t.Fatal("current baseline fixture failed")
	}
	lease := newLifecycleLeaseFixture(t)
	lease.layout, lease.raw = f.r.Service.Layout, retentionJSON(t, f.r)
	openRemoval := func() (windowsservice.Layout, receiptStore, error) {
		layout, store, err := lease.open()
		if err != nil {
			return layout, store, err
		}
		f.installerLeaseHeld = true
		return layout, currentRemovalLeaseFixture{store, func() { f.installerLeaseHeld = false }}, nil
	}
	stops, deletes, controllerAbsentChecks := 0, 0, 0
	heldSCM, absenceObserved, completed, captured := true, false, false, false
	assertOwned := func(r windowsservice.Receipt) error {
		if !lease.held.Load() || !f.installerLeaseHeld || r != f.r.Service {
			return errRetentionFixture
		}
		return nil
	}
	steps := setupWizardRemovalSteps{
		inspectOwned: func(_ context.Context, r windowsservice.Receipt) (windowsservice.Snapshot, error) {
			state := windowsservice.Running
			if stops > 0 {
				state = windowsservice.Stopped
			}
			return windowsservice.Snapshot{Exists: true, State: state, ServiceSID: r.ServiceSID}, assertOwned(r)
		},
		stop: func(_ context.Context, r windowsservice.Receipt) (windowsservice.ApplyResult, error) {
			stops++
			f.stopped = true
			return windowsservice.ApplyResult{Requested: true}, assertOwned(r)
		},
		remove: func(_ context.Context, r windowsservice.Receipt) (windowsservice.ApplyResult, error) {
			deletes++
			return windowsservice.ApplyResult{Requested: true, DeletePending: true, StateRetained: true}, assertOwned(r)
		},
		inspectRemoval: func(_ context.Context, r windowsservice.Receipt) (windowsservice.Snapshot, error) {
			if err := assertOwned(r); err != nil {
				return windowsservice.Snapshot{}, err
			}
			if heldSCM {
				return windowsservice.Snapshot{Exists: true, State: windowsservice.Stopped, ServiceSID: r.ServiceSID}, nil
			}
			absenceObserved = true
			return windowsservice.Snapshot{}, nil
		},
		pending: func(error) bool { return false },
		wait:    func(context.Context) error { return errRetentionFixture },
	}
	err = setupWizardUninstallWithLease(context.Background(), openRemoval, steps, func(text string) {
		if text == "Service deletion is pending. Waiting for SCM to confirm absence." {
			if !f.stopped || !heldSCM || !lease.held.Load() {
				t.Fatal("fixture missed held stopped deletion boundary")
			}
			// Negative control reproduces the old full-core read at this exact
			// boundary, not an unrelated fake open before removal starts.
			if _, err := o.verify(context.Background(), 9, f.open, f.stage, "retention-stopped-", true); err != setupgate.ErrGuard || f.blockedInstallerOpens != 1 {
				t.Fatal("old retention read did not reproduce exclusive journal collision")
			}
			opened := map[string]int{}
			openStopped := func(path string, options windowsstate.Options) (currentRetentionStore, error) {
				opened[path]++
				return f.open(path, options)
			}
			if o.captureStopped(context.Background(), 9, openStopped, f.stage) != nil || o.stopped == nil || o.proof.Verified || f.blockedInstallerOpens != 1 {
				t.Fatal("stopped capture reopened journal or prematurely produced final proof")
			}
			if opened[f.r.Service.Layout.StateRoot+"-installer"] != 0 {
				t.Fatal("stopped capture acquired GUI journal")
			}
			for _, spec := range currentRetentionCore(f.r)[1:] {
				if opened[spec.path] == 0 {
					t.Fatal("stopped immutable store was skipped")
				}
			}
			for _, spec := range currentRetentionGrantSpecs(f.r) {
				if opened[spec.path] == 0 {
					t.Fatal("stopped granted store was skipped")
				}
			}
			for _, path := range []string{f.r.Service.Layout.SenderRoot, filepath.Join(f.r.Service.Layout.StateRoot+"-event-history", "reports"), filepath.Join(f.r.Service.Layout.StateRoot+"-event-history", "consumption")} {
				if opened[path] == 0 {
					t.Fatal("stopped sender/history store was skipped")
				}
			}
			// Even populated stopped evidence cannot bypass a still-held final
			// authoritative read, and cannot publish the receipt proof.
			if o.verifyAbsent(context.Background(), 9, f.open, f.stage) != setupgate.ErrGuard || o.proof.Verified {
				t.Fatal("live journal was replaced with cached final authority")
			}
			captured, heldSCM = true, false
		}
		if text == setupRemovalCompletedText {
			if lease.held.Load() || f.installerLeaseHeld || !captured || !absenceObserved || o.proof.Verified {
				t.Fatal("removal completion or receipt proof preceded required release")
			}
			completed = true
		}
	})
	if err != nil || !completed || stops != 1 || deletes != 1 || lease.closes != 1 {
		t.Fatal("real removal coordinator failed or repeated a native effect")
	}
	// The controller independently observes absence after the GUI result.
	controllerAbsentChecks++
	if heldSCM || !absenceObserved {
		t.Fatal("controller absence was not established")
	}
	if o.verifyAbsent(context.Background(), 9, f.open, f.stage) != nil || !o.proof.Verified || o.proof.Validate() != nil || controllerAbsentChecks != 1 {
		t.Fatal("full final retained-state proof failed")
	}
	f.assertReleased(t)
}

func TestCurrentRetentionFinalInstallerAuthorityCannotBeReplacedByBaseline(t *testing.T) {
	for _, failure := range []string{"open", "entries", "read", "verify", "close", "changed-receipt", "changed-intent", "missing-receipt", "extra-entry"} {
		t.Run(failure, func(t *testing.T) {
			f := newCurrentRetentionFixture(t)
			o, err := f.capture()
			if err != nil {
				t.Fatal("current baseline fixture failed")
			}
			f.stopped, f.installerLeaseHeld = true, true
			if o.captureStopped(context.Background(), 9, f.open, f.stage) != nil || o.proof.Verified {
				t.Fatal("stopped fixture or provisional proof boundary failed")
			}
			f.installerLeaseHeld = false
			path := f.r.Service.Layout.StateRoot + "-installer"
			switch failure {
			case "changed-receipt":
				changed := f.r
				changed.Service.InstallationID = strings.Repeat("f", 32)
				f.files[path]["receipt.json"] = retentionJSON(t, changed)
			case "changed-intent":
				f.files[path]["intent.json"] = []byte(`{"changed":true}`)
			case "missing-receipt":
				delete(f.files[path], "receipt.json")
			case "extra-entry":
				f.files[path]["unexpected.json"] = []byte(`{}`)
			default:
				f.faultPath, f.fault = path, failure
			}
			if o.verifyAbsent(context.Background(), 9, f.open, f.stage) != setupgate.ErrGuard || o.proof.Verified {
				t.Fatal("cached installer baseline bypassed failed or changed final authority")
			}
			f.assertReleased(t)
		})
	}
}

func TestCurrentRetentionFinalStoppedBytesAndOriginalSequenceRemainRequired(t *testing.T) {
	for _, failure := range []string{"sender-advance", "history-change", "grant-change"} {
		t.Run(failure, func(t *testing.T) {
			f := newCurrentRetentionFixture(t)
			o, err := f.capture()
			if err != nil {
				t.Fatal("current baseline fixture failed")
			}
			f.stopped, f.installerLeaseHeld = true, true
			if o.captureStopped(context.Background(), 9, f.open, f.stage) != nil {
				t.Fatal("stopped fixture failed")
			}
			f.installerLeaseHeld = false
			switch failure {
			case "sender-advance":
				path := f.r.Service.Layout.SenderRoot
				f.files[path]["state.json"] = []byte(strings.Replace(string(f.files[path]["state.json"]), `"lastSequence":9`, `"lastSequence":10`, 1))
			case "history-change":
				f.files[filepath.Join(f.r.Service.Layout.StateRoot+"-event-history", "reports")]["reports.json"] = []byte(`{"changed":true}`)
			case "grant-change":
				f.files[f.r.Service.Layout.StateRoot+"-visible-volumes"]["consent.json"] = []byte(`{}`)
			}
			if o.verifyAbsent(context.Background(), 9, f.open, f.stage) != setupgate.ErrGuard || o.proof.Verified {
				t.Fatal("changed stopped bytes acquired final proof")
			}
			f.assertReleased(t)
		})
	}
}

func TestCurrentRetentionControllerKeepsQuiescenceAbsenceAndProofOrder(t *testing.T) {
	raw, err := os.ReadFile("current_setup_acceptance_native_windows_test.go")
	if err != nil {
		t.Fatal("controller source unavailable")
	}
	s := string(raw)
	last := -1
	for _, marker := range []string{"captureCurrentRetainedState(", `r.Checks["deletePendingObserved"] = true`, "retained.captureStopped(", `r.Stage = "uninstall-release"`, `r.Stage = "uninstall-finish"`, "if u.exit(ctx, 0) != nil", `r.Checks["serviceAbsent"] = true`, "retained.verifyAbsent(", "r.ReceiptProof = retained.proof", `r.Checks["receiptAndGrantsVerified"] = true`} {
		next := strings.Index(s, marker)
		if next <= last {
			t.Fatal("retention verification order changed")
		}
		last = next
	}
}
