package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"localrmm/internal/windowsacceptance/setupgate"
	"localrmm/internal/windowsservice"
)

// Model the real production lease lifetime, not just individual receipt writes.
// Setup owns it from createJournal until its deferred Close, including hidden
// input and activation. This is the collision missed by the older fixture.
type currentCaptureJournal struct {
	*readSetupFixture
	leased *atomic.Bool
}

func (j currentCaptureJournal) Close() error {
	err := j.readSetupFixture.Close()
	j.leased.Store(false)
	return err
}

type currentCaptureCoordinator struct {
	fixture                              readSetupFixture
	leased                               atomic.Bool
	storeReads, snapshots                atomic.Int32
	inputEntered, inputRelease           chan struct{}
	activationEntered, activationRelease chan struct{}
	done                                 chan error
}

func newCurrentCaptureCoordinator(outcome string) *currentCaptureCoordinator {
	p := &currentCaptureCoordinator{inputEntered: make(chan struct{}), inputRelease: make(chan struct{}), done: make(chan error, 1)}
	h := freshReadAdminFixtureHooks(&p.fixture)
	h.setup.createJournal = func(windowsservice.Layout) (setupJournal, error) {
		if !p.leased.CompareAndSwap(false, true) {
			return nil, errPendingObservationFixture
		}
		return currentCaptureJournal{&p.fixture, &p.leased}, nil
	}
	h.setup.enroll = func(context.Context, windowsservice.Layout) error {
		close(p.inputEntered)
		<-p.inputRelease
		if !p.leased.Load() {
			return errPendingObservationFixture
		}
		if outcome == "cancel-hidden-input" {
			return errPendingObservationFixture
		}
		return nil
	}
	if outcome == "pending-transport" {
		p.activationEntered, p.activationRelease = make(chan struct{}), make(chan struct{})
		h.activateIdentity = func(context.Context, windowsservice.Receipt) error {
			close(p.activationEntered)
			<-p.activationRelease
			return errPendingObservationFixture
		}
	}
	update := h.updateReceipt
	h.updateReceipt = func(l windowsservice.Layout, previous, next []byte) error {
		if !p.leased.Load() {
			return errPendingObservationFixture
		}
		return update(l, previous, next)
	}
	go func() {
		_, err := setupReadObservation(context.Background(), "fixture", freshReadAdminSetupConsent(false), h)
		p.done <- err
	}()
	return p
}

func (p *currentCaptureCoordinator) storeRead() (installReceipt, error) {
	p.storeReads.Add(1)
	if p.leased.Load() {
		return installReceipt{}, errPendingObservationFixture
	}
	return decodeCurrentSetupReceipt(p.fixture.raw, p.fixture.record.Service.Layout)
}

func (p *currentCaptureCoordinator) snapshotRead(path string, maxBytes int64) ([]byte, error) {
	p.snapshots.Add(1)
	want := filepath.Join(p.fixture.record.Service.Layout.StateRoot+"-installer", "receipt.json")
	if !p.leased.Load() || path != want || maxBytes != 64<<10 || p.fixture.record.ReadSetup.Phase != "claim-started" {
		return nil, errPendingObservationFixture
	}
	return bytes.Clone(p.fixture.raw), nil
}

func currentCaptureCompletedInspector(_ context.Context, r windowsservice.Receipt) (windowsservice.Snapshot, error) {
	return windowsservice.Snapshot{Exists: true, ServiceSID: r.ServiceSID, Configuration: windowsservice.Configuration{StartType: 2}}, nil
}

func TestCurrentSetupPendingCaptureRespectsWholeTransactionLease(t *testing.T) {
	for _, outcome := range []string{"install-uninstall", "cancel-hidden-input", "pending-transport"} {
		t.Run(outcome, func(t *testing.T) {
			p := newCurrentCaptureCoordinator(outcome)
			<-p.inputEntered
			// Negative control: the previous full-store capture deterministically
			// fails while the worker is at its hidden-input prompt.
			_, oldErr := captureCurrentSetupPendingObservation(context.Background(), p.storeRead, pendingObservationInspector)
			layout := p.fixture.record.Service.Layout
			inspections := 0
			o, captureErr := captureCurrentSetupPendingObservation(context.Background(), func() (installReceipt, error) {
				return readCurrentSetupPendingReceipt(context.Background(), layout, p.snapshotRead)
			}, func(ctx context.Context, r windowsservice.Receipt) (windowsservice.Snapshot, error) {
				inspections++
				return pendingObservationInspector(ctx, r)
			})
			pollErr := o.inspectDisabled(context.Background())
			close(p.inputRelease)
			if outcome == "pending-transport" {
				<-p.activationEntered
				for range 32 {
					if err := o.inspectDisabled(context.Background()); err != nil {
						pollErr = err
					}
				}
				close(p.activationRelease)
			}
			workerErr := <-p.done
			if oldErr != setupgate.ErrGuard || captureErr != nil || pollErr != nil || p.snapshots.Load() != 1 || p.storeReads.Load() != 1 || p.leased.Load() || inspections < 2 {
				t.Fatal("capture reopened the live journal, skipped ownership, or lost lease exclusion")
			}
			if outcome == "install-uninstall" {
				if workerErr != nil || p.fixture.started != 1 || p.fixture.transitioned != 1 {
					t.Fatal("read-only snapshot interfered with the real coordinator")
				}
				if _, err := o.verifyCompleted(context.Background(), p.storeRead, currentCaptureCompletedInspector); err != nil {
					t.Fatal("completed authoritative binding rejected")
				}
			} else {
				if workerErr == nil || p.fixture.started != 0 || p.fixture.transitioned != 0 {
					t.Fatal("partial outcome started or reconfigured the service")
				}
				if o.verifyRetained(context.Background(), p.storeRead) != nil {
					t.Fatal("retained authoritative binding rejected")
				}
			}
			if p.storeReads.Load() != 2 {
				t.Fatal("terminal outcome skipped its mandatory full-store read")
			}
		})
	}
}

func currentCaptureReceipt() installReceipt {
	r := pendingObservationReceipt()
	r.Version = 12
	r.ReadSetup.Consent = freshReadAdminSetupConsent(false)
	return r
}

func TestCurrentSetupPendingSnapshotKeepsCanonicalAndProtectionFailuresClosed(t *testing.T) {
	r := currentCaptureReceipt()
	raw, _ := json.Marshal(r)
	for _, name := range []string{"read-or-close", "empty", "oversized", "whitespace", "unknown-field", "layout", "old-consent", "old-receipt", "canceled-read"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			read := func(path string, maxBytes int64) ([]byte, error) {
				if path != filepath.Join(r.Service.Layout.StateRoot+"-installer", "receipt.json") || maxBytes != 64<<10 {
					t.Fatal("snapshot read widened")
				}
				b := bytes.Clone(raw)
				switch name {
				case "read-or-close":
					return b, errPendingObservationFixture
				case "empty":
					return nil, nil
				case "oversized":
					return make([]byte, 64<<10+1), nil
				case "whitespace":
					return append(b, '\n'), nil
				case "unknown-field":
					return append([]byte(`{"unexpected":true,`), b[1:]...), nil
				case "layout", "old-consent", "old-receipt":
					var changed installReceipt
					_ = json.Unmarshal(b, &changed)
					if name == "layout" {
						changed.Service.Layout.StateRoot = "other"
					}
					if name == "old-consent" {
						changed.ReadSetup.Consent = historicalReadAdminV13Consent()
					}
					if name == "old-receipt" {
						changed.Version = 11
					}
					return json.Marshal(changed)
				case "canceled-read":
					cancel()
				}
				return b, nil
			}
			if _, err := readCurrentSetupPendingReceipt(ctx, r.Service.Layout, read); err != setupgate.ErrGuard {
				t.Fatal("invalid protected snapshot accepted")
			}
		})
	}
	for _, mutate := range []func(*installReceipt){
		func(r *installReceipt) { r.Prepared = false },
		func(r *installReceipt) { r.ReadSetup.Phase = "activation-started" },
		func(r *installReceipt) { r.ReadSetup.SenderBinding = strings.Repeat("a", 64) },
		func(r *installReceipt) { r.ReadSetup.Grants.MetadataScopeVerified = true },
	} {
		bad := currentCaptureReceipt()
		mutate(&bad)
		if _, err := captureCurrentSetupPendingObservation(context.Background(), func() (installReceipt, error) { return bad, nil }, pendingObservationInspector); err != setupgate.ErrGuard {
			t.Fatal("capture accepted a non-hidden-input phase")
		}
	}
}

func TestCurrentSetupPendingSnapshotCannotReplaceAuthoritativeCompletion(t *testing.T) {
	r := currentCaptureReceipt()
	o, err := captureCurrentSetupPendingObservation(context.Background(), func() (installReceipt, error) { return r, nil }, pendingObservationInspector)
	if err != nil {
		t.Fatal("fixture capture failed")
	}
	f := &readSetupFixture{}
	if _, err := setupReadObservation(context.Background(), "fixture", freshReadAdminSetupConsent(false), freshReadAdminFixtureHooks(f)); err != nil {
		t.Fatal("fixture completion failed")
	}
	for _, name := range []string{"read-or-close", "installation", "SID", "layout", "executable", "scope", "incomplete", "inspector", "startup", "absent"} {
		t.Run(name, func(t *testing.T) {
			reads := 0
			read := func() (installReceipt, error) {
				reads++
				var current installReceipt
				_ = json.Unmarshal(f.raw, &current)
				switch name {
				case "read-or-close":
					return current, errPendingObservationFixture
				case "installation":
					current.Service.InstallationID = "replacement"
				case "SID":
					current.Service.ServiceSID = "replacement"
				case "layout":
					current.Service.Layout.EnrollmentRoot = "replacement"
				case "executable":
					current.Service.ExecutableSHA256 = "replacement"
				case "scope":
					current.ReadSetup.Consent.Scopes = current.ReadSetup.Consent.Scopes[:20]
				case "incomplete":
					current.ReadSetup.Phase = "startup-transition-started"
				}
				return current, nil
			}
			inspect := func(ctx context.Context, r windowsservice.Receipt) (windowsservice.Snapshot, error) {
				s, _ := currentCaptureCompletedInspector(ctx, r)
				if name == "inspector" {
					return s, errPendingObservationFixture
				}
				if name == "startup" {
					s.Configuration.StartType = 4
				}
				if name == "absent" {
					s.Exists = false
				}
				return s, nil
			}
			if _, err := o.verifyCompleted(context.Background(), read, inspect); err != setupgate.ErrGuard || reads != 1 {
				t.Fatal("snapshot bypassed failed or changed final authority")
			}
		})
	}
}

func TestCurrentSetupControllerUsesProvisionalSnapshotAndFinalStore(t *testing.T) {
	raw, err := os.ReadFile("current_setup_acceptance_native_windows_test.go")
	if err != nil {
		t.Fatal("controller source unavailable")
	}
	s := string(raw)
	capture := strings.Index(s, "pending, e := captureCurrentSetupPendingObservation")
	if capture < 0 {
		t.Fatal("capture boundary missing")
	}
	end := strings.Index(s[capture:], `r.Checks["pendingStoppedDisabled"]`)
	if capture < 0 || end < 0 {
		t.Fatal("capture boundary missing")
	}
	block := s[capture : capture+end]
	if !strings.Contains(block, "readCurrentSetupPendingReceipt(ctx, l, windowsstate.ReadSetupReceiptSnapshot)") || strings.Contains(block, "currentSetupReceipt(l)") {
		t.Fatal("live capture reopened the exclusive journal")
	}
	for _, required := range []string{
		"pending.verifyCompleted(ctx, func() (installReceipt, error) { return currentSetupReceipt(l) }, windowsservice.InspectOwned)",
		"pending.verifyRetained(ctx, func() (installReceipt, error) { return currentSetupReceipt(l) })",
	} {
		if !strings.Contains(s, required) {
			t.Fatal("terminal outcome lost its authoritative full-store binding")
		}
	}
}
