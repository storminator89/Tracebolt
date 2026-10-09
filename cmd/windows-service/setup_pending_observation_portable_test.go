package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"localrmm/internal/windowsacceptance/setupgate"
	"localrmm/internal/windowsservice"
)

var errPendingObservationFixture = errors.New("private fixture path and native failure")

func pendingObservationReceipt() installReceipt {
	f := &readSetupFixture{}
	h := f.hooks()
	p, _ := h.setup.plan(context.Background())
	s, _ := h.setup.apply(context.Background(), p)
	return installReceipt{Version: 2, Prepared: true, Service: s, ReadSetup: &readSetupProgress{Consent: readSetupConsentFixture(), Phase: "claim-started"}}
}

func pendingObservationSnapshot(r windowsservice.Receipt) windowsservice.Snapshot {
	return windowsservice.Snapshot{Exists: true, ServiceSID: r.ServiceSID, State: windowsservice.Stopped, Configuration: windowsservice.Configuration{StartType: 4}}
}

func pendingObservationInspector(_ context.Context, r windowsservice.Receipt) (windowsservice.Snapshot, error) {
	return pendingObservationSnapshot(r), nil
}

func TestSetupPendingCaptureRejectsReadAndCloseFailuresBeforeInput(t *testing.T) {
	// The native reader includes Open, Read, canonical decoding and Close. Even
	// a populated record accompanied by its final Close error must not escape.
	for _, failure := range []string{"open", "read", "decode", "close"} {
		t.Run(failure, func(t *testing.T) {
			input, inspected := false, false
			read := func() (installReceipt, error) {
				if failure == "close" {
					return pendingObservationReceipt(), errPendingObservationFixture
				}
				return installReceipt{}, errPendingObservationFixture
			}
			o, err := captureSetupPendingObservation(context.Background(), read, func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
				inspected = true
				return windowsservice.Snapshot{}, nil
			})
			if err == nil {
				input = true
			}
			if err != setupgate.ErrGuard || input || inspected || o.inspect != nil {
				t.Fatal("receipt failure reached input or escaped as a usable observer")
			}
		})
	}
}

func TestSetupPendingCaptureRejectsUnpreparedOrUnapprovedReceipts(t *testing.T) {
	for _, mutate := range []func(*installReceipt){
		func(r *installReceipt) { r.Version = 1 },
		func(r *installReceipt) { r.Prepared = false },
		func(r *installReceipt) { r.Service.Version = 1 },
		func(r *installReceipt) { r.Service.Complete = false },
		func(r *installReceipt) { r.ReadSetup = nil },
		func(r *installReceipt) { r.ReadSetup.Consent.Acknowledged = false },
		func(r *installReceipt) { r.ReadSetup.Consent.Scopes = r.ReadSetup.Consent.Scopes[:4] },
	} {
		r := pendingObservationReceipt()
		mutate(&r)
		calls := 0
		_, err := captureSetupPendingObservation(context.Background(), func() (installReceipt, error) { return r, nil }, func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
			calls++
			return windowsservice.Snapshot{}, nil
		})
		if err != setupgate.ErrGuard || calls != 0 {
			t.Fatal("invalid staged receipt reached live inspection")
		}
	}
}

func TestSetupPendingObserverRetainsOriginalServiceAndDeepCopiedConsent(t *testing.T) {
	r := pendingObservationReceipt()
	originalService := r.Service
	originalConsent := readSetupConsentFixture()
	inspections := 0
	o, err := captureSetupPendingObservation(context.Background(), func() (installReceipt, error) { return r, nil }, func(_ context.Context, got windowsservice.Receipt) (windowsservice.Snapshot, error) {
		inspections++
		if got != originalService {
			t.Fatal("observation followed a changed receipt")
		}
		return pendingObservationSnapshot(got), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	r.Service.InstallationID = "replacement"
	r.ReadSetup.Consent.Scopes[0] = "unapproved"
	r.ReadSetup.Consent.Acknowledged = false
	if !reflect.DeepEqual(o.consent, originalConsent) || o.service != originalService {
		t.Fatal("captured binding shares mutable receipt state")
	}
	for range 3 {
		if o.inspectDisabled(context.Background()) != nil {
			t.Fatal("original immutable binding lost")
		}
	}
	if inspections != 4 {
		t.Fatal("active poll skipped live ownership inspection")
	}
}

func TestSetupPendingObserverRejectsInspectionFailuresAndChangedSnapshots(t *testing.T) {
	for name, mutate := range map[string]func(*windowsservice.Snapshot){
		"absent":    func(s *windowsservice.Snapshot) { s.Exists = false },
		"other-sid": func(s *windowsservice.Snapshot) { s.ServiceSID = "foreign" },
		"running":   func(s *windowsservice.Snapshot) { s.State = windowsservice.Running },
		"starting":  func(s *windowsservice.Snapshot) { s.State = windowsservice.StartPending },
		"stopping":  func(s *windowsservice.Snapshot) { s.State = windowsservice.StopPending },
		"automatic": func(s *windowsservice.Snapshot) { s.Configuration.StartType = 2 },
		"manual":    func(s *windowsservice.Snapshot) { s.Configuration.StartType = 3 },
		"inspector": nil,
	} {
		t.Run(name, func(t *testing.T) {
			r := pendingObservationReceipt()
			changed := false
			inspect := func(_ context.Context, got windowsservice.Receipt) (windowsservice.Snapshot, error) {
				s := pendingObservationSnapshot(got)
				if changed {
					if mutate == nil {
						// Exact native configuration, receipt, binary and ACL failures
						// all arrive through the authoritative owned inspector.
						return s, errPendingObservationFixture
					}
					mutate(&s)
				}
				return s, nil
			}
			o, err := captureSetupPendingObservation(context.Background(), func() (installReceipt, error) { return r, nil }, inspect)
			if err != nil {
				t.Fatal(err)
			}
			changed = true
			if o.inspectDisabled(context.Background()) != setupgate.ErrGuard {
				t.Fatal("changed service or inspection error accepted")
			}
			if o.verifyRetained(context.Background(), func() (installReceipt, error) { return r, nil }) != setupgate.ErrGuard {
				t.Fatal("valid retained receipt bypassed changed live service inspection")
			}
			if _, err := captureSetupPendingObservation(context.Background(), func() (installReceipt, error) { return r, nil }, inspect); err != setupgate.ErrGuard {
				t.Fatal("bad initial inspection permitted input")
			}
		})
	}
}

func TestSetupPendingObserverRequiresAuthoritativeFinalRead(t *testing.T) {
	r := pendingObservationReceipt()
	o, err := captureSetupPendingObservation(context.Background(), func() (installReceipt, error) { return r, nil }, pendingObservationInspector)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*installReceipt){
		"installer-version": func(r *installReceipt) { r.Version = 1 },
		"unprepared":        func(r *installReceipt) { r.Prepared = false },
		"incomplete":        func(r *installReceipt) { r.Service.Complete = false },
		"service":           func(r *installReceipt) { r.Service.InstallationID = "replacement" },
		"layout":            func(r *installReceipt) { r.Service.Layout.EnrollmentRoot = "other" },
		"binary":            func(r *installReceipt) { r.Service.ExecutableSHA256 = "changed" },
		"configuration":     func(r *installReceipt) { r.Service.ConfigurationSHA256 = "changed" },
		"automatic":         func(r *installReceipt) { r.Service.Version = 1 },
		"consent":           func(r *installReceipt) { r.ReadSetup.Consent.InsecureHTTPAcknowledged = true },
		"missing-progress":  func(r *installReceipt) { r.ReadSetup = nil },
		"corruption":        nil,
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			err := o.verifyRetained(context.Background(), func() (installReceipt, error) {
				calls++
				current := pendingObservationReceipt()
				if mutate == nil {
					return current, errPendingObservationFixture
				}
				mutate(&current)
				return current, nil
			})
			if err != setupgate.ErrGuard || calls != 1 {
				t.Fatal("durable changed/corrupt receipt bypassed by cached evidence")
			}
		})
	}
	if o.verifyRetained(context.Background(), nil) != setupgate.ErrGuard {
		t.Fatal("missing final durable reader accepted")
	}
	for _, phase := range []string{"claim-started", "activation-started"} {
		calls := 0
		if o.verifyRetained(context.Background(), func() (installReceipt, error) {
			calls++
			current := pendingObservationReceipt()
			current.ReadSetup.Phase = phase
			return current, nil
		}) != nil || calls != 1 {
			t.Fatal("legitimate phase update rejected or durable read skipped")
		}
	}
}

func TestSetupPendingObserverDependenciesAndCancellationFailClosed(t *testing.T) {
	read := func() (installReceipt, error) { return pendingObservationReceipt(), nil }
	if _, err := captureSetupPendingObservation(nil, read, pendingObservationInspector); err != setupgate.ErrGuard {
		t.Fatal("nil context accepted")
	}
	if _, err := captureSetupPendingObservation(context.Background(), nil, pendingObservationInspector); err != setupgate.ErrGuard {
		t.Fatal("nil reader accepted")
	}
	if _, err := captureSetupPendingObservation(context.Background(), read, nil); err != setupgate.ErrGuard {
		t.Fatal("nil inspector accepted")
	}
	var zero setupPendingObservation
	if zero.inspectDisabled(context.Background()) != setupgate.ErrGuard || zero.verifyRetained(context.Background(), read) != setupgate.ErrGuard {
		t.Fatal("uncaptured observer accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	if _, err := captureSetupPendingObservation(ctx, func() (installReceipt, error) { calls++; return read() }, pendingObservationInspector); err != setupgate.ErrGuard || calls != 0 {
		t.Fatal("canceled capture reached protected store")
	}
	o, err := captureSetupPendingObservation(context.Background(), read, pendingObservationInspector)
	if err != nil {
		t.Fatal(err)
	}
	if o.inspectDisabled(ctx) != setupgate.ErrGuard || o.verifyRetained(ctx, func() (installReceipt, error) { calls++; return read() }) != setupgate.ErrGuard || calls != 0 {
		t.Fatal("canceled observation or final read executed")
	}
	ctx, cancel = context.WithCancel(context.Background())
	if _, err := captureSetupPendingObservation(ctx, read, func(_ context.Context, r windowsservice.Receipt) (windowsservice.Snapshot, error) {
		cancel()
		return pendingObservationSnapshot(r), nil
	}); err != setupgate.ErrGuard {
		t.Fatal("cancellation during inspector accepted")
	}
}

// pendingCoordinator exercises the real portable setupReadObservation sequence.
// The fake store models native share=0/fail-immediately exclusion, while barriers
// force both overlap orders without sleeps, scheduler luck or Windows APIs.
type pendingCoordinator struct {
	fixture           readSetupFixture
	lock              sync.Mutex
	reads             atomic.Int32
	claimEntered      chan struct{}
	claimRelease      chan struct{}
	activationEntered chan struct{}
	activationRelease chan struct{}
	done              chan error
}

func newPendingCoordinator(holdActivation, stopAtActivation bool) *pendingCoordinator {
	p := &pendingCoordinator{claimEntered: make(chan struct{}), claimRelease: make(chan struct{}), done: make(chan error, 1)}
	if holdActivation {
		p.activationEntered, p.activationRelease = make(chan struct{}), make(chan struct{})
	}
	h := p.fixture.hooks()
	enroll, update := h.setup.enroll, h.updateReceipt
	h.setup.enroll = func(ctx context.Context, l windowsservice.Layout) error {
		if err := enroll(ctx, l); err != nil {
			return err
		}
		close(p.claimEntered)
		<-p.claimRelease
		return nil
	}
	h.updateReceipt = func(l windowsservice.Layout, previous, next []byte) error {
		if !p.lock.TryLock() {
			return errPendingObservationFixture
		}
		defer p.lock.Unlock()
		var r installReceipt
		if json.Unmarshal(next, &r) != nil {
			return errPendingObservationFixture
		}
		if r.ReadSetup.Phase == "activation-started" && p.activationEntered != nil {
			close(p.activationEntered)
			<-p.activationRelease
		}
		return update(l, previous, next)
	}
	if stopAtActivation {
		h.activateIdentity = func(context.Context, windowsservice.Receipt) error { return errPendingObservationFixture }
	}
	go func() {
		_, err := setupReadObservation(context.Background(), "fixture", readSetupConsentFixture(), h)
		p.done <- err
	}()
	return p
}

func (p *pendingCoordinator) readReceipt() (installReceipt, error) {
	return p.readReceiptWithBarrier(nil, nil)
}

func (p *pendingCoordinator) readReceiptWithBarrier(entered chan<- struct{}, release <-chan struct{}) (installReceipt, error) {
	p.reads.Add(1)
	if !p.lock.TryLock() {
		return installReceipt{}, errPendingObservationFixture
	}
	defer p.lock.Unlock()
	if entered != nil {
		close(entered)
		<-release
	}
	return p.fixture.record, nil
}

func TestSetupPendingRepeatedStoreReadsReproduceBothExclusiveCollisionOrders(t *testing.T) {
	t.Run("observer-owns-lock-worker-fails", func(t *testing.T) {
		p := newPendingCoordinator(false, false)
		<-p.claimEntered
		readEntered, readRelease, readDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
		go func() {
			// Reproduce the old setupReceipt observation's complete open/read/
			// close lifetime overlapping the worker's activation receipt save.
			_, err := p.readReceiptWithBarrier(readEntered, readRelease)
			readDone <- err
		}()
		<-readEntered
		close(p.claimRelease)
		err := <-p.done
		close(readRelease)
		readErr := <-readDone
		stage, _ := setupFailureDiagnostic(err)
		if err == nil || stage != "activation_record" || readErr != nil || p.reads.Load() != 1 || p.fixture.record.ReadSetup.Phase != "claim-started" || p.fixture.started != 0 || p.fixture.transitioned != 0 {
			t.Fatal("observer overlap did not reproduce fail-closed activation write failure")
		}
	})
	t.Run("worker-owns-lock-observer-fails", func(t *testing.T) {
		p := newPendingCoordinator(true, false)
		<-p.claimEntered
		close(p.claimRelease)
		<-p.activationEntered
		_, readErr := p.readReceipt()
		close(p.activationRelease)
		workerErr := <-p.done
		if readErr == nil || workerErr != nil || !completeReadSetup(p.fixture.record) || p.fixture.started != 1 {
			t.Fatal("worker overlap did not reproduce observer-only failure")
		}
	})
}

func TestSetupPendingPollingNeverOpensInstallerDuringRealCoordinatorPhaseWrite(t *testing.T) {
	p := newPendingCoordinator(true, true)
	<-p.claimEntered // Original claim-started record is stable before input.
	inspections := 0
	o, captureErr := captureSetupPendingObservation(context.Background(), p.readReceipt, func(_ context.Context, r windowsservice.Receipt) (windowsservice.Snapshot, error) {
		inspections++
		return pendingObservationSnapshot(r), nil
	})
	close(p.claimRelease)
	<-p.activationEntered // Writer keeps exclusive ownership throughout polling.
	var pollErr error
	for range 32 {
		if err := o.inspectDisabled(context.Background()); err != nil {
			pollErr = err
		}
	}
	activeReads := p.reads.Load()
	close(p.activationRelease)
	workerErr := <-p.done
	if captureErr != nil || pollErr != nil || activeReads != 1 || inspections != 33 {
		t.Fatal("active observer reopened the installer or skipped live service checks")
	}
	stage, _ := setupFailureDiagnostic(workerErr)
	if workerErr == nil || stage != "identity_activate" || p.fixture.record.ReadSetup.Phase != "activation-started" || p.fixture.started != 0 || p.fixture.transitioned != 0 {
		t.Fatal("observer interfered with activation write or test did not retain pending state")
	}
	if o.verifyRetained(context.Background(), p.readReceipt) != nil || p.reads.Load() != 2 || inspections != 34 {
		t.Fatal("quiescent verification did not require fresh durable receipt and SCM checks")
	}
}
