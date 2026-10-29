package windowscustomerflow

import (
	"bytes"
	"errors"
	"io/fs"
	"sync"
	"testing"
	"time"

	"localrmm/internal/windowsstate"
)

// This in-memory fake tests receipt coordination only; it does not test Windows
// ACLs, handles, durability, native services, endpoint identity or grants.
type fakeReceiptStore struct {
	mu                             sync.Mutex
	value                          []byte
	present, failAfter, panicAfter bool
	schemaOK                       bool
}

func (s *fakeReceiptStore) RequireInstallerSchema(names []string, lock, temp string, max int64) error {
	if !s.schemaOK || len(names) != 1 || names[0] != receiptName || lock != receiptLock || temp != receiptTemp || max != receiptLimit {
		return windowsstate.ErrPolicy
	}
	return nil
}
func (s *fakeReceiptStore) Read(string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.present {
		return nil, fs.ErrNotExist
	}
	return bytes.Clone(s.value), nil
}
func (s *fakeReceiptStore) CompareAndWrite(_ string, expected []byte, absent bool, next []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.present == absent || s.present && !bytes.Equal(s.value, expected) {
		return windowsstate.ErrCompare
	}
	s.value = bytes.Clone(next)
	s.present = true
	if s.panicAfter {
		panic("fixture backend panic after write")
	}
	if s.failAfter {
		return windowsstate.ErrStorage
	}
	return nil
}

type fixtureGuard struct{ calls, failAt int }

func fixedClock(now time.Time) func() time.Time { return func() time.Time { return now } }

// No-op fixture guards do not establish real durable authority or recovery.
func (*fixtureGuard) CheckReconciled([32]byte) error               { return nil }
func (*fixtureGuard) BeginWrite([32]byte, [32]byte, bool) error    { return nil }
func (*fixtureGuard) CompleteWrite([32]byte, [32]byte, bool) error { return nil }

type shiftingGuard struct {
	clock         *time.Time
	call, shiftAt int
	to            time.Time
}

func (g *shiftingGuard) Check() error {
	g.call++
	if g.call == g.shiftAt {
		*g.clock = g.to
	}
	return nil
}
func (*shiftingGuard) CheckReconciled([32]byte) error               { return nil }
func (*shiftingGuard) BeginWrite([32]byte, [32]byte, bool) error    { return nil }
func (*shiftingGuard) CompleteWrite([32]byte, [32]byte, bool) error { return nil }

func (g *fixtureGuard) Check() error {
	g.calls++
	if g.failAt > 0 && g.calls == g.failAt {
		return errors.New("fixture guard lost")
	}
	return nil
}

func TestReceiptCreateOnlyAndRestartFence(t *testing.T) {
	s, e, now := fixture(t)
	storage := &fakeReceiptStore{schemaOK: true}
	j, err := attach(storage)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = j.Read(); !errors.Is(err, ErrReceipt) {
		t.Fatal("uninitialized read accepted", err)
	}
	if _, _, err = j.Initialize(s.Binding, s.Consent, fixedClock(now), nil); err == nil {
		t.Fatal("missing fresh guard accepted")
	}
	initial, raw, err := j.Initialize(s.Binding, s.Consent, fixedClock(now), &fixtureGuard{})
	if err != nil || initial.Phase != Pending {
		t.Fatal("initialize", err)
	}
	if _, _, err = j.Initialize(s.Binding, s.Consent, fixedClock(now), &fixtureGuard{}); !errors.Is(err, ErrUncertain) {
		t.Fatal("existing receipt reinitialized", err)
	}
	started, next, err := j.Transition(raw, BeginActivation, e, fixedClock(now), &fixtureGuard{})
	if err != nil || started.Phase != ActivationStarted {
		t.Fatal("started fence", err)
	}
	// Simulate reopening the same retained protected state after an interruption.
	reopened, err := attach(storage)
	if err != nil {
		t.Fatal(err)
	}
	current, copyRaw, err := reopened.Read()
	if err != nil || current.Phase != ActivationStarted || !bytes.Equal(next, copyRaw) {
		t.Fatal("reopen", err)
	}
	if _, _, err = reopened.Transition(copyRaw, BeginActivation, e, fixedClock(now), &fixtureGuard{}); err == nil {
		t.Fatal("native activation rearmed after restart")
	}
	e.ApprovalCurrent = false
	e.IssuerCurrent = false
	failed, _, err := reopened.Transition(copyRaw, Interrupt, e, fixedClock(time.Unix(s.Binding.DeadlineAt+1, 0)), &fixtureGuard{})
	if err != nil || failed.Phase != Indeterminate {
		t.Fatal("uncertain outcome not retained", err)
	}
}

func TestReceiptCASConflictAndTamperFailClosed(t *testing.T) {
	s, e, now := fixture(t)
	storage := &fakeReceiptStore{schemaOK: true}
	j, _ := attach(storage)
	_, raw, err := j.Initialize(s.Binding, s.Consent, fixedClock(now), &fixtureGuard{})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := j.Transition(raw, BeginActivation, e, fixedClock(now), &fixtureGuard{})
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	wins, conflicts := 0, 0
	for err := range results {
		if err == nil {
			wins++
		} else if errors.Is(err, ErrUncertain) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatalf("wins=%d conflicts=%d", wins, conflicts)
	}
	if _, _, err = j.Transition(append(bytes.Clone(raw), []byte(` {}`)...), BeginActivation, e, fixedClock(now), &fixtureGuard{}); !errors.Is(err, ErrReceipt) {
		t.Fatal("noncanonical receipt accepted", err)
	}
	bad := &fakeReceiptStore{}
	if _, err = attach(bad); !errors.Is(err, ErrReceipt) {
		t.Fatal("unprotected schema accepted", err)
	}
}

func TestReceiptUncertainWritesNeverAuthorizeHostWork(t *testing.T) {
	s, e, now := fixture(t)
	for _, scenario := range []string{"postguard", "write"} {
		t.Run(scenario, func(t *testing.T) {
			storage := &fakeReceiptStore{schemaOK: true}
			j, _ := attach(storage)
			_, raw, err := j.Initialize(s.Binding, s.Consent, fixedClock(now), &fixtureGuard{})
			if err != nil {
				t.Fatal(err)
			}
			guard := &fixtureGuard{}
			if scenario == "postguard" {
				guard.failAt = 4
			} else {
				storage.failAfter = true
			}
			_, _, err = j.Transition(raw, BeginActivation, e, fixedClock(now), guard)
			if err == nil {
				t.Fatal("uncertain write reported as success")
			}
			if !errors.Is(err, ErrUncertain) {
				t.Fatal("uncertain write not identified", err)
			}
			storage.failAfter = false
			state, retained, err := j.Read()
			if err != nil || state.Phase != ActivationStarted {
				t.Fatal("started fence not retained", err)
			}
			if _, _, err = j.Transition(raw, BeginActivation, e, fixedClock(now), &fixtureGuard{}); !errors.Is(err, ErrUncertain) {
				t.Fatal("uncertain write retried", err)
			}
			if _, _, err = j.Transition(retained, BeginActivation, e, fixedClock(now), &fixtureGuard{}); err == nil {
				t.Fatal("started fence rearmed")
			}
		})
	}
}

func TestReceiptRechecksClockAtAndAfterCAS(t *testing.T) {
	s, e, start := fixture(t)
	for _, operation := range []string{"initialize", "transition"} {
		for _, stage := range []string{"before", "after"} {
			for _, movement := range []string{"expired", "backwards"} {
				t.Run(operation+"/"+stage+"/"+movement, func(t *testing.T) {
					storage := &fakeReceiptStore{schemaOK: true}
					j, _ := attach(storage)
					now := start
					var raw []byte
					if operation == "transition" {
						_, raw, _ = j.Initialize(s.Binding, s.Consent, func() time.Time { return now }, &fixtureGuard{})
					}
					to := time.Unix(s.Binding.DeadlineAt, 0)
					if movement == "backwards" {
						to = start.Add(-time.Second)
					}
					at := 2
					if stage == "after" {
						at = 4
						if operation == "initialize" {
							at = 3
						}
					}
					guard := &shiftingGuard{clock: &now, shiftAt: at, to: to}
					var err error
					if operation == "initialize" {
						_, _, err = j.Initialize(s.Binding, s.Consent, func() time.Time { return now }, guard)
					} else {
						_, _, err = j.Transition(raw, BeginActivation, e, func() time.Time { return now }, guard)
					}
					if err == nil {
						t.Fatal("stale authority accepted")
					}
					if stage == "after" && !errors.Is(err, ErrUncertain) {
						t.Fatal("post-CAS uncertainty not reported", err)
					}
					if operation == "initialize" && stage == "before" {
						if _, err = storage.Read(receiptName); !errors.Is(err, fs.ErrNotExist) {
							t.Fatal("expired initialization wrote", err)
						}
					}
					if operation == "transition" && stage == "before" {
						state, _, err := j.Read()
						if err != nil || state.Phase != Pending {
							t.Fatal("expired transition wrote", err)
						}
					}
					if stage == "after" {
						state, _, err := j.Read()
						if err != nil || (operation == "transition" && state.Phase != ActivationStarted) || (operation == "initialize" && state.Phase != Pending) {
							t.Fatal("uncertain persisted state lost", err)
						}
					}
				})
			}
		}
	}
}

// fixtureFence models a separate durable fence shared across an artificial
// restart. It does not demonstrate real Windows persistence, ACLs or recovery.
type fixtureFence struct {
	settled, pending        [32]byte
	present, unresolved     bool
	checks, failAt, panicAt int
}

func (g *fixtureFence) Check() error {
	g.checks++
	if g.checks == g.panicAt {
		panic("fixture guard panic")
	}
	if g.checks == g.failAt {
		return errors.New("fixture guard lost")
	}
	return nil
}
func (g *fixtureFence) CheckReconciled(hash [32]byte) error {
	if g.unresolved || !g.present || g.settled != hash {
		return errors.New("unreconciled fixture")
	}
	return nil
}
func (g *fixtureFence) BeginWrite(old, next [32]byte, absent bool) error {
	if g.unresolved || absent == g.present || (!absent && old != g.settled) {
		return errors.New("unreconciled fixture")
	}
	g.pending = next
	g.unresolved = true
	return nil
}

// resolve models an independently invoked recovery decision, not a method the
// Journal may call. Real recovery must verify durable and native evidence.
func (g *fixtureFence) resolve() {
	g.settled = g.pending
	g.present = true
	g.unresolved = false
}

func TestSuccessfulWriteStillNeedsIndependentReconciliation(t *testing.T) {
	initial, e, now := fixture(t)
	store := &fakeReceiptStore{schemaOK: true}
	j, _ := attach(store)
	guard := &fixtureFence{}
	_, raw, err := j.Initialize(initial.Binding, initial.Consent, fixedClock(now), guard)
	if err != nil || !guard.unresolved {
		t.Fatal("fresh write not fenced", err)
	}
	if _, _, err = j.Transition(raw, BeginActivation, e, fixedClock(now), guard); !errors.Is(err, ErrReceipt) {
		t.Fatal("unreconciled successful write accepted", err)
	}
	// A separate owner explicitly reconciles; this test does not implement that
	// owner's protected storage or actual native evidence verification.
	guard.resolve()
	_, next, err := j.Transition(raw, BeginActivation, e, fixedClock(now), guard)
	if err != nil || !guard.unresolved {
		t.Fatal("started write not fenced", err)
	}
	if _, _, err = j.Transition(next, FinishActivation, e, fixedClock(now), guard); !errors.Is(err, ErrReceipt) {
		t.Fatal("native outcome advanced without reconciliation", err)
	}
}

func TestUncertainReceiptNeedsExternalReconciliationAfterRestart(t *testing.T) {
	for _, target := range []string{"initialize", "finish-activation", "finish-grants", "finish-startup"} {
		for _, mode := range []string{"guard-error", "guard-panic", "backend-panic"} {
			t.Run(target+"/"+mode, func(t *testing.T) {
				initial, e, now := fixture(t)
				store := &fakeReceiptStore{schemaOK: true}
				j, _ := attach(store)
				guard := &fixtureFence{}
				var raw []byte
				if target != "initialize" {
					_, raw, _ = j.Initialize(initial.Binding, initial.Consent, fixedClock(now), guard)
					guard.resolve()
					advance := func(a Action) {
						t.Helper()
						guard.checks = 0
						var err error
						_, raw, err = j.Transition(raw, a, e, fixedClock(now), guard)
						if err != nil {
							t.Fatalf("setup %s: %v", a, err)
						}
						guard.resolve()
					}
					advance(BeginActivation)
					if target == "finish-grants" || target == "finish-startup" {
						advance(FinishActivation)
						advance(BeginGrants)
					}
					if target == "finish-startup" {
						advance(FinishGrants)
						advance(BeginStartup)
					}
				}
				guard.checks = 0
				failAt := 4
				if target == "initialize" {
					failAt = 3
				}
				if mode == "guard-error" {
					guard.failAt = failAt
				} else if mode == "guard-panic" {
					guard.panicAt = failAt
				} else {
					store.panicAfter = true
				}
				var err error
				switch target {
				case "initialize":
					_, _, err = j.Initialize(initial.Binding, initial.Consent, fixedClock(now), guard)
				case "finish-activation":
					_, _, err = j.Transition(raw, FinishActivation, e, fixedClock(now), guard)
				case "finish-grants":
					_, _, err = j.Transition(raw, FinishGrants, e, fixedClock(now), guard)
				case "finish-startup":
					_, _, err = j.Transition(raw, FinishStartup, e, fixedClock(now), guard)
				}
				if !errors.Is(err, ErrUncertain) || !guard.unresolved {
					t.Fatal("post-CAS uncertainty not fenced", err)
				}
				// Read after restart returns structural data, not proof of completion.
				reopened, _ := attach(store)
				state, retained, err := reopened.Read()
				if err != nil {
					t.Fatal(err)
				}
				want, next := Pending, BeginActivation
				switch target {
				case "finish-activation":
					want, next = IdentityActive, BeginGrants
				case "finish-grants":
					want, next = GrantsVerified, BeginStartup
				case "finish-startup":
					want, next = Completed, BeginActivation
				}
				if state.Phase != want {
					t.Fatalf("unexpected persisted phase %s", state.Phase)
				}
				guard.checks = 0
				guard.failAt = 0
				guard.panicAt = 0
				store.panicAfter = false
				if _, _, err = reopened.Transition(retained, next, e, fixedClock(now), guard); !errors.Is(err, ErrReceipt) {
					t.Fatal("unreconciled receipt accepted", err)
				}
				_, unchanged, err := reopened.Read()
				if err != nil || !bytes.Equal(unchanged, retained) {
					t.Fatal("unreconciled state changed", err)
				}
			})
		}
	}
}
