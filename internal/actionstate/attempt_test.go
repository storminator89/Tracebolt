//go:build linux

package actionstate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"localrmm/internal/actionpermit"
)

func beginFixture(t *testing.T) (*State, string, *Attempt, Status) {
	t.Helper()
	s, dir := fixture(t)
	st, a, err := s.Begin(context.Background(), signed(t, permit(t, 1)), testNow)
	if err != nil || a == nil || st.Phase != Admitted {
		t.Fatalf("begin: %+v %v %v", st, a, err)
	}
	return s, dir, a, st
}

func dispatchFixture(t *testing.T) (*State, string, *Attempt, Status) {
	t.Helper()
	s, dir, a, original := beginFixture(t)
	st, err := a.MarkDispatching(context.Background(), testNow.Add(time.Second))
	if err != nil || st.Phase != Dispatching {
		t.Fatalf("dispatch: %+v %v", st, err)
	}
	return s, dir, a, original
}

func assertOriginal(t *testing.T, got, original Status) {
	t.Helper()
	if got.Permit != original.Permit || got.EnvelopeDigest != original.EnvelopeDigest || got.ConsumedAt != original.ConsumedAt {
		t.Fatal("transition changed original signed metadata or consumption", got, original)
	}
}

func TestFreshBeginOnlyAndConcurrentCopies(t *testing.T) {
	s, dir := fixture(t)
	raw := signed(t, permit(t, 1))
	copyState := *s
	var issued atomic.Int32
	var winner *Attempt
	var winnerMu sync.Mutex
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, a, err := copyState.Begin(context.Background(), raw, testNow)
			if err != nil || got.Phase != Admitted {
				t.Errorf("begin: %+v %v", got, err)
			}
			if a != nil {
				issued.Add(1)
				winnerMu.Lock()
				winner = a
				winnerMu.Unlock()
			}
		}()
	}
	wg.Wait()
	if issued.Load() != 1 || len(s.inner.record.Jobs) != 1 {
		t.Fatal("Begin did not issue exactly one ephemeral attempt")
	}
	before := read(t, filepath.Join(dir, stateName))
	for _, now := range []time.Time{testNow.Add(-time.Hour), testNow.Add(time.Hour), {}} {
		_, a, err := s.Begin(context.Background(), raw, now)
		if err != nil || a != nil {
			t.Fatal("duplicate returned attempt", a, err)
		}
	}
	if !bytes.Equal(before, read(t, filepath.Join(dir, stateName))) {
		t.Fatal("duplicate rewrote state")
	}
	copyAttempt := *winner
	var dispatched atomic.Int32
	for i := range 32 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a := winner
			if i%2 != 0 {
				a = &copyAttempt
			}
			_, err := a.MarkDispatching(context.Background(), testNow)
			if err == nil {
				dispatched.Add(1)
			} else if !errors.Is(err, ErrAttempt) {
				t.Errorf("dispatch: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if dispatched.Load() != 1 {
		t.Fatal("copied attempt dispatched more than once")
	}
	var completed atomic.Int32
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := copyAttempt.Complete(context.Background(), OutcomeCompleted, ObservedUnknown, testNow)
			if err == nil {
				completed.Add(1)
			} else if !errors.Is(err, ErrAttempt) {
				t.Errorf("complete: %v", err)
			}
		}()
	}
	wg.Wait()
	if completed.Load() != 1 {
		t.Fatal("copied attempt completed more than once")
	}
	if _, a, err := s.Begin(context.Background(), signed(t, permit(t, 2)), testNow); err != nil || a == nil {
		t.Fatal("completion did not allow next sequence", err)
	}
	_, err := winner.NotStarted(context.Background(), ReasonCanceled, testNow)
	requireErr(t, err, ErrAttempt)
}

func TestAttemptCannotComeFromLegacyStatusOrZeroValue(t *testing.T) {
	s, dir := fixture(t)
	raw := signed(t, permit(t, 1))
	st, err := s.Admit(context.Background(), raw, testNow)
	if err != nil {
		t.Fatal(err)
	}
	before := read(t, filepath.Join(dir, stateName))
	got, a, err := s.Begin(context.Background(), raw, testNow)
	if err != nil || a != nil || got != st {
		t.Fatal("legacy admission gained capability", got, a, err)
	}
	if !bytes.Equal(before, read(t, filepath.Join(dir, stateName))) || s.inner.record.Version != Version {
		t.Fatal("reading old admission migrated it")
	}
	for _, invalid := range []*Attempt{nil, {}, {inner: &attempt{owner: s.inner, index: 0}}} {
		_, err := invalid.MarkDispatching(context.Background(), testNow)
		requireErr(t, err, ErrAttempt)
		_, err = invalid.NotStarted(context.Background(), ReasonCanceled, testNow)
		requireErr(t, err, ErrAttempt)
		_, err = invalid.Complete(context.Background(), OutcomeCompleted, ObservedActive, testNow)
		requireErr(t, err, ErrAttempt)
	}
}

func TestAttemptPhasesResultsAndImmutability(t *testing.T) {
	for _, observed := range []ObservedState{ObservedActive, ObservedInactive, ObservedFailed, ObservedUnknown} {
		t.Run(string(observed), func(t *testing.T) {
			s, dir, a, original := dispatchFixture(t)
			// Original start expiry never truncates an already invoked operation.
			finished := testNow.Add(time.Hour)
			st, err := a.Complete(context.Background(), OutcomeCompleted, observed, finished)
			if err != nil || st.Phase != OperationCompleted || st.Outcome != OutcomeCompleted || st.ObservedState != observed || st.TransitionAt != finished || st.DispatchAt != testNow.Add(time.Second) {
				t.Fatal("result", st, err)
			}
			assertOriginal(t, st, original)
			_ = s.Close()
			s, err = Open(context.Background(), dir, verifier(t))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			got, token, err := s.Begin(context.Background(), signed(t, original.Permit), testNow)
			if err != nil || token != nil || got != st {
				t.Fatal("completed duplicate changed", got, token, err)
			}
		})
	}
	for _, reason := range []NotStartedReason{ReasonCanceled, ReasonExpired, ReasonPolicyChanged, ReasonPreflight, ReasonInactive} {
		for _, dispatch := range []bool{false, true} {
			t.Run(string(reason)+map[bool]string{false: "-admitted", true: "-dispatching"}[dispatch], func(t *testing.T) {
				s, _, a, original := beginFixture(t)
				if dispatch {
					if _, err := a.MarkDispatching(context.Background(), testNow); err != nil {
						t.Fatal(err)
					}
				}
				st, err := a.NotStarted(context.Background(), reason, testNow.Add(time.Second))
				if err != nil || st.Phase != NotStarted || st.Reason != reason || st.Outcome != "" || st.ObservedState != "" {
					t.Fatal(st, err)
				}
				assertOriginal(t, st, original)
				if _, a, err := s.Begin(context.Background(), signed(t, permit(t, 2)), testNow.Add(time.Second)); err != nil || a == nil {
					t.Fatal("not-started did not release later sequence", err)
				}
			})
		}
	}
}

func TestInvokedUnknownAlwaysBlocksAndCannotBecomeNotStarted(t *testing.T) {
	for _, observed := range []ObservedState{ObservedActive, ObservedInactive, ObservedFailed, ObservedUnknown} {
		t.Run(string(observed), func(t *testing.T) {
			s, dir, a, original := dispatchFixture(t)
			st, err := a.Complete(context.Background(), OutcomeUnknown, observed, testNow.Add(2*time.Second))
			if err != nil || st.Phase != NeedsIntervention || st.Outcome != OutcomeUnknown {
				t.Fatal(st, err)
			}
			assertOriginal(t, st, original)
			_, err = a.NotStarted(context.Background(), ReasonCanceled, testNow.Add(2*time.Second))
			requireErr(t, err, ErrAttempt)
			_, _, err = s.Begin(context.Background(), signed(t, permit(t, 2)), testNow.Add(2*time.Second))
			requireErr(t, err, ErrBusy)
			_ = s.Close()
			s, err = Open(context.Background(), dir, verifier(t))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			got, err := s.Status(context.Background(), original.Permit.JobID)
			if err != nil || got != st {
				t.Fatal("uncertainty changed on reopen", got, err)
			}
		})
	}
}

func TestCrashAtEveryRunnerPhase(t *testing.T) {
	for _, phase := range []string{Admitted, Dispatching, NotStarted, OperationCompleted, NeedsIntervention} {
		t.Run(phase, func(t *testing.T) {
			s, dir, a, original := beginFixture(t)
			ctx := context.Background()
			if phase != Admitted && phase != NotStarted {
				if _, err := a.MarkDispatching(ctx, testNow.Add(time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			switch phase {
			case NotStarted:
				_, _ = a.NotStarted(ctx, ReasonPreflight, testNow.Add(2*time.Second))
			case OperationCompleted:
				_, _ = a.Complete(ctx, OutcomeCompleted, ObservedInactive, testNow.Add(2*time.Second))
			case NeedsIntervention:
				_, _ = a.Complete(ctx, OutcomeUnknown, ObservedUnknown, testNow.Add(2*time.Second))
			}
			before, err := s.Status(ctx, original.Permit.JobID)
			if err != nil || before.Phase != phase {
				t.Fatal(before, err)
			}
			_ = s.Close()
			s, err = Open(ctx, dir, verifier(t))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			got, token, err := s.Begin(ctx, signed(t, original.Permit), testNow)
			if err != nil || token != nil {
				t.Fatal("recovery issued attempt", token, err)
			}
			assertOriginal(t, got, original)
			if got.TransitionAt != before.TransitionAt || got.DispatchAt != before.DispatchAt {
				t.Fatal("recovery invented clock metadata")
			}
			if phase == Admitted || phase == Dispatching {
				if got.Phase != NeedsIntervention || got.Outcome != OutcomeUnknown || got.ObservedState != ObservedUnknown {
					t.Fatal("crash did not retain uncertainty", got)
				}
			} else if got != before {
				t.Fatal("terminal outcome changed")
			}
			if got.Phase == NeedsIntervention {
				_, token, err = s.Begin(ctx, signed(t, permit(t, 2)), testNow.Add(3*time.Second))
				requireErr(t, err, ErrBusy)
				if token != nil {
					t.Fatal("crash allowed a new attempt")
				}
			}
			_, err = a.MarkDispatching(ctx, testNow.Add(3*time.Second))
			requireErr(t, err, ErrClosed)
		})
	}
}

func TestTransitionTimeBoundsAndInvalidInputs(t *testing.T) {
	s, dir, a, _ := beginFixture(t)
	before := read(t, filepath.Join(dir, stateName))
	_, err := a.Complete(context.Background(), OutcomeCompleted, ObservedActive, testNow)
	requireErr(t, err, ErrTransition)
	_, err = a.NotStarted(context.Background(), "arbitrary backend output", testNow)
	requireErr(t, err, ErrTransition)
	for _, now := range []time.Time{testNow.Add(-time.Microsecond), testNow.In(time.FixedZone("offset", 0)), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		_, err = a.MarkDispatching(context.Background(), now)
		requireErr(t, err, actionpermit.ErrClock)
	}
	_, err = a.MarkDispatching(context.Background(), testNow.Add(time.Minute))
	requireErr(t, err, actionpermit.ErrExpired)
	if !bytes.Equal(before, read(t, filepath.Join(dir, stateName))) {
		t.Fatal("invalid transition wrote state")
	}
	if _, err = a.MarkDispatching(context.Background(), testNow.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, args := range []struct {
		outcome Outcome
		state   ObservedState
	}{{"output text", ObservedActive}, {OutcomeCompleted, "arbitrary"}, {OutcomeUnknown, ""}} {
		_, err = a.Complete(context.Background(), args.outcome, args.state, testNow.Add(time.Second))
		requireErr(t, err, ErrTransition)
	}
	_, err = a.Complete(context.Background(), OutcomeCompleted, ObservedActive, testNow)
	requireErr(t, err, actionpermit.ErrClock)
	finished := testNow.Add(3 * time.Second)
	if _, err = a.Complete(context.Background(), OutcomeCompleted, ObservedActive, finished); err != nil {
		t.Fatal(err)
	}
	_, _, err = s.Begin(context.Background(), signed(t, permit(t, 2)), finished.Add(-time.Microsecond))
	requireErr(t, err, actionpermit.ErrClock)
	if _, _, err = s.Begin(context.Background(), signed(t, permit(t, 2)), finished); err != nil {
		t.Fatal(err)
	}
}

func TestExpiryDuringAdmissionAndDispatchFsync(t *testing.T) {
	for _, waitAt := range []string{"begin", "dispatch"} {
		t.Run(waitAt, func(t *testing.T) {
			s, _ := fixture(t)
			clock := testNow.Add(59 * time.Second)
			store := s.inner.store.(*linuxStorage)
			originalSync := store.ops.sync
			delay := func() {
				store.ops.sync = func(fd int) error {
					err := originalSync(fd)
					if fd == store.dirFD() {
						clock = clock.Add(time.Second)
					}
					return err
				}
			}
			if waitAt == "begin" {
				delay()
			}
			_, a, err := s.Begin(context.Background(), signed(t, permit(t, 1)), clock)
			if err != nil || a == nil {
				t.Fatal(err)
			}
			if waitAt == "dispatch" {
				delay()
			}
			_, err = a.MarkDispatching(context.Background(), clock)
			if waitAt == "begin" {
				requireErr(t, err, actionpermit.ErrExpired)
			} else if err != nil {
				t.Fatal(err)
			}
			// The runtime's final fresh clock check catches deadline crossing
			// during the durable barrier, without ever calling a backend.
			requireErr(t, verifier(t).CheckTime(permit(t, 1), clock), actionpermit.ErrExpired)
			store.ops.sync = originalSync
			st, err := a.NotStarted(context.Background(), ReasonExpired, clock)
			if err != nil || st.Phase != NotStarted || st.Reason != ReasonExpired {
				t.Fatal(st, err)
			}
		})
	}
}

type failedReplaceStorage struct{ storage }

func (s failedReplaceStorage) replace(context.Context, []byte) error { return ErrIO }

func TestEveryRunnerWriteFailurePoisonsSharedState(t *testing.T) {
	for _, operation := range []string{"begin", "dispatch", "not-started", "complete"} {
		for _, fault := range []string{"before-write", "disk-full", "short-write", "file-sync", "rename", "directory-sync", "cancel-before-rename", "cancel-after-commit"} {
			t.Run(operation+"/"+fault, func(t *testing.T) {
				s, dir := fixture(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var a *Attempt
				var err error
				if operation != "begin" {
					_, a, err = s.Begin(ctx, signed(t, permit(t, 1)), testNow)
					if err != nil {
						t.Fatal(err)
					}
				}
				if operation == "complete" {
					if _, err = a.MarkDispatching(ctx, testNow); err != nil {
						t.Fatal(err)
					}
				}
				copyState := *s
				store := s.inner.store.(*linuxStorage)
				syncOriginal, renameOriginal := store.ops.sync, store.ops.rename
				switch fault {
				case "before-write":
					s.inner.store = failedReplaceStorage{store}
				case "disk-full":
					store.ops.write = func(*os.File, []byte) (int, error) { return 0, unix.ENOSPC }
				case "short-write":
					store.ops.write = func(f *os.File, b []byte) (int, error) { return f.Write(b[:len(b)/2]) }
				}
				store.ops.sync = func(fd int) error {
					if fault == "file-sync" && fd != store.dirFD() || fault == "directory-sync" && fd == store.dirFD() {
						return errors.New("inert injected sync error")
					}
					err := syncOriginal(fd)
					if fault == "cancel-before-rename" && fd != store.dirFD() || fault == "cancel-after-commit" && fd == store.dirFD() {
						cancel()
					}
					return err
				}
				store.ops.rename = func(a int, b string, c int, d string) error {
					if fault == "rename" {
						return errors.New("inert injected rename error")
					}
					return renameOriginal(a, b, c, d)
				}
				var got Status
				switch operation {
				case "begin":
					got, a, err = s.Begin(ctx, signed(t, permit(t, 1)), testNow)
					if a != nil {
						t.Fatal("failed Begin issued capability")
					}
				case "dispatch":
					got, err = a.MarkDispatching(ctx, testNow)
				case "not-started":
					got, err = a.NotStarted(ctx, ReasonPreflight, testNow)
				case "complete":
					got, err = a.Complete(ctx, OutcomeCompleted, ObservedActive, testNow)
				}
				want := ErrUncertain
				if fault == "before-write" {
					want = ErrIO
				}
				if fault == "cancel-after-commit" {
					want = ErrCanceled
				}
				requireErr(t, err, want)
				if got != (Status{}) {
					t.Fatal("failed transition returned status")
				}
				if fault != "cancel-after-commit" {
					_, err = copyState.Status(context.Background(), permit(t, 1).JobID)
					requireErr(t, err, want)
					_, _, err = copyState.Begin(context.Background(), signed(t, permit(t, 2)), testNow)
					requireErr(t, err, want)
				}
				_ = s.Close()
				if fault == "directory-sync" || fault == "cancel-after-commit" || fault == "before-write" {
					s, err = Open(context.Background(), dir, verifier(t))
					if err != nil {
						t.Fatal(err)
					}
					defer s.Close()
					_, token, err := s.Begin(context.Background(), signed(t, permit(t, 1)), testNow)
					if operation == "begin" && fault == "before-write" {
						if err != nil || token == nil {
							t.Fatal("clean pre-write failure lost unused sequence")
						}
					} else if err != nil || token != nil {
						t.Fatal("reopen recreated capability", token, err)
					}
				} else {
					_, err = Open(context.Background(), dir, verifier(t))
					requireErr(t, err, ErrUncertain)
					if _, err = os.Lstat(filepath.Join(dir, tempName)); err != nil {
						t.Fatal("ambiguous temp removed")
					}
				}
			})
		}
	}
}

func TestCancellationBeforeRunnerTransitionsIsInert(t *testing.T) {
	s, dir := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := read(t, filepath.Join(dir, stateName))
	_, a, err := s.Begin(ctx, signed(t, permit(t, 1)), testNow)
	requireErr(t, err, ErrCanceled)
	if a != nil || !bytes.Equal(before, read(t, filepath.Join(dir, stateName))) {
		t.Fatal("canceled Begin changed state")
	}
	_, a, err = s.Begin(context.Background(), signed(t, permit(t, 1)), testNow)
	if err != nil {
		t.Fatal(err)
	}
	before = read(t, filepath.Join(dir, stateName))
	_, err = a.MarkDispatching(ctx, testNow)
	requireErr(t, err, ErrCanceled)
	_, err = a.NotStarted(ctx, ReasonCanceled, testNow)
	requireErr(t, err, ErrCanceled)
	if !bytes.Equal(before, read(t, filepath.Join(dir, stateName))) {
		t.Fatal("canceled transition changed state")
	}
	if _, err = a.NotStarted(context.Background(), ReasonCanceled, testNow); err != nil {
		t.Fatal(err)
	}
}

func TestV1LosslessMigrationAndBindingPreservation(t *testing.T) {
	s, dir := fixture(t)
	for i := uint64(1); i <= 3; i++ {
		_, err := s.Admit(context.Background(), signed(t, permit(t, i)), testNow.Add(time.Minute))
		requireErr(t, err, actionpermit.ErrExpired)
	}
	oldBytes := read(t, filepath.Join(dir, stateName))
	old, err := decodeRecord(oldBytes, verifier(t))
	if err != nil || old.Version != Version {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = Open(context.Background(), dir, verifier(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if !bytes.Equal(oldBytes, read(t, filepath.Join(dir, stateName))) {
		t.Fatal("read migrated v1")
	}
	_, a, err := s.Begin(context.Background(), signed(t, permit(t, 2)), testNow)
	if err != nil || a != nil || !bytes.Equal(oldBytes, read(t, filepath.Join(dir, stateName))) {
		t.Fatal("duplicate migrated v1")
	}
	next := permit(t, 9)
	next.IssuedAt += 60
	next.NotBefore += 60
	next.StartDeadline += 60
	_, a, err = s.Begin(context.Background(), signed(t, next), testNow.Add(time.Minute))
	if err != nil || a == nil {
		t.Fatal(err)
	}
	migrated, err := decodeRecord(read(t, filepath.Join(dir, stateName)), verifier(t))
	if err != nil || migrated.Version != RunnerVersion || migrated.Floor != 9 || migrated.BindingDigest != old.BindingDigest || len(migrated.Jobs) != 4 {
		t.Fatal("bad migration", err)
	}
	oldJobs, _ := json.Marshal(old.Jobs)
	newPrefix, _ := json.Marshal(migrated.Jobs[:len(old.Jobs)])
	if !bytes.Equal(oldJobs, newPrefix) || migrated.HighWater != old.HighWater {
		t.Fatal("migration changed old history or clock")
	}
	if digest, err := s.BindingDigest(context.Background()); err != nil || digest != old.BindingDigest {
		t.Fatal(digest, err)
	}
	if _, err = a.NotStarted(context.Background(), ReasonPolicyChanged, testNow.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	c := pins()
	c.Enabled = false
	c.RootPolicyDigest = actionpermit.Digest([]byte("new policy and transport profile"))
	v, _ := actionpermit.NewVerifier(c)
	s, err = Open(context.Background(), dir, v)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.inner.record.Floor != 9 || s.inner.record.BindingDigest != old.BindingDigest {
		t.Fatal("policy change reset domain")
	}
	if _, token, err := s.Begin(context.Background(), signed(t, next), testNow); err != nil || token != nil {
		t.Fatal("disabled duplicate regained capability")
	}
}

func TestV1LegacyRecoveryDoesNotMigrate(t *testing.T) {
	s, dir := fixture(t)
	raw := signed(t, permit(t, 1))
	if _, err := s.Admit(context.Background(), raw, testNow); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err := Open(context.Background(), dir, verifier(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.inner.record.Version != Version || s.inner.record.Jobs[0].Lifecycle != nil {
		t.Fatal("legacy recovery gained runner metadata")
	}
	st, token, err := s.Begin(context.Background(), raw, testNow)
	if err != nil || token != nil || st.Phase != NeedsIntervention {
		t.Fatal(st, token, err)
	}
}

func TestCorruptRunnerTransitionsRejected(t *testing.T) {
	s, _, a, _ := dispatchFixture(t)
	if _, err := a.Complete(context.Background(), OutcomeCompleted, ObservedActive, testNow.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	base := s.inner.record
	for name, mutate := range map[string]func(*diskRecord){
		"v1-lifecycle":              func(r *diskRecord) { r.Version = Version },
		"missing-lifecycle":         func(r *diskRecord) { r.Jobs[0].Lifecycle = nil },
		"no-dispatch":               func(r *diskRecord) { r.Jobs[0].Lifecycle.DispatchAt = 0 },
		"late-dispatch":             func(r *diskRecord) { r.Jobs[0].Lifecycle.DispatchAt = testNow.Add(time.Minute).UnixMicro() },
		"dispatch-before-admission": func(r *diskRecord) { r.Jobs[0].Lifecycle.DispatchAt = testNow.Add(-time.Microsecond).UnixMicro() },
		"end-before-dispatch":       func(r *diskRecord) { r.Jobs[0].Lifecycle.TransitionAt = testNow.UnixMicro() },
		"high-water-regression":     func(r *diskRecord) { r.HighWater = testNow.UnixMicro() },
		"unknown-completed":         func(r *diskRecord) { r.Jobs[0].Lifecycle.Outcome = OutcomeUnknown },
		"arbitrary-outcome":         func(r *diskRecord) { r.Jobs[0].Lifecycle.Outcome = "untrusted output" },
		"arbitrary-observation":     func(r *diskRecord) { r.Jobs[0].Lifecycle.ObservedState = "raw journal" },
		"unbounded-reason": func(r *diskRecord) {
			r.Jobs[0].Phase = NotStarted
			r.Jobs[0].Lifecycle.Reason = "raw error"
			r.Jobs[0].Lifecycle.Outcome = ""
			r.Jobs[0].Lifecycle.ObservedState = ""
		},
		"admitted-with-result":    func(r *diskRecord) { r.Jobs[0].Phase = Admitted },
		"dispatching-with-result": func(r *diskRecord) { r.Jobs[0].Phase = Dispatching },
		"expired-with-lifecycle":  func(r *diskRecord) { r.Jobs[0].Phase = Expired },
		"completed-unknown-phase": func(r *diskRecord) { r.Jobs[0].Phase = NeedsIntervention },
		"not-started-with-result": func(r *diskRecord) { r.Jobs[0].Phase = NotStarted; r.Jobs[0].Lifecycle.Reason = ReasonCanceled },
	} {
		t.Run(name, func(t *testing.T) {
			r := base
			r.Jobs = append([]diskJob(nil), base.Jobs...)
			l := *base.Jobs[0].Lifecycle
			r.Jobs[0].Lifecycle = &l
			mutate(&r)
			raw, err := encodeRecord(r)
			if err != nil {
				t.Fatal(err)
			}
			_, err = decodeRecord(raw, verifier(t))
			requireErr(t, err, ErrCorrupt)
		})
	}
}

func TestExpiredBeginAndLegacyAdmitNeverCreateCapabilities(t *testing.T) {
	s, dir := fixture(t)
	st, token, err := s.Begin(context.Background(), signed(t, permit(t, 1)), testNow.Add(time.Minute))
	requireErr(t, err, actionpermit.ErrExpired)
	if st.Phase != Expired || token != nil || s.inner.record.Version != Version {
		t.Fatal("expired runner request created lifecycle", st, token)
	}
	next := permit(t, 2)
	next.IssuedAt += 60
	next.NotBefore += 60
	next.StartDeadline += 60
	_, token, err = s.Begin(context.Background(), signed(t, next), testNow.Add(time.Minute))
	if err != nil || token == nil {
		t.Fatal(err)
	}
	if _, err = token.NotStarted(context.Background(), ReasonPreflight, testNow.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	next.JobID = permit(t, 3).JobID
	next.Sequence = 3
	st, err = s.Admit(context.Background(), signed(t, next), testNow.Add(time.Minute))
	if err != nil || st.Phase != Admitted || s.inner.record.Version != RunnerVersion || s.inner.record.Jobs[2].Lifecycle != nil {
		t.Fatal("Admit gained runner capability", st, err)
	}
	before := read(t, filepath.Join(dir, stateName))
	got, token, err := s.Begin(context.Background(), signed(t, next), testNow.Add(time.Minute))
	if err != nil || token != nil || got != st || !bytes.Equal(before, read(t, filepath.Join(dir, stateName))) {
		t.Fatal("legacy v2 duplicate gained capability")
	}
}

func TestRunnerHistoryIsNeverPrunedOrReset(t *testing.T) {
	s, dir := fixture(t)
	for i := uint64(1); i <= MaxJobs; i++ {
		_, a, err := s.Begin(context.Background(), signed(t, permit(t, i)), testNow)
		if err != nil || a == nil {
			t.Fatal(i, err)
		}
		if _, err = a.NotStarted(context.Background(), ReasonInactive, testNow); err != nil {
			t.Fatal(i, err)
		}
	}
	_, a, err := s.Begin(context.Background(), signed(t, permit(t, MaxJobs+1)), testNow)
	requireErr(t, err, ErrCapacity)
	if a != nil {
		t.Fatal("capacity issued attempt")
	}
	before := read(t, filepath.Join(dir, stateName))
	_ = s.Close()
	s, err = Open(context.Background(), dir, verifier(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if !bytes.Equal(before, read(t, filepath.Join(dir, stateName))) || s.inner.record.Floor != MaxJobs || len(s.inner.record.Jobs) != MaxJobs {
		t.Fatal("reopen pruned terminal history")
	}
	for i := uint64(1); i <= MaxJobs; i++ {
		got, a, err := s.Begin(context.Background(), signed(t, permit(t, i)), testNow.Add(-time.Hour))
		if err != nil || a != nil || got.Phase != NotStarted {
			t.Fatal(i, got, a, err)
		}
	}
}

func TestMigrationFailuresPreserveV1PrefixAndConsumption(t *testing.T) {
	for _, afterRename := range []bool{false, true} {
		t.Run(map[bool]string{false: "file-sync", true: "directory-sync"}[afterRename], func(t *testing.T) {
			s, dir := fixture(t)
			_, err := s.Admit(context.Background(), signed(t, permit(t, 1)), testNow.Add(time.Minute))
			requireErr(t, err, actionpermit.ErrExpired)
			before := read(t, filepath.Join(dir, stateName))
			oldJobs, _ := json.Marshal(s.inner.record.Jobs)
			store := s.inner.store.(*linuxStorage)
			originalSync := store.ops.sync
			store.ops.sync = func(fd int) error {
				if (fd == store.dirFD()) == afterRename {
					return errors.New("inert migration sync failure")
				}
				return originalSync(fd)
			}
			p := permit(t, 2)
			p.IssuedAt += 60
			p.NotBefore += 60
			p.StartDeadline += 60
			_, a, err := s.Begin(context.Background(), signed(t, p), testNow.Add(time.Minute))
			requireErr(t, err, ErrUncertain)
			if a != nil {
				t.Fatal("migration failure issued capability")
			}
			after := read(t, filepath.Join(dir, stateName))
			if !afterRename && !bytes.Equal(before, after) {
				t.Fatal("uncommitted migration changed v1")
			}
			r, err := decodeRecord(after, verifier(t))
			if err != nil {
				t.Fatal(err)
			}
			prefix, _ := json.Marshal(r.Jobs[:1])
			if !bytes.Equal(prefix, oldJobs) {
				t.Fatal("migration altered old signed history")
			}
			_ = s.Close()
			s, err = Open(context.Background(), dir, verifier(t))
			if !afterRename {
				requireErr(t, err, ErrUncertain)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			st, a, err := s.Begin(context.Background(), signed(t, p), testNow)
			if err != nil || a != nil || st.Phase != NeedsIntervention || s.inner.record.Floor != 2 {
				t.Fatal(st, a, err)
			}
		})
	}
}

func TestTransitionClockHighWaterConstrainsFollowingRecords(t *testing.T) {
	s, _, a, _ := dispatchFixture(t)
	if _, err := a.Complete(context.Background(), OutcomeCompleted, ObservedActive, testNow.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	_, a, err := s.Begin(context.Background(), signed(t, permit(t, 2)), testNow.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.NotStarted(context.Background(), ReasonPreflight, testNow.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	base := s.inner.record
	for _, kind := range []string{"consume-before-prior-finish", "unresolved-before-next", "recovered-before-next"} {
		t.Run(kind, func(t *testing.T) {
			r := base
			r.Jobs = append([]diskJob(nil), base.Jobs...)
			first, second := *base.Jobs[0].Lifecycle, *base.Jobs[1].Lifecycle
			r.Jobs[0].Lifecycle, r.Jobs[1].Lifecycle = &first, &second
			switch kind {
			case "consume-before-prior-finish":
				r.Jobs[1].ConsumedAt = testNow.Add(2 * time.Second).UnixMicro()
			case "unresolved-before-next":
				r.Jobs[0].Phase = Dispatching
				first.TransitionAt, first.Outcome, first.ObservedState = first.DispatchAt, "", ""
			case "recovered-before-next":
				r.Jobs[0].Phase = NeedsIntervention
				first.Outcome = OutcomeUnknown
			}
			raw, err := encodeRecord(r)
			if err != nil {
				t.Fatal(err)
			}
			_, err = decodeRecord(raw, verifier(t))
			requireErr(t, err, ErrCorrupt)
		})
	}
}
