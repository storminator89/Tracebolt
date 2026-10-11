package windowsservice

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type restartFixture struct {
	layout                              Layout
	receipt                             Receipt
	snapshot                            Snapshot
	now                                 time.Time
	events                              []string
	calls                               map[string]int
	hook                                func(string, int) error
	opens, closes, stops, starts, waits int
	owned                               bool
	noProgress                          bool
	noClockProgress                     bool
	returnHandleOnOpenError             bool
}

func newRestartFixture(t *testing.T) *restartFixture {
	t.Helper()
	base, r := installedFixture(t)
	f := &restartFixture{layout: base.layout, receipt: r, snapshot: base.s.snapshot, now: time.Unix(1000, 0), calls: map[string]int{}, owned: true}
	f.snapshot.State = Running
	f.snapshot.ProcessID = 123
	return f
}
func (f *restartFixture) event(name string) error {
	f.events = append(f.events, name)
	f.calls[name]++
	if !f.owned {
		panic("effect without lease")
	}
	if f.hook != nil {
		return f.hook(name, f.calls[name])
	}
	return nil
}
func (f *restartFixture) Layout() (Layout, error) { e := f.event("layout"); return f.layout, e }
func (f *restartFixture) VerifyExecutable(Layout) (string, error) {
	e := f.event("hash")
	return fixtureHash, e
}
func (f *restartFixture) LookupSID() (string, error)            { panic("unexpected independent SID lookup") }
func (f *restartFixture) Create(Configuration) (service, error) { panic("unexpected create") }
func (f *restartFixture) Open(a access) (service, error) {
	if a != restartAccess {
		panic("incorrect access")
	}
	f.opens++
	e := f.event("open")
	if e != nil && !f.returnHandleOnOpenError {
		return nil, e
	}
	return f, e
}
func (f *restartFixture) Inspect() (Snapshot, error) {
	e := f.event("inspect")
	return f.snapshot, e
}
func (f *restartFixture) Stop() error {
	f.stops++
	// The native effect may precede an error return. Tests deliberately model it.
	f.snapshot.State = StopPending
	return f.event("stop")
}
func (f *restartFixture) Start() error {
	f.starts++
	f.snapshot.State = StartPending
	return f.event("start")
}
func (f *restartFixture) Delete() error { panic("unexpected delete") }
func (f *restartFixture) Close() error  { f.closes++; return f.event("close") }
func (f *restartFixture) Verify() error { return f.event("lease") }
func (f *restartFixture) clock() restartClock {
	return restartClock{func() time.Time { return f.now }, func(ctx context.Context, d time.Duration) error {
		if d <= 0 || d > restartPoll {
			panic("unbounded wait")
		}
		f.waits++
		if !f.noClockProgress {
			f.now = f.now.Add(d)
		}
		e := f.event("wait")
		if !f.noProgress {
			if f.snapshot.State == StopPending {
				f.snapshot.State = Stopped
			}
			if f.snapshot.State == StartPending {
				f.snapshot.State = Running
			}
		}
		return e
	}}
}
func (f *restartFixture) run(ctx context.Context) (RestartResult, error) {
	return restart(ctx, f, f.receipt, f, f.clock())
}

func TestRestartOneHandleExactlyOnceAndHistoricalSCMOutcome(t *testing.T) {
	f := newRestartFixture(t)
	got, err := f.run(context.Background())
	if err != nil || got.Outcome != "running-observed" || got.Phase != "complete" || !got.StopAttempted || !got.StopRequested || !got.StoppedObserved || !got.StartAttempted || !got.StartRequested || !got.RunningObserved || !got.StateRetained || got.LastObservedState != Running {
		t.Fatal(got, err)
	}
	if f.opens != 1 || f.closes != 1 || f.stops != 1 || f.starts != 1 || f.waits != 2 {
		t.Fatal(f.events)
	}
	want := []string{"lease", "layout", "open", "inspect", "lease", "hash", "inspect", "stop", "inspect", "wait", "inspect", "lease", "hash", "inspect", "start", "inspect", "wait", "inspect", "lease", "hash", "inspect", "close"}
	if !reflect.DeepEqual(f.events, want) {
		t.Fatal(f.events)
	}
}

func TestRestartRequiresInitialRunningAndExactReceipt(t *testing.T) {
	for _, state := range []State{Stopped, StartPending, StopPending, 0, 5, 6, 7} {
		t.Run(string(rune('a'+state)), func(t *testing.T) {
			f := newRestartFixture(t)
			f.snapshot.State = state
			got, err := f.run(context.Background())
			if !errors.Is(err, ErrRestartState) || got.Outcome != "not-requested" || f.stops != 0 || f.starts != 0 || f.closes != 1 {
				t.Fatal(got, err, f.events)
			}
		})
	}
	for name, mutate := range map[string]func(*Receipt){
		"empty": func(r *Receipt) { *r = Receipt{} }, "version": func(r *Receipt) { r.Version = 2 }, "incomplete": func(r *Receipt) { r.Complete = false }, "foreign-layout": func(r *Receipt) { r.Layout.Executable += "other" }, "foreign-marker": func(r *Receipt) { r.InstallationID = strings.Repeat("f", 32) }, "foreign-sid": func(r *Receipt) { r.ServiceSID = "S-1-5-19" }, "foreign-digest": func(r *Receipt) { r.ConfigurationSHA256 = strings.Repeat("f", 64) }, "hash": func(r *Receipt) { r.ExecutableSHA256 = "bad" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newRestartFixture(t)
			mutate(&f.receipt)
			got, err := f.run(context.Background())
			if !errors.Is(err, ErrMismatch) || got.StopAttempted || f.opens != 0 {
				t.Fatal(got, err, f.events)
			}
		})
	}
}

func TestRestartRejectsEveryObservedBindingDrift(t *testing.T) {
	for _, at := range []int{1, 2, 3, 4, 5, 6, 7, 8} {
		for _, kind := range []string{"sid", "config", "missing"} {
			t.Run(kind+string(rune('a'+at)), func(t *testing.T) {
				f := newRestartFixture(t)
				f.hook = func(name string, n int) error {
					if name == "inspect" && n == at {
						switch kind {
						case "sid":
							f.snapshot.ServiceSID = "S-1-5-80-9-9-9-9-9"
						case "config":
							f.snapshot.Configuration.StartType = 4
						case "missing":
							f.snapshot.Exists = false
						}
					}
					return nil
				}
				got, err := f.run(context.Background())
				if !errors.Is(err, ErrMismatch) || f.closes != 1 || f.opens != 1 || f.stops > 1 || f.starts > 1 || got.Outcome == "running-observed" {
					t.Fatal(got, err, f.events)
				}
				if at <= 5 && f.starts != 0 {
					t.Fatal("start followed drift", f.events)
				}
			})
		}
	}
}

func TestRestartHashAndLeaseFailureBeforeEachEffect(t *testing.T) {
	failure := errors.New("fixture verification failure")
	for _, name := range []string{"hash", "lease"} {
		max := 3
		if name == "lease" {
			max = 4
		}
		for at := 1; at <= max; at++ {
			t.Run(name+string(rune('a'+at)), func(t *testing.T) {
				f := newRestartFixture(t)
				f.hook = func(s string, n int) error {
					if s == name && n == at {
						return failure
					}
					return nil
				}
				got, err := f.run(context.Background())
				if !errors.Is(err, failure) || got.Outcome == "running-observed" || f.stops > 1 || f.starts > 1 {
					t.Fatal(got, err, f.events)
				}
				if name == "hash" && at <= 2 && f.starts != 0 {
					t.Fatal(f.events)
				}
				if name == "lease" && at <= 3 && f.starts != 0 {
					t.Fatal(f.events)
				}
			})
		}
	}
}

type changedHashBackend struct {
	*restartFixture
	at int
}

func (b changedHashBackend) VerifyExecutable(l Layout) (string, error) {
	hash, e := b.restartFixture.VerifyExecutable(l)
	if b.calls["hash"] == b.at {
		hash = strings.Repeat("b", 64)
	}
	return hash, e
}
func TestRestartRejectsExecutableHashDrift(t *testing.T) {
	for _, at := range []int{1, 2, 3} {
		f := newRestartFixture(t)
		got, err := restart(context.Background(), changedHashBackend{f, at}, f.receipt, f, f.clock())
		if !errors.Is(err, ErrMismatch) || got.Outcome == "running-observed" || f.closes != 1 || at <= 2 && f.starts != 0 {
			t.Fatal(got, err, f.events)
		}
	}
}

func TestRestartNativeControlErrorsNeverRetryOrCompensate(t *testing.T) {
	failure := errors.New("ambiguous native control")
	for _, which := range []string{"stop", "start"} {
		for _, effect := range []bool{false, true} {
			f := newRestartFixture(t)
			f.hook = func(s string, n int) error {
				if s == which {
					if !effect {
						if which == "stop" {
							f.snapshot.State = Running
						} else {
							f.snapshot.State = Stopped
						}
					}
					return failure
				}
				return nil
			}
			got, err := f.run(context.Background())
			if !errors.Is(err, failure) || got.Outcome != "intervention-required" || f.stops != 1 || f.closes != 1 || f.starts > 1 {
				t.Fatal(got, err, f.events)
			}
			if which == "stop" && (got.StopRequested || got.StartAttempted || f.starts != 0) || which == "start" && (!got.StartAttempted || got.StartRequested || f.starts != 1) {
				t.Fatal(got)
			}
			if f.events[len(f.events)-2] != which {
				t.Fatal("observation/retry after uncertain control", f.events)
			}
		}
	}
}

func TestRestartCancellationAndLateReturnsFenceLaterEffects(t *testing.T) {
	for _, late := range []bool{false, true} {
		for _, point := range []struct {
			name string
			at   int
		}{{"lease", 1}, {"layout", 1}, {"open", 1}, {"inspect", 1}, {"hash", 1}, {"inspect", 2}, {"stop", 1}, {"inspect", 4}, {"hash", 2}, {"inspect", 5}, {"start", 1}, {"inspect", 7}, {"hash", 3}, {"inspect", 8}, {"close", 1}} {
			t.Run(point.name+string(rune('a'+point.at))+map[bool]string{true: "deadline", false: "cancel"}[late], func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				f := newRestartFixture(t)
				f.hook = func(s string, n int) error {
					if s == point.name && n == point.at {
						if late {
							f.now = f.now.Add(restartBudget)
						} else {
							cancel()
						}
					}
					return nil
				}
				got, err := f.run(ctx)
				want := error(context.Canceled)
				if late {
					want = context.DeadlineExceeded
				}
				if !errors.Is(err, want) || got.Outcome == "running-observed" || f.stops > 1 || f.starts > 1 || f.opens == 1 && f.closes != 1 {
					t.Fatal(got, err, f.events)
				}
				if (point.name == "hash" && point.at <= 2 || point.name == "stop" || point.name == "inspect" && point.at <= 5) && f.starts != 0 {
					t.Fatal("start after cancellation", f.events)
				}
			})
		}
	}
}

func TestRestartPollingHasTimeAndObservationBudgets(t *testing.T) {
	for _, stuckClock := range []bool{false, true} {
		for _, phase := range []string{"stop", "start"} {
			f := newRestartFixture(t)
			f.noClockProgress = stuckClock
			f.hook = func(s string, _ int) error {
				if s == phase {
					f.noProgress = true
				}
				return nil
			}
			got, err := f.run(context.Background())
			if !errors.Is(err, context.DeadlineExceeded) || got.Outcome != "intervention-required" || got.Observations > restartMaxObservations || f.waits > restartMaxObservations || f.closes != 1 || f.stops != 1 || f.starts > 1 {
				t.Fatal(got, err, f.events)
			}
			if phase == "stop" && f.starts != 0 {
				t.Fatal("started without stopped observation")
			}
		}
	}
}
func TestRestartRetainsPrimaryAndCloseErrors(t *testing.T) {
	primary, closed := errors.New("primary"), errors.New("close")
	for _, where := range []string{"open", "inspect", "stop", "start", "none"} {
		f := newRestartFixture(t)
		f.returnHandleOnOpenError = true
		f.hook = func(s string, _ int) error {
			if s == where {
				return primary
			}
			if s == "close" {
				return closed
			}
			return nil
		}
		got, err := f.run(context.Background())
		wantPhase := map[string]string{"open": "open", "inspect": "initial-observe", "stop": "stop", "start": "start", "none": "close"}[where]
		if !errors.Is(err, closed) || where != "none" && !errors.Is(err, primary) || got.Outcome == "running-observed" || f.closes != 1 || got.Phase != wantPhase {
			t.Fatal(got, err, f.events)
		}
	}
}
func TestRestartUnexpectedTransitionsAndInvalidInputsFailClosed(t *testing.T) {
	for _, point := range []int{2, 3, 5, 6, 8} {
		f := newRestartFixture(t)
		f.hook = func(s string, n int) error {
			if s == "inspect" && n == point {
				f.snapshot.State = 7
			}
			return nil
		}
		got, err := f.run(context.Background())
		if !errors.Is(err, ErrRestartState) || got.Outcome == "running-observed" || f.closes != 1 {
			t.Fatal(got, err, f.events)
		}
	}
	f := newRestartFixture(t)
	if _, err := restart(nil, f, f.receipt, f, f.clock()); !errors.Is(err, ErrMismatch) || len(f.events) != 0 {
		t.Fatal(err)
	}
	if _, err := restart(context.Background(), f, f.receipt, nil, f.clock()); !errors.Is(err, ErrMismatch) || len(f.events) != 0 {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.run(ctx); !errors.Is(err, context.Canceled) || len(f.events) != 0 {
		t.Fatal(err)
	}
	f.hook = func(s string, _ int) error {
		if s == "layout" {
			f.now = f.now.Add(-time.Second)
		}
		return nil
	}
	if _, err := f.run(context.Background()); !errors.Is(err, context.DeadlineExceeded) || f.opens != 0 {
		t.Fatal(err)
	}
}

func TestRestartRequiresRunningPIDButNeverClaimsChangedProcess(t *testing.T) {
	for _, at := range []int{1, 2, 7, 8} {
		f := newRestartFixture(t)
		f.hook = func(name string, n int) error {
			if name == "inspect" && n == at {
				f.snapshot.ProcessID = 0
			}
			return nil
		}
		got, err := f.run(context.Background())
		if !errors.Is(err, ErrMismatch) || got.Outcome == "running-observed" || f.closes != 1 {
			t.Fatal(got, err)
		}
	}
	f := newRestartFixture(t)
	f.hook = func(name string, _ int) error {
		if name == "inspect" {
			if f.snapshot.State == Running {
				f.snapshot.ProcessID = 123
			} else {
				f.snapshot.ProcessID = 0
			}
		}
		return nil
	}
	got, err := f.run(context.Background())
	if err != nil || got.Outcome != "running-observed" {
		t.Fatal("PID reuse or pending zero was rejected", got, err)
	}
}
