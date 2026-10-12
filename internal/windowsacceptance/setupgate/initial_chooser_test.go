package setupgate

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

type initialChooserFixture struct {
	now                                                       time.Time
	identity                                                  InitialChooserIdentity
	absent, disabled, discoveries, observations, waits, posts int
	canceled, exited, discoverError, observeError, postFailed bool
	onDiscover, onObserve, onVisibility, onWait               func()
	stage                                                     string
	trace                                                     clickTrace
}

func newInitialChooserFixture() (*initialChooserFixture, *InitialChooser) {
	f := &initialChooserFixture{now: time.Unix(100, 0), identity: InitialChooserIdentity{Process: 10, Thread: 20, Root: 30, Control: 40}}
	return f, NewInitialChooser(f.now.Add(15*time.Second), 10, f.steps())
}
func (f *initialChooserFixture) record(s string) { f.stage = s }
func (f *initialChooserFixture) steps() InitialChooserSteps {
	return InitialChooserSteps{
		Now: func() time.Time { return f.now }, Canceled: func() bool { return f.canceled }, Process: func() bool { return !f.exited },
		Wait: func(delay time.Duration) error {
			if delay <= 0 || delay > 100*time.Millisecond {
				panic("unbounded wait")
			}
			f.waits++
			f.now = f.now.Add(delay)
			if f.onWait != nil {
				f.onWait()
			}
			return nil
		},
		Discover: func() (InitialChooserIdentity, error) {
			f.discoveries++
			if f.onDiscover != nil {
				f.onDiscover()
			}
			if f.discoverError {
				return InitialChooserIdentity{}, errors.New("private API error")
			}
			if f.discoveries <= f.absent {
				return InitialChooserIdentity{}, nil
			}
			return f.identity, nil
		},
		Observe: func() (InitialChooserIdentity, bool, error) {
			f.observations++
			if f.onObserve != nil {
				f.onObserve()
			}
			if f.observeError {
				return InitialChooserIdentity{}, false, errors.New("private invalid handle")
			}
			return f.identity, f.observations > f.disabled, nil
		},
		Visibility: func(stage func(string)) error {
			if f.onVisibility != nil {
				f.onVisibility()
			}
			return CheckClickVisibility(stage, "chooser-click", f.trace.visibility())
		},
		Post: func() bool { f.posts++; return !f.postFailed },
	}
}
func TestInitialChooserTransientDisabledPostsOnceWithinSharedBudget(t *testing.T) {
	f, c := newInitialChooserFixture()
	f.absent, f.disabled = 3, 4
	start := f.now
	if c.Discover(f.record) != nil || c.Click(f.record) != nil {
		t.Fatal("transient readiness rejected")
	}
	if f.posts != 1 || f.discoveries != 4 || f.observations != 6 || f.waits != 7 || f.now.Sub(start) != 700*time.Millisecond {
		t.Fatal("unexpected polling or post count")
	}
	if !reflect.DeepEqual(f.trace.operations, clickOperationOrder[2:17]) {
		t.Fatalf("geometry checks changed: %v", f.trace.operations)
	}
	if c.Click(f.record) != ErrGuard || f.posts != 1 || f.stage != "initial-chooser-attempt" {
		t.Fatal("successful attempt replayed")
	}
}
func TestInitialChooserPermanentDisabledAndDiscoveryUseOneDeadline(t *testing.T) {
	for _, test := range []struct {
		name                           string
		absent, disabled, observations int
	}{
		{"permanent disabled", 0, 200, 150}, {"discovery consumes budget", 150, 0, 0}, {"remaining readiness only", 149, 2, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, c := newInitialChooserFixture()
			f.absent, f.disabled = test.absent, test.disabled
			start := f.now
			err := c.Discover(f.record)
			if err == nil {
				err = c.Click(f.record)
			}
			if err != ErrGuard || f.posts != 0 || f.now.Sub(start) != 15*time.Second || f.observations != test.observations || f.stage != "initial-chooser-deadline" {
				t.Fatalf("deadline renewed: elapsed=%v observations=%d stage=%s", f.now.Sub(start), f.observations, f.stage)
			}
			if c.Click(f.record) != ErrGuard || f.posts != 0 {
				t.Fatal("failed attempt replayed")
			}
		})
	}
}
func TestInitialChooserLateCallbacksAndDisabledFinalObservationNeverPost(t *testing.T) {
	for _, point := range []string{"discovery", "readiness", "geometry", "final observation", "disabled again", "cancel at geometry", "exit at geometry", "cancel at final observation", "exit at final observation"} {
		t.Run(point, func(t *testing.T) {
			f, c := newInitialChooserFixture()
			expire := func() { f.now = c.deadline }
			switch point {
			case "discovery":
				f.onDiscover = expire
			case "readiness":
				f.onObserve = expire
			case "geometry":
				f.onVisibility = expire
			case "final observation":
				f.onObserve = func() {
					if f.observations == 2 {
						expire()
					}
				}
			case "disabled again":
				f.onObserve = func() {
					if f.observations == 2 {
						f.disabled = 2
					}
				}
			case "cancel at geometry":
				f.onVisibility = func() { f.canceled = true }
			case "exit at geometry":
				f.onVisibility = func() { f.exited = true }
			case "cancel at final observation":
				f.onObserve = func() {
					if f.observations == 2 {
						f.canceled = true
					}
				}
			case "exit at final observation":
				f.onObserve = func() {
					if f.observations == 2 {
						f.exited = true
					}
				}
			}
			err := c.Discover(f.record)
			if err == nil {
				err = c.Click(f.record)
			}
			if err != ErrGuard || f.posts != 0 || f.waits != 0 {
				t.Fatal("late/terminal readiness posted or retried")
			}
			if c.Click(f.record) != ErrGuard || f.posts != 0 {
				t.Fatal("failed attempt replayed")
			}
		})
	}
}
func TestInitialChooserInvalidIdentityAndAPIErrorsAreTerminal(t *testing.T) {
	for _, point := range []string{"discovery", "readiness", "pre-post"} {
		for _, failure := range []string{"API", "process", "thread", "root", "chooser", "missing", "same handle"} {
			t.Run(point+"/"+failure, func(t *testing.T) {
				f, c := newInitialChooserFixture()
				breakIdentity := func() {
					switch failure {
					case "API":
						f.discoverError, f.observeError = true, true
					case "process":
						f.identity.Process++
					case "thread":
						if point == "discovery" {
							f.identity.Thread = 0
						} else {
							f.identity.Thread++
						}
					case "root":
						if point == "discovery" {
							f.identity.Root = 0
						} else {
							f.identity.Root++
						}
					case "chooser":
						if point == "discovery" {
							f.identity.Control = 0
						} else {
							f.identity.Control++
						}
					case "missing":
						f.identity = InitialChooserIdentity{}
						f.observeError = true
						f.discoverError = true
					case "same handle":
						f.identity.Control = f.identity.Root
					}
				}
				if point == "discovery" {
					f.onDiscover = breakIdentity
				} else {
					f.onObserve = func() {
						if point == "readiness" || f.observations == 2 {
							breakIdentity()
						}
					}
				}
				err := c.Discover(f.record)
				if err == nil {
					err = c.Click(f.record)
				}
				if err != ErrGuard || f.posts != 0 || f.waits != 0 {
					t.Fatal("invalid identity/API error retried or posted")
				}
				if c.Click(f.record) != ErrGuard || f.posts != 0 {
					t.Fatal("failed attempt replayed")
				}
			})
		}
	}
}
func TestInitialChooserExitAndCancellationStopDiscoveryAndReadiness(t *testing.T) {
	for _, discovery := range []bool{false, true} {
		for _, cancellation := range []bool{false, true} {
			f, c := newInitialChooserFixture()
			if discovery {
				f.absent = 5
			} else {
				f.disabled = 5
			}
			f.onWait = func() {
				if cancellation {
					f.canceled = true
				} else {
					f.exited = true
				}
			}
			err := c.Discover(f.record)
			if err == nil {
				err = c.Click(f.record)
			}
			want := "initial-chooser-process"
			if cancellation {
				want = "initial-chooser-context"
			}
			if err != ErrGuard || f.posts != 0 || f.waits != 1 || f.stage != want {
				t.Fatal("terminal observation was polled")
			}
		}
	}
}
func TestInitialChooserEveryGeometryFailureStopsWithoutRetry(t *testing.T) {
	for _, operation := range clickOperationOrder[3:16] {
		f, c := newInitialChooserFixture()
		f.trace.fail = map[string]bool{operation: true}
		if c.Discover(f.record) != nil || c.Click(f.record) != ErrGuard || f.posts != 0 || f.waits != 0 || f.stage != "chooser-click-"+operation {
			t.Fatalf("geometry guard %s lost", operation)
		}
		if c.Click(f.record) != ErrGuard || f.posts != 0 {
			t.Fatal("geometry failure retried")
		}
	}
}
func TestInitialChooserFailedPostIsSpentAndNeverRepeated(t *testing.T) {
	f, c := newInitialChooserFixture()
	f.postFailed = true
	if c.Discover(f.record) != nil || c.Click(f.record) != ErrGuard || f.posts != 1 || f.stage != "initial-chooser-post" {
		t.Fatal("failed post lost")
	}
	if c.Click(f.record) != ErrGuard || f.posts != 1 {
		t.Fatal("failed post retried")
	}
}
func TestInitialChooserMalformedCallsAndRepeatedDiscoveryAreInert(t *testing.T) {
	f, c := newInitialChooserFixture()
	if c.Click(f.record) != ErrGuard || c.Discover(f.record) != ErrGuard || f.posts != 0 || f.discoveries != 0 {
		t.Fatal("premature click did not spend attempt")
	}
	f, c = newInitialChooserFixture()
	if c.Discover(f.record) != nil || c.Discover(f.record) != ErrGuard || c.Click(f.record) != ErrGuard || f.discoveries != 1 || f.posts != 0 {
		t.Fatal("discovery replayed")
	}
	for i := 0; i < reflect.TypeOf(InitialChooserSteps{}).NumField(); i++ {
		f, c := newInitialChooserFixture()
		steps := c.steps
		reflect.ValueOf(&c.steps).Elem().Field(i).SetZero()
		if c.Discover(f.record) != ErrGuard || f.discoveries != 0 {
			t.Fatal("missing callback executed")
		}
		c.steps = steps
		if c.Discover(f.record) != ErrGuard {
			t.Fatal("malformed discovery replayed")
		}
	}
	f, c = newInitialChooserFixture()
	if c.Discover(f.record) != nil || c.Click(nil) != ErrGuard || c.Click(f.record) != ErrGuard || f.posts != 0 {
		t.Fatal("malformed click replayed")
	}
}

func TestInitialChooserRemainingBudgetCapsWaitAndLateInitialCallFails(t *testing.T) {
	f, c := newInitialChooserFixture()
	if c.Discover(f.record) != nil {
		t.Fatal("discovery failed")
	}
	f.now = c.deadline.Add(-25 * time.Millisecond)
	f.disabled = 2
	if c.Click(f.record) != ErrGuard || f.waits != 1 || !f.now.Equal(c.deadline) || f.posts != 0 {
		t.Fatal("last wait exceeded original deadline")
	}
	f, c = newInitialChooserFixture()
	if c.Discover(f.record) != nil {
		t.Fatal("discovery failed")
	}
	f.now = c.deadline
	if c.Click(f.record) != ErrGuard || f.observations != 0 || f.posts != 0 {
		t.Fatal("expired discovered chooser accepted")
	}
}

func TestInitialChooserWaitErrorIsTerminalAndPrivate(t *testing.T) {
	f, c := newInitialChooserFixture()
	f.disabled = 2
	c.steps.Wait = func(time.Duration) error { return errors.New("private wait API error") }
	if c.Discover(f.record) != nil || c.Click(f.record) != ErrGuard || f.posts != 0 || f.observations != 1 {
		t.Fatal("wait error retried or exposed")
	}
	if c.Click(f.record) != ErrGuard || f.posts != 0 {
		t.Fatal("wait failure replayed")
	}
}
