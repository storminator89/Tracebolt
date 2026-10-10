package setupgate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type initialChooserTrace struct {
	attempt                                       InitialChooserAttempt
	now, deadline                                 time.Time
	discoveries, pins, observations, waits, posts int
	stages                                        []string
	steps                                         InitialChooserSteps
	click                                         ClickSteps
}

func newInitialChooserTrace() *initialChooserTrace {
	tr := &initialChooserTrace{now: time.Unix(1000, 0)}
	tr.deadline = tr.now.Add(15 * time.Second)
	tr.steps = InitialChooserSteps{
		InitialChooserBinding: InitialChooserBinding{
			Now:   func() time.Time { return tr.now },
			Alive: func() bool { return true }, Owned: func() bool { return true },
		},
		Discover: func() (bool, error) { tr.discoveries++; return true, nil },
		Pin:      func() bool { tr.pins++; return true },
		Enabled:  func() (bool, error) { tr.observations++; return true, nil },
		Wait:     func(_ context.Context, delay time.Duration) error { tr.waits++; tr.now = tr.now.Add(delay); return nil },
	}
	tr.click = ClickSteps{
		Control: func() bool { return true }, Enabled: func() bool { return true },
		Visibility: func() error { return nil }, Post: func() bool { tr.posts++; return true },
	}
	return tr
}
func (tr *initialChooserTrace) stage(s string) { tr.stages = append(tr.stages, s) }
func (tr *initialChooserTrace) await(ctx context.Context) error {
	return AwaitInitialChooser(ctx, tr.deadline, tr.stage, tr.steps)
}
func (tr *initialChooserTrace) post(ctx context.Context) error {
	return tr.attempt.Click(ctx, tr.deadline, tr.stage, tr.steps.InitialChooserBinding, tr.click)
}
func (tr *initialChooserTrace) last() string { return tr.stages[len(tr.stages)-1] }

func TestInitialChooserDisabledThenEnabledOnlyPostsAfterReadiness(t *testing.T) {
	tr := newInitialChooserTrace()
	tr.steps.Enabled = func() (bool, error) { tr.observations++; return tr.observations == 3, nil }
	if tr.await(context.Background()) != nil || tr.posts != 0 || tr.discoveries != 1 || tr.pins != 1 || tr.observations != 3 || tr.waits != 2 {
		t.Fatalf("readiness rediscovered, repinned, posted, or failed: %+v", tr)
	}
	if tr.post(context.Background()) != nil || tr.posts != 1 || tr.last() != "chooser-click-post" {
		t.Fatal("first guarded click did not post exactly once")
	}
}

func TestInitialChooserDiscoveryAndReadinessShareOriginalBudget(t *testing.T) {
	tr := newInitialChooserTrace()
	tr.steps.Discover = func() (bool, error) {
		tr.discoveries++
		tr.now = tr.now.Add(14950 * time.Millisecond)
		return true, nil
	}
	tr.steps.Enabled = func() (bool, error) { tr.observations++; return false, nil }
	var waited time.Duration
	tr.steps.Wait = func(_ context.Context, d time.Duration) error {
		waited += d
		tr.now = tr.now.Add(d)
		return nil
	}
	if tr.await(context.Background()) != ErrGuard || waited != 50*time.Millisecond || tr.observations != 1 || tr.pins != 1 || tr.discoveries != 1 || !tr.now.Equal(tr.deadline) || tr.posts != 0 || tr.last() != "chooser-ready-deadline" {
		t.Fatal("discovery reset/extended the launch budget or final wait overshot it")
	}
}

func TestInitialChooserAbsentDiscoveryAndDisabledTimeout(t *testing.T) {
	for _, absent := range []bool{false, true} {
		tr := newInitialChooserTrace()
		tr.steps.Discover = func() (bool, error) { tr.discoveries++; return !absent, nil }
		tr.steps.Enabled = func() (bool, error) { tr.observations++; return false, nil }
		if tr.await(context.Background()) != ErrGuard || tr.posts != 0 || !tr.now.Equal(tr.deadline) || tr.last() != "chooser-ready-deadline" {
			t.Fatal("unready chooser escaped the original budget")
		}
		if absent && (tr.pins != 0 || tr.observations != 0) || !absent && (tr.pins != 1 || tr.discoveries != 1) {
			t.Fatal("discovery/pinning repeated after discovery")
		}
	}
}

func TestInitialChooserLateCallbacksAndCancellationNeverPost(t *testing.T) {
	for _, phase := range []string{"discovery", "enabled", "wait", "before-click", "visibility", "post-enabled"} {
		for _, cancelInstead := range []bool{false, true} {
			t.Run(phase+map[bool]string{false: "/deadline", true: "/cancel"}[cancelInstead], func(t *testing.T) {
				tr := newInitialChooserTrace()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				stop := func() {
					if cancelInstead {
						cancel()
					} else {
						tr.now = tr.deadline
					}
				}
				switch phase {
				case "discovery":
					tr.steps.Discover = func() (bool, error) { stop(); return true, nil }
				case "enabled":
					tr.steps.Enabled = func() (bool, error) { stop(); return true, nil }
				case "wait":
					tr.steps.Enabled = func() (bool, error) { return false, nil }
					tr.steps.Wait = func(context.Context, time.Duration) error { stop(); return nil }
				}
				err := tr.await(ctx)
				if phase == "before-click" || phase == "visibility" || phase == "post-enabled" {
					if err != nil {
						t.Fatal("initial readiness failed")
					}
					switch phase {
					case "before-click":
						stop()
					case "visibility":
						tr.click.Visibility = func() error { stop(); return nil }
					case "post-enabled":
						n := 0
						tr.click.Enabled = func() bool {
							n++
							if n == 2 {
								stop()
							}
							return true
						}
					}
					err = tr.post(ctx)
				}
				if err != ErrGuard || tr.posts != 0 || tr.last() != "chooser-ready-deadline" {
					t.Fatal("late/cancelled observation posted or escaped")
				}
			})
		}
	}
}

func TestInitialChooserFailuresNeverRetryOrLeakErrors(t *testing.T) {
	private := errors.New("private native handle/path/result")
	for _, failure := range []string{"discovery-api", "pin", "process-before", "process-after", "owned-before", "owned-after", "enabled-api", "wait-error"} {
		t.Run(failure, func(t *testing.T) {
			tr := newInitialChooserTrace()
			want := "chooser-ready-owned"
			switch failure {
			case "discovery-api":
				tr.steps.Discover = func() (bool, error) { tr.discoveries++; return false, private }
				want = "chooser-ready-discovery"
			case "pin":
				tr.steps.Pin = func() bool { tr.pins++; return false }
			case "process-before":
				tr.steps.Alive = func() bool { return false }
				want = "chooser-ready-process"
			case "process-after":
				tr.steps.Alive = func() bool { return tr.observations == 0 }
				want = "chooser-ready-process"
			case "owned-before":
				tr.steps.Owned = func() bool { return false }
			case "owned-after":
				tr.steps.Owned = func() bool { return tr.observations == 0 }
			case "enabled-api":
				tr.steps.Enabled = func() (bool, error) { tr.observations++; return false, private }
				want = "chooser-ready-enabled"
			case "wait-error":
				tr.steps.Enabled = func() (bool, error) { tr.observations++; return false, nil }
				tr.steps.Wait = func(context.Context, time.Duration) error { return private }
				want = "chooser-ready-deadline"
			}
			if tr.await(context.Background()) != ErrGuard || tr.posts != 0 || tr.discoveries > 1 || tr.pins > 1 || tr.observations > 1 || tr.waits != 0 || tr.last() != want {
				t.Fatalf("failure retried or leaked: %+v", tr)
			}
		})
	}
}

func TestInitialChooserFirstClickKeepsExistingGuardsAndSinglePost(t *testing.T) {
	for _, failure := range []string{"control", "enabled", "dpi-set", "visible", "root", "not-iconic", "control-rect", "client-rect", "client-top-left", "client-bottom-right", "monitor", "monitor-info", "client-contained", "work-contained", "dpi-restore", "post"} {
		t.Run(failure, func(t *testing.T) {
			tr := newInitialChooserTrace()
			if tr.await(context.Background()) != nil {
				t.Fatal("initial readiness failed")
			}
			click := &clickTrace{fail: map[string]bool{failure: true}}
			tr.click = click.click("chooser-click")
			originalPost := tr.click.Post
			tr.click.Post = func() bool { tr.posts++; return originalPost() }
			if tr.post(context.Background()) != ErrGuard || tr.posts > 1 || failure != "post" && tr.posts != 0 {
				t.Fatal("failed click posted/retried")
			}
			last := tr.last()
			if failure != "control" && failure != "enabled" && failure != "post" {
				last = click.stages[len(click.stages)-1]
			}
			if last != "chooser-click-"+failure {
				t.Fatalf("specific existing failure label lost: %s", last)
			}
		})
	}
	for _, failure := range []string{"process", "owned", "redisabled"} {
		tr := newInitialChooserTrace()
		if tr.await(context.Background()) != nil {
			t.Fatal("initial readiness failed")
		}
		// The binding and click callbacks capture dynamic state, as native HWND
		// observations do, rather than replacing the copied function fields.
		alive, owned, enabled := true, true, true
		tr.steps.Alive = func() bool { return alive }
		tr.steps.Owned = func() bool { return owned }
		tr.click.Enabled = func() bool { return enabled }
		tr.click.Visibility = func() error {
			switch failure {
			case "process":
				alive = false
			case "owned":
				owned = false
			case "redisabled":
				enabled = false
			}
			return nil
		}
		if tr.post(context.Background()) != ErrGuard || tr.posts != 0 {
			t.Fatal("changed binding or re-disabled control posted")
		}
	}
}

func TestInitialChooserOwnershipRejectsEveryChangedPinOrNativeFailure(t *testing.T) {
	w := InitialChooserWindows{Root: 10, Control: 11, PID: 12, RootThread: 13, ControlThread: 13}
	for _, failure := range []string{"", "root-invalid", "control-invalid", "root-foreign", "control-foreign", "root-api", "control-api", "root-thread", "control-thread", "root-replaced", "control-root", "control-parent", "control-replaced", "control-lost"} {
		t.Run(failure, func(t *testing.T) {
			s := InitialChooserWindowSteps{
				Valid: func(h uintptr) bool {
					return !(h == w.Root && failure == "root-invalid" || h == w.Control && failure == "control-invalid")
				},
				Owner: func(h uintptr) (uint32, uint32, error) {
					if h == w.Root && failure == "root-api" || h == w.Control && failure == "control-api" {
						return 0, 0, errors.New("private native failure")
					}
					if h == w.Root && failure == "root-foreign" || h == w.Control && failure == "control-foreign" {
						return 99, 13, nil
					}
					if h == w.Root && failure == "root-thread" || h == w.Control && failure == "control-thread" {
						return w.PID, 99, nil
					}
					return w.PID, 13, nil
				},
				Root: func(h uintptr) uintptr {
					if h == w.Root && failure == "root-replaced" || h == w.Control && failure == "control-root" {
						return 90
					}
					return w.Root
				},
				Parent: func(uintptr) uintptr {
					if failure == "control-parent" {
						return 90
					}
					return w.Root
				},
				Control: func(uintptr) uintptr {
					if failure == "control-lost" {
						return 0
					}
					if failure == "control-replaced" {
						return 90
					}
					return w.Control
				},
			}
			if OwnsInitialChooser(w, s) != (failure == "") {
				t.Fatal("changed/foreign/missing pin or native failure accepted")
			}
		})
	}
}

func TestInitialChooserInvalidInputsAreInert(t *testing.T) {
	for _, field := range []string{"Now", "Alive", "Owned", "Discover", "Pin", "Enabled", "Wait"} {
		tr := newInitialChooserTrace()
		reflect.ValueOf(&tr.steps).Elem().FieldByName(field).SetZero()
		if tr.await(context.Background()) != ErrGuard || len(tr.stages) != 0 || tr.discoveries != 0 || tr.pins != 0 || tr.posts != 0 {
			t.Fatal("missing callback executed")
		}
	}
	for _, mode := range []string{"nil-context", "nil-stage", "zero-deadline"} {
		tr := newInitialChooserTrace()
		ctx := context.Background()
		stage := tr.stage
		if mode == "nil-context" {
			ctx = nil
		}
		if mode == "nil-stage" {
			stage = nil
		}
		if mode == "zero-deadline" {
			tr.deadline = time.Time{}
		}
		if AwaitInitialChooser(ctx, tr.deadline, stage, tr.steps) != ErrGuard || tr.attempt.Click(ctx, tr.deadline, stage, tr.steps.InitialChooserBinding, tr.click) != ErrGuard || len(tr.stages) != 0 {
			t.Fatal("invalid input executed")
		}
	}
}

func TestInitialChooserNativeOptInBoundary(t *testing.T) {
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join("..", "..", "..", "cmd", "windows-service", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	controller := read("setup_acceptance_native_windows_test.go")
	ui := read("setup_acceptance_ui_windows_test.go")
	if strings.Count(controller, "setupLaunchInitialChooser(ctx, exe,") != 2 ||
		!strings.Contains(controller, "preflight, err = setupLaunchInitialChooser(ctx, exe, stage)") ||
		!strings.Contains(controller, "g, e := setupLaunchInitialChooser(ctx, exe, func(s string) { r.Stage = s })") ||
		strings.Count(controller, "setupLaunch(ctx, exe)") != 3 {
		t.Fatal("initial readiness opt-in escaped the two initial public-bootstrap launches")
	}
	for _, unchanged := range []string{
		`return setupLaunchObserved(ctx, path, false, func(string) {})`,
		`else if setupAwait(ctx, 15*time.Second, func() bool { g.window = setupWindow(g.pid, "TraceboltFreshSetupWizard"); return g.window != 0 }) != nil`,
		`else if setupClickObserved(g.window, 102, "chooser-click", stage) != nil`,
		`setupClickObserved(dialog, 1, "chooser-open", stage)`,
		`setupAwait(ctx, 10*time.Second, func() bool { dialog = setupWindow(g.pid, "#32770"); return dialog != 0 })`,
		`return setupAwait(ctx, 10*time.Second, func() bool { return setupWindow(g.pid, "#32770") == 0 && setupEnabled(setupControl(g.window, 1)) })`,
	} {
		if !strings.Contains(ui, unchanged) {
			t.Fatal("ordinary launch/click or chooser dialog postcondition changed")
		}
	}
	if strings.Count(ui, "//go:uintptrescapes") != 3 || strings.Count(ui, "initialChooserDeadline = time.Now().Add(15 * time.Second)") != 1 {
		t.Fatal("pointer lifetime or single deadline boundary changed")
	}
}

func TestInitialChooserAttemptIsSpentBeforeSuccessOrFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		tr := newInitialChooserTrace()
		tr.click.Enabled = func() bool { return !fail }
		err := tr.post(context.Background())
		if (err == nil) == fail {
			t.Fatal("first attempt result changed")
		}
		operations := len(tr.stages)
		tr.click.Enabled = func() bool { return true }
		if tr.post(context.Background()) != ErrGuard || len(tr.stages) != operations || tr.posts > 1 || fail && tr.posts != 0 {
			t.Fatal("spent attempt retried")
		}
	}
}

func TestInitialChooserInvalidDisabledObservationNeverWaits(t *testing.T) {
	tr := newInitialChooserTrace()
	tr.steps.Enabled = func() (bool, error) { tr.observations++; return false, nil }
	tr.steps.Owned = func() bool { return tr.observations == 0 }
	if tr.await(context.Background()) != ErrGuard || tr.observations != 1 || tr.waits != 0 || tr.pins != 1 || tr.discoveries != 1 || tr.posts != 0 || tr.last() != "chooser-ready-owned" {
		t.Fatal("invalid HWND was treated as retryable disabled state")
	}
}

func TestInitialChooserSuccessAllowsOrdinaryLaterClickWithoutReadiness(t *testing.T) {
	tr := newInitialChooserTrace()
	if tr.await(context.Background()) != nil || tr.post(context.Background()) != nil {
		t.Fatal("initial chooser failed")
	}
	// Mirrors the native success-only transition. The later ordinary click has
	// no launch budget or new readiness loop; existing CheckClick guards apply.
	tr.now = tr.deadline.Add(time.Hour)
	tr.click.Enabled = func() bool { return false }
	observations, waits := tr.observations, tr.waits
	if CheckClick(tr.stage, "chooser-click", tr.click) != ErrGuard || tr.posts != 1 || tr.observations != observations || tr.waits != waits || tr.last() != "chooser-click-enabled" {
		t.Fatal("later generic click acquired readiness waiting")
	}
	tr.click.Enabled = func() bool { return true }
	if CheckClick(tr.stage, "chooser-click", tr.click) != nil || tr.posts != 2 || tr.observations != observations || tr.waits != waits {
		t.Fatal("later generic click incorrectly reused the expired initial deadline")
	}
}
