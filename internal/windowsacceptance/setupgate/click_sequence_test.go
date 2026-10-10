package setupgate

import (
	"errors"
	"reflect"
	"testing"
)

type clickTrace struct {
	operations, stages []string
	fail               map[string]bool
}

func (trace *clickTrace) stage(stage string) { trace.stages = append(trace.stages, stage) }
func (trace *clickTrace) check(name string) func() bool {
	return func() bool {
		trace.operations = append(trace.operations, name)
		return !trace.fail[name]
	}
}
func (trace *clickTrace) visibility() ClickVisibilitySteps {
	return ClickVisibilitySteps{
		LockThread:   func() { trace.operations = append(trace.operations, "lock-thread") },
		UnlockThread: func() { trace.operations = append(trace.operations, "unlock-thread") },
		SetDPI:       trace.check("dpi-set"), RestoreDPI: trace.check("dpi-restore"),
		Visible: trace.check("visible"), Root: trace.check("root"), NotIconic: trace.check("not-iconic"),
		ControlRect: trace.check("control-rect"), ClientRect: trace.check("client-rect"),
		ClientTopLeft: trace.check("client-top-left"), ClientBottomRight: trace.check("client-bottom-right"),
		Monitor: trace.check("monitor"), MonitorInfo: trace.check("monitor-info"),
		ClientContained: trace.check("client-contained"), WorkContained: trace.check("work-contained"),
	}
}
func (trace *clickTrace) click(prefix string) ClickSteps {
	return ClickSteps{
		Control: trace.check("control"), Enabled: trace.check("enabled"), Post: trace.check("post"),
		Visibility: func() error { return CheckClickVisibility(trace.stage, prefix, trace.visibility()) },
	}
}

var clickOperationOrder = []string{
	"control", "enabled", "lock-thread", "dpi-set", "visible", "root", "not-iconic",
	"control-rect", "client-rect", "client-top-left", "client-bottom-right", "monitor",
	"monitor-info", "client-contained", "work-contained", "dpi-restore", "unlock-thread", "post",
}

func TestClickSequenceEveryBranchStopsAndCleansUp(t *testing.T) {
	for _, prefix := range []string{"chooser-click", "chooser-open"} {
		t.Run(prefix+"/success", func(t *testing.T) {
			trace := &clickTrace{}
			if err := CheckClick(trace.stage, prefix, trace.click(prefix)); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(trace.operations, clickOperationOrder) {
				t.Fatalf("operation order = %v", trace.operations)
			}
			if trace.stages[len(trace.stages)-1] != prefix+"-post" {
				t.Fatal("successful click did not finish at its one post")
			}
		})
		for i, failure := range clickOperationOrder {
			if failure == "lock-thread" || failure == "unlock-thread" {
				continue
			}
			t.Run(prefix+"/"+failure, func(t *testing.T) {
				trace := &clickTrace{fail: map[string]bool{failure: true}}
				if err := CheckClick(trace.stage, prefix, trace.click(prefix)); err != ErrGuard {
					t.Fatalf("failed branch returned %v", err)
				}
				want := append([]string{}, clickOperationOrder[:i+1]...)
				// GetDlgItem/enabled failures never lock. Failed DPI entry only
				// unlocks. Every entered context restores, even after a guard fails.
				if i >= 3 && i <= 15 {
					if i > 3 && i < 15 {
						want = append(want, "dpi-restore")
					}
					want = append(want, "unlock-thread")
				}
				if !reflect.DeepEqual(trace.operations, want) {
					t.Fatalf("operation order = %v, want %v", trace.operations, want)
				}
				last := trace.stages[len(trace.stages)-1]
				if last != prefix+"-"+failure || !Contains(ChooserClickFailureStages, last) {
					t.Fatalf("failure label = %s", last)
				}
				for _, stage := range trace.stages {
					if !Contains(ChooserClickFailureStages, stage) {
						t.Fatalf("nonfinite label = %s", stage)
					}
				}
			})
		}
	}
}

func TestClickRestoreFailureNeverMasksEarlierGuard(t *testing.T) {
	for _, prefix := range []string{"chooser-click", "chooser-open"} {
		for i := 4; i <= 14; i++ {
			failure := clickOperationOrder[i]
			t.Run(prefix+"/"+failure, func(t *testing.T) {
				trace := &clickTrace{fail: map[string]bool{failure: true, "dpi-restore": true}}
				if CheckClick(trace.stage, prefix, trace.click(prefix)) != ErrGuard {
					t.Fatal("failed guard accepted")
				}
				want := append(append([]string{}, clickOperationOrder[:i+1]...), "dpi-restore", "unlock-thread")
				if !reflect.DeepEqual(trace.operations, want) {
					t.Fatalf("cleanup order = %v, want %v", trace.operations, want)
				}
				if trace.stages[len(trace.stages)-1] != prefix+"-"+failure || Contains(trace.stages, prefix+"-dpi-restore") {
					t.Fatal("DPI restoration overwrote the original failed guard")
				}
			})
		}
	}
}

func TestClickInvalidInputsAndMissingCallbacksAreInert(t *testing.T) {
	for _, prefix := range []string{"", "chooser", "chooser-click-private-hwnd-path", "chooser-open-post"} {
		trace := &clickTrace{}
		if CheckClick(trace.stage, prefix, trace.click(prefix)) != ErrGuard || CheckClickVisibility(trace.stage, prefix, trace.visibility()) != ErrGuard || len(trace.operations) != 0 || len(trace.stages) != 0 {
			t.Fatal("unknown prefix was accepted or executed")
		}
	}
	trace := &clickTrace{}
	if CheckClick(nil, "chooser-click", trace.click("chooser-click")) != ErrGuard || CheckClickVisibility(nil, "chooser-click", trace.visibility()) != ErrGuard || len(trace.operations) != 0 {
		t.Fatal("missing observer was accepted or executed")
	}
	for _, visibility := range []bool{false, true} {
		var fields int
		if visibility {
			fields = reflect.TypeOf(ClickVisibilitySteps{}).NumField()
		} else {
			fields = reflect.TypeOf(ClickSteps{}).NumField()
		}
		for i := 0; i < fields; i++ {
			trace := &clickTrace{}
			var err error
			if visibility {
				steps := trace.visibility()
				reflect.ValueOf(&steps).Elem().Field(i).SetZero()
				err = CheckClickVisibility(trace.stage, "chooser-click", steps)
			} else {
				steps := trace.click("chooser-click")
				reflect.ValueOf(&steps).Elem().Field(i).SetZero()
				err = CheckClick(trace.stage, "chooser-click", steps)
			}
			if err != ErrGuard || len(trace.operations) != 0 || len(trace.stages) != 0 {
				t.Fatalf("visibility=%v missing callback %d executed or passed", visibility, i)
			}
		}
	}
}

func TestClickVisibilityErrorIsNotExposed(t *testing.T) {
	trace := &clickTrace{}
	steps := trace.click("chooser-open")
	steps.Visibility = func() error { return errors.New("private native error, handle and geometry") }
	if CheckClick(trace.stage, "chooser-open", steps) != ErrGuard || !reflect.DeepEqual(trace.operations, []string{"control", "enabled"}) {
		t.Fatal("private callback error escaped or click was posted")
	}
}

func TestChooserClickFailureStagesExactFiniteVocabulary(t *testing.T) {
	suffixes := []string{
		"control", "enabled", "dpi-set", "visible", "root", "not-iconic", "control-rect", "client-rect",
		"client-top-left", "client-bottom-right", "monitor", "monitor-info", "client-contained", "work-contained", "dpi-restore", "post",
	}
	var want []string
	for _, prefix := range []string{"chooser-click", "chooser-open"} {
		for _, suffix := range suffixes {
			want = append(want, prefix+"-"+suffix)
		}
	}
	if !reflect.DeepEqual(ChooserClickFailureStages, want) {
		t.Fatal("chooser branch vocabulary changed")
	}
}
