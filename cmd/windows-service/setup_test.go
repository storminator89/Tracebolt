package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"localrmm/internal/windowsservice"
)

type setupFixture struct {
	steps         []string
	fail          string
	receiptWrites int
	prepared      bool
	raw           []byte
}

func (f *setupFixture) call(s string) error {
	f.steps = append(f.steps, s)
	if f.fail == s {
		return errors.New("synthetic failure")
	}
	return nil
}
func (f *setupFixture) Write(name string, b []byte) error {
	step := name
	if name == "receipt.json" {
		f.receiptWrites++
		var r installReceipt
		if json.Unmarshal(b, &r) != nil {
			return errors.New("fixture receipt")
		}
		if f.receiptWrites == 1 && r.Prepared || f.receiptWrites == 2 && !r.Prepared {
			return errors.New("prepared marker order")
		}
		if r.Prepared {
			step = "prepared-receipt"
			f.prepared = true
		}
	}
	return f.call(step)
}
func (f *setupFixture) Close() error { return f.call("close") }
func (f *setupFixture) operations() setupSteps {
	return setupSteps{
		plan: func(context.Context) (windowsservice.InstallPlan, error) {
			return windowsservice.InstallPlan{}, f.call("plan")
		},
		readBootstrap: func(string) ([]byte, error) {
			f.raw = []byte("synthetic-public-bootstrap")
			return f.raw, f.call("read-bootstrap")
		},
		validateBootstrap: func([]byte) error { return f.call("validate-bootstrap") },
		createJournal:     func(windowsservice.Layout) (setupJournal, error) { return f, f.call("create-journal") },
		apply: func(context.Context, windowsservice.InstallPlan) (windowsservice.Receipt, error) {
			err := f.call("apply")
			return windowsservice.Receipt{Complete: err == nil}, err
		},
		prepare:     func(windowsservice.Layout, windowsservice.Receipt, []byte) error { return f.call("prepare") },
		verifyOwned: func(context.Context, windowsservice.Receipt) error { return f.call("preclaim") },
		enroll: func(context.Context, windowsservice.Layout) error {
			if !f.prepared {
				return errors.New("unprepared enrollment")
			}
			return f.call("enroll")
		},
		start: func(context.Context, windowsservice.Receipt) (windowsservice.ApplyResult, error) {
			return windowsservice.ApplyResult{Requested: true}, f.call("start")
		},
	}
}
func TestSetupWritesIntentBeforeSCMAndPreparedReceiptBeforeEnrollment(t *testing.T) {
	f := &setupFixture{}
	if _, err := setup(context.Background(), "fixture", f.operations()); err != nil {
		t.Fatal("fixture setup failed")
	}
	want := []string{"plan", "read-bootstrap", "validate-bootstrap", "create-journal", "intent.json", "apply", "receipt.json", "prepare", "prepared-receipt", "close", "preclaim", "enroll", "start", "close"}
	if !reflect.DeepEqual(f.steps, want) {
		t.Fatal("setup side-effect order changed")
	}
	for _, b := range f.raw {
		if b != 0 {
			t.Fatal("retained bootstrap buffer not cleared")
		}
	}
}
func TestSetupFailuresNeverSkipReceiptOrStart(t *testing.T) {
	for _, stage := range []string{"plan", "read-bootstrap", "validate-bootstrap", "create-journal", "intent.json", "apply", "receipt.json", "prepare", "prepared-receipt", "close", "preclaim", "enroll"} {
		t.Run(stage, func(t *testing.T) {
			f := &setupFixture{fail: stage}
			if _, err := setup(context.Background(), "fixture", f.operations()); err == nil {
				t.Fatal("failed setup returned success")
			}
			for _, step := range f.steps {
				if step == "start" {
					t.Fatal("failed setup started service")
				}
			}
			if stage == "apply" && f.receiptWrites != 1 {
				t.Fatal("partial creation receipt was not retained")
			}
		})
	}
}
func TestSetupRejectsCancellationAndExistingServiceBeforeIntent(t *testing.T) {
	f := &setupFixture{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := setup(ctx, "fixture", f.operations()); err == nil || len(f.steps) != 0 {
		t.Fatal("cancelled setup touched backend")
	}
	s := f.operations()
	s.plan = func(context.Context) (windowsservice.InstallPlan, error) {
		return windowsservice.InstallPlan{Existing: windowsservice.Snapshot{Exists: true}}, nil
	}
	if _, err := setup(context.Background(), "fixture", s); err == nil || len(f.steps) != 0 {
		t.Fatal("existing service was adopted")
	}
}
