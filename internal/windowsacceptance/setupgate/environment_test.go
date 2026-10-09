package setupgate

import (
	"errors"
	"reflect"
	"testing"
)

func TestControllerEnvironmentUsesOnlyValidatedDerivedDrive(t *testing.T) {
	for _, root := range []string{`C:\Windows`, `D:\WinNT`} {
		calls := []string{}
		err := PrepareControllerEnvironment(func() (string, error) { calls = append(calls, "get"); return root, nil }, func(key, value string) error { calls = append(calls, key+"="+value); return nil })
		if err != nil || !reflect.DeepEqual(calls, []string{"get", "SystemDrive=" + root[:2]}) {
			t.Fatal("unexpected environment propagation", calls)
		}
	}
}
func TestControllerEnvironmentFailsClosedAndRedacts(t *testing.T) {
	private := errors.New("private native error and path")
	for _, root := range []string{"", `C:Windows`, `\\server\share\Windows`, `\\?\C:\Windows`, `C:\Windows\..\Other`, `C:\%ROOT%`, `C:\*`, "C:\\Windows\x00", `/Windows`, `C:\`} {
		called := false
		err := PrepareControllerEnvironment(func() (string, error) { return root, nil }, func(string, string) error { called = true; return nil })
		if err != ErrGuard || called {
			t.Fatal("invalid directory reached environment update")
		}
	}
	called := false
	if err := PrepareControllerEnvironment(func() (string, error) { return `C:\Windows`, private }, func(string, string) error { called = true; return nil }); err != ErrGuard || called {
		t.Fatal("native error reached environment update")
	}
	calls := 0
	if err := PrepareControllerEnvironment(func() (string, error) { return `C:\Windows`, nil }, func(key, value string) error { calls++; return private }); err != ErrGuard || calls != 1 {
		t.Fatal("environment failure hidden or retried")
	}
	if PrepareControllerEnvironment(nil, nil) != ErrGuard {
		t.Fatal("missing dependency accepted")
	}
}

func TestFreshFailureStagesStayFiniteAndInert(t *testing.T) {
	_, b, _ := authorized()
	for _, stage := range []string{"fresh-environment", "fresh-layout", "fresh-service", "fresh-program-files", "fresh-program-data"} {
		r := NewReport(b)
		r.ApprovalValidated = true
		r.Stage, r.Reason = stage, "operation_failed"
		if r.Validate() != nil {
			t.Fatal("finite fresh failure rejected", stage)
		}
		r.NativeActionsAttempted = true
		if r.Validate() == nil {
			t.Fatal("blocked stage claimed native actions", stage)
		}
		r.NativeActionsAttempted = false
		r.Stage = "private path or native error"
		if r.Validate() == nil {
			t.Fatal("unbounded stage accepted")
		}
	}
}

func TestFreshPrerequisitePipelineStopsBeforeLaterChecks(t *testing.T) {
	labels := []string{"fresh-environment", "fresh-layout", "fresh-service", "fresh-program-files", "fresh-program-data"}
	private := errors.New("private path and native error")
	// -1 succeeds; each other iteration fails at exactly one native prerequisite.
	for failure := -1; failure < len(labels); failure++ {
		for _, missing := range []bool{false, true} {
			calls, stages := []string{}, []string{}
			callbacks := make([]func() error, len(labels))
			for i := range callbacks {
				callbacks[i] = func() error {
					calls = append(calls, labels[i])
					if failure == i {
						return private
					}
					return nil
				}
			}
			if missing && failure >= 0 {
				callbacks[failure] = nil
			}
			checks := FreshPrerequisites{callbacks[0], callbacks[1], callbacks[2], callbacks[3], callbacks[4]}
			err := CheckFreshPrerequisites(func(stage string) { stages = append(stages, stage) }, checks)
			count := len(labels)
			if failure >= 0 {
				count = failure + 1
				if err != ErrGuard {
					t.Fatal("failure not redacted or accepted", failure)
				}
			} else if err != nil {
				t.Fatal("valid sequence rejected")
			}
			if !reflect.DeepEqual(stages, labels[:count]) {
				t.Fatal("wrong stage or later stage ran", stages)
			}
			if missing && failure >= 0 {
				count--
			}
			if !reflect.DeepEqual(calls, labels[:count]) {
				t.Fatal("later prerequisite ran", calls)
			}
		}
	}
	if CheckFreshPrerequisites(nil, FreshPrerequisites{}) != ErrGuard {
		t.Fatal("missing stage sink accepted")
	}
}
