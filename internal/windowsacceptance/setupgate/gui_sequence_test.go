package setupgate

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestPreflightSequenceEveryFailureStops(t *testing.T) {
	labels := []string{"preflight-launch", "preflight-choose", "preflight-consent", "preflight-cancel-click", "preflight-exit", "preflight-fresh-service", "preflight-fresh-program-files", "preflight-fresh-program-data"}
	for fail := -1; fail < len(labels); fail++ {
		var seen []string
		last := ""
		callbacks := make([]func() error, len(labels))
		for i := range callbacks {
			i := i
			callbacks[i] = func() error {
				seen = append(seen, labels[i])
				if fail == i {
					return errors.New("private callback detail")
				}
				return nil
			}
		}
		err := CheckPreflight(func(s string) { last = s }, PreflightSteps{callbacks[0], callbacks[1], callbacks[2], callbacks[3], callbacks[4], callbacks[5], callbacks[6], callbacks[7]})
		n := len(labels)
		if fail >= 0 {
			n = fail + 1
			if err != ErrGuard {
				t.Fatalf("failure %d escaped", fail)
			}
		} else if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(seen, labels[:n]) || last != labels[n-1] {
			t.Fatalf("failure %d: %v %s", fail, seen, last)
		}
	}
	if CheckPreflight(nil, PreflightSteps{}) != ErrGuard || CheckPreflight(func(string) {}, PreflightSteps{}) != ErrGuard {
		t.Fatal("missing callbacks accepted")
	}
}

type consentEvent struct{ name, stage string }

func consentFixture(http bool, fail int) (error, []consentEvent, string) {
	var events []consentEvent
	stage := ""
	call := func(name string) bool {
		events = append(events, consentEvent{name, stage})
		return len(events)-1 == fail
	}
	run := func(name string) func() error {
		return func() error {
			if call(name) {
				return errors.New("private")
			}
			return nil
		}
	}
	err := CheckConsent(func(v string) { stage = v }, http, ConsentSteps{Next: run("next"), WaitReview: run("review"), Back: run("back"), WaitInput: run("input"), WaitEnabled: run("enabled"), NextEnabled: func() bool { return call("disabled") }, Present: func(id int) bool { return call(fmt.Sprintf("present-%d", id)) }, Unchecked: func(id int) error { return run(fmt.Sprintf("unchecked-%d", id))() }, ClickChecked: func(id int) error { return run(fmt.Sprintf("checked-%d", id))() }})
	return err, events, stage
}
func TestConsentSequenceEveryFailureStops(t *testing.T) {
	for _, http := range []bool{false, true} {
		err, baseline, _ := consentFixture(http, -1)
		if err != nil {
			t.Fatal(err)
		}
		var expected []string
		expected = append(expected, "next", "review")
		if !http {
			expected = append(expected, "present-108")
		}
		for pass := 0; pass < 2; pass++ {
			expected = append(expected, "disabled")
			for _, prefix := range []string{"unchecked", "checked"} {
				for id := 104; id <= 107; id++ {
					expected = append(expected, fmt.Sprintf("%s-%d", prefix, id))
				}
				if http {
					expected = append(expected, prefix+"-108")
				}
			}
			expected = append(expected, "enabled")
			if pass == 0 {
				expected = append(expected, "back", "input", "next", "review")
			}
		}
		var actual []string
		for _, e := range baseline {
			actual = append(actual, e.name)
			if !Contains(Stages, e.stage) {
				t.Fatalf("unregistered stage %s", e.stage)
			}
		}
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("http=%v: %v", http, actual)
		}
		for fail, want := range baseline {
			err, events, stage := consentFixture(http, fail)
			if err != ErrGuard || len(events) != fail+1 || stage != want.stage || !reflect.DeepEqual(events, baseline[:fail+1]) {
				t.Fatalf("http=%v fail=%d stage=%s want=%s calls=%d", http, fail, stage, want.stage, len(events))
			}
		}
	}
}
func TestConsentMissingCallbacksFailClosed(t *testing.T) {
	if CheckConsent(nil, true, ConsentSteps{}) != ErrGuard || CheckConsent(func(string) {}, true, ConsentSteps{}) != ErrGuard {
		t.Fatal("nil callback accepted")
	}
}
