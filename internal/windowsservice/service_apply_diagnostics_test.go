package windowsservice

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
)

type applyDiagnosticService struct {
	*fakeService
	inspections int
	after       Snapshot
	afterError  error
}

func (s *applyDiagnosticService) Inspect() (Snapshot, error) {
	s.inspections++
	if s.inspections == 1 {
		return s.fakeService.Inspect()
	}
	return s.after, s.afterError
}

type applyDiagnosticBackend struct {
	*fakeBackend
	service *applyDiagnosticService
}

func (b *applyDiagnosticBackend) Open(a access) (service, error) {
	b.opened = append(b.opened, a)
	return b.service, nil
}

func applyDiagnosticFixture(t *testing.T, state State) (*applyDiagnosticBackend, Receipt) {
	t.Helper()
	b, receipt := installedFixture(t)
	b.s.snapshot.State = state
	b.s.closes = 0
	b.opened = nil
	s := &applyDiagnosticService{fakeService: b.s, after: b.s.snapshot}
	s.after.State = StopPending
	s.after.ProcessID = 123
	return &applyDiagnosticBackend{fakeBackend: b, service: s}, receipt
}

func TestApplyRemovalFailureDiagnosticsPreserveOperation(t *testing.T) {
	for _, step := range []struct {
		name, stage string
		access      access
		state       State
		inspections int
		requested   bool
	}{
		{"stop_control", "service_apply_stop_control", stopAccess, Running, 1, false},
		{"delete", "service_apply_delete", deleteAccess, Stopped, 1, false},
		{"stop_inspect", "service_apply_stop_inspect", stopAccess, Running, 2, true},
	} {
		for _, inner := range []bool{false, true} {
			name := step.name + "/raw"
			if inner {
				name = step.name + "/inner_binding_failure"
			}
			t.Run(name, func(t *testing.T) {
				b, receipt := applyDiagnosticFixture(t, step.state)
				cause := &os.PathError{Op: "inspect", Path: "private-fixture-path", Err: ErrMismatch}
				var fault error = cause
				wantStage, wantCategory := step.stage, "failed"
				if inner {
					// A nested binding failure retains its specific diagnosis even
					// when joined with cancellation; the outer action is less precise.
					fault = errors.Join(context.Canceled, setupStageError("service_owned_binding", "mismatch", cause))
					wantStage, wantCategory = "service_owned_binding", "mismatch"
				}
				switch step.name {
				case "stop_control":
					b.s.errorStop = fault
				case "delete":
					b.s.errorDelete = fault
				case "stop_inspect":
					b.service.afterError = fault
				}
				before := b.s.snapshot
				created, verified := b.created, b.verified
				result, err := apply(context.Background(), b, receipt, step.access)
				requireSetupDiagnostic(t, err, wantStage, wantCategory)
				var gotCause *os.PathError
				if !errors.Is(err, fault) || !errors.Is(err, ErrMismatch) || !errors.As(err, &gotCause) || gotCause != cause || err.Error() != fault.Error() {
					t.Fatal("diagnostic changed error identity, cause chain, or rendering")
				}
				wantSnapshot := before
				if step.requested {
					wantSnapshot = b.service.after
				}
				want := ApplyResult{Snapshot: wantSnapshot, Requested: step.requested, StateRetained: true}
				if !reflect.DeepEqual(result, want) {
					t.Fatalf("apply result changed: got %+v, want %+v", result, want)
				}
				wantStops, wantDeletes := 1, 0
				if step.access == deleteAccess {
					wantStops, wantDeletes = 0, 1
				}
				if b.s.starts != 0 || b.s.stops != wantStops || b.s.deletes != wantDeletes || b.s.closes != 1 || b.service.inspections != step.inspections ||
					!reflect.DeepEqual(b.opened, []access{step.access}) || b.created != created || b.verified != verified {
					t.Fatal("diagnostic added or changed a backend call")
				}
			})
		}
	}
}

func TestApplyRemovalDiagnosticsPreserveSuccess(t *testing.T) {
	for _, a := range []access{stopAccess, deleteAccess} {
		state := Running
		if a == deleteAccess {
			state = Stopped
		}
		b, receipt := applyDiagnosticFixture(t, state)
		before := b.s.snapshot
		result, err := apply(context.Background(), b, receipt, a)
		want := ApplyResult{Snapshot: b.service.after, Requested: true, StateRetained: true}
		wantInspections, wantStops, wantDeletes := 2, 1, 0
		if a == deleteAccess {
			want.Snapshot, want.DeletePending = before, true
			wantInspections, wantStops, wantDeletes = 1, 0, 1
		}
		if err != nil || !reflect.DeepEqual(result, want) || b.service.inspections != wantInspections || b.s.stops != wantStops || b.s.deletes != wantDeletes || b.s.starts != 0 || b.s.closes != 1 {
			t.Fatal("success behavior changed", result, err)
		}
	}
}

func TestApplyRemovalDiagnosticsLeaveStartErrorsUnchanged(t *testing.T) {
	for _, postInspect := range []bool{false, true} {
		b, receipt := applyDiagnosticFixture(t, Stopped)
		fault := errors.New("private start fixture error")
		if postInspect {
			b.service.afterError = fault
		} else {
			b.s.errorStart = fault
		}
		result, err := apply(context.Background(), b, receipt, startAccess)
		if err != fault || result.Requested != postInspect || !result.StateRetained || result.DeletePending || b.s.starts != 1 || b.s.stops != 0 || b.s.deletes != 0 || b.s.closes != 1 {
			t.Fatal("unrelated start failure behavior changed")
		}
		requireSetupDiagnostic(t, err, "unknown", "unknown")
	}
}
