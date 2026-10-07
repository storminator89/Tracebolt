package native

import (
	"localrmm/internal/windowsservice"
	"testing"
)

func TestOrderlyAcceptanceStopRejectsNativeFailureExitCodes(t *testing.T) {
	for _, codes := range [][2]uint32{{1, 0}, {1066, 1}, {0, 1}} {
		s := windowsservice.Snapshot{Exists: true, State: windowsservice.Stopped, Win32ExitCode: codes[0], ServiceSpecificExitCode: codes[1]}
		if arrived, rejected := transitionObservation(s, windowsservice.Stopped, false); arrived || !rejected {
			t.Fatal("failed service counted as orderly Stop")
		}
		if arrived, rejected := transitionObservation(s, windowsservice.Stopped, true); !arrived || rejected {
			t.Fatal("failed owned service cannot reach cleanup-only absence")
		}
	}
}
func TestTransitionObservationNeedsExistingWantedState(t *testing.T) {
	for _, cleanupOnly := range []bool{false, true} {
		if a, r := transitionObservation(windowsservice.Snapshot{Exists: true, State: windowsservice.Stopped}, windowsservice.Stopped, cleanupOnly); !a || r {
			t.Fatal("orderly Stop rejected")
		}
		if a, r := transitionObservation(windowsservice.Snapshot{Exists: true, State: windowsservice.StopPending}, windowsservice.Stopped, cleanupOnly); a || r {
			t.Fatal("pending state is terminal")
		}
		if a, r := transitionObservation(windowsservice.Snapshot{State: windowsservice.Stopped}, windowsservice.Stopped, cleanupOnly); a || !r {
			t.Fatal("missing service counted as owned Stop")
		}
		if a, r := transitionObservation(windowsservice.Snapshot{Exists: true, State: windowsservice.Stopped}, windowsservice.Running, cleanupOnly); a || !r {
			t.Fatal("failed startup became running")
		}
	}
}
