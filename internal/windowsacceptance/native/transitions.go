package native

import "localrmm/internal/windowsservice"

// transitionObservation distinguishes orderly acceptance from cleanup of a
// failed owned service. It is a pure decision over one receipt-bound SCM result.
func transitionObservation(s windowsservice.Snapshot, want windowsservice.State, cleanupOnly bool) (arrived, rejected bool) {
	if !s.Exists {
		return false, true
	}
	if want == windowsservice.Running && s.State == windowsservice.Stopped {
		return false, true
	}
	if s.State != want {
		return false, false
	}
	if want == windowsservice.Stopped && !cleanupOnly && (s.Win32ExitCode != 0 || s.ServiceSpecificExitCode != 0) {
		return false, true
	}
	return true, false
}
