package main

import (
	"context"
	"fmt"
	"localrmm/internal/windowsservice"
	"syscall"
)

// removalFailure preserves the operation's original public error and unwrap
// identity. detail retains a swallowed inspection/wait cause for finite
// diagnosis only; it cannot alter cancellation, retry or removal decisions.
type removalFailure struct {
	step             string
	original, detail error
}

func (e *removalFailure) Error() string { return e.original.Error() }
func (e *removalFailure) Unwrap() error { return e.original }
func (e *removalFailure) Format(s fmt.State, v rune) {
	if v == 'q' {
		fmt.Fprintf(s, "%q", e.Error())
		return
	}
	fmt.Fprint(s, e.Error())
}
func (e *removalFailure) GoString() string { return e.Error() }

var removalSteps = []string{"validate", "context", "receipt", "owned", "state", "stop", "stop-observe", "stop-state", "stop-wait", "pre-delete", "delete", "delete-result", "absence-inspect", "absence-owned", "absence-wait"}

func removalStepValid(s string) bool {
	for _, v := range removalSteps {
		if s == v {
			return true
		}
	}
	return false
}
func removalCause(err error) string {
	category := removalNativeCause(err)
	if stage, code := windowsservice.SetupDiagnostic(err); stage != "unknown" {
		return "service:" + stage + ":" + code + ":" + category
	}
	d := windowsservice.Diagnostic(err)
	if d.Phase == windowsservice.PhaseReceipt && d.Reason == windowsservice.ReasonStateRejected {
		return "receipt_rejected"
	}
	return category
}
func removalNativeCause(err error) string {
	chain, ok := setupErrorChain(err)
	if !ok {
		return "failed"
	}
	for _, e := range chain {
		switch e {
		case context.Canceled:
			return "canceled"
		case context.DeadlineExceeded:
			return "deadline"
		}
		if n, ok := e.(syscall.Errno); ok {
			switch n {
			case 5:
				return "access_denied"
			case 1061:
				return "cannot_accept_control"
			case 1062:
				return "not_active"
			case 1051:
				return "dependent_services"
			case 1072:
				return "delete_pending"
			}
		}
	}
	return "failed"
}
func setupRemovalFailureText(err error) string {
	step, reason := "unknown", "failed"
	if e, ok := err.(*removalFailure); ok && e != nil && removalStepValid(e.step) {
		step = e.step
		reason = removalCause(e.detail)
	}
	return "Service removal did not complete. Removal diagnostic: " + step + "; " + reason + ". Files, identity and grants remain; inspect retained state before any further action."
}
