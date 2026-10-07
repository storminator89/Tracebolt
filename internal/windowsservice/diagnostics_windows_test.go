//go:build windows

package windowsservice

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/sys/windows/svc"
)

// The invalid-argument branch returns before any token, SCM or filesystem read.
// This is an in-memory callback fixture, never a service-dispatcher invocation.
func TestRuntimeArgumentRejectionHasSanitizedSCMCode(t *testing.T) {
	for _, args := range [][]string{nil, {maliciousDiagnosticText}, {Name, maliciousDiagnosticText}} {
		called := false
		h := runtimeHandler{
			ctx: context.Background(),
			worker: func(context.Context, func()) error {
				called = true
				return nil
			},
			result: make(chan error, 1),
		}
		changes := make(chan svc.Status, 1)
		specific, code := h.Execute(args, nil, changes)
		if called || !specific || code != 1313 || len(changes) != 0 {
			t.Fatalf("invalid dispatch performed work or returned generic failure: called=%t specific=%t code=%d", called, specific, code)
		}
		err := <-h.result
		if !errors.Is(err, ErrMismatch) || Diagnostic(err) != (DiagnosticStatus{PhaseRuntimeDispatch, ReasonInvalidArguments, 1313}) {
			t.Fatalf("invalid dispatch diagnosis changed: %v", err)
		}
		assertSafeDiagnosticText(t, err.Error())
	}
}
