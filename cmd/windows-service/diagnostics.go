package main

import (
	"fmt"
	"io"

	"localrmm/internal/windowsservice"
)

func marked(phase windowsservice.Phase, reason windowsservice.Reason, err error) error {
	if err == nil {
		err = errLifecycle
	}
	// Keep a more specific finite diagnosis, including read-access preflight,
	// when an inner reviewed component already supplied one.
	d := windowsservice.Diagnostic(err)
	if d.Phase != windowsservice.PhaseUnknown && d.Reason != windowsservice.ReasonUnknown {
		// A cancellation leaf joined to a real authority failure is not the
		// phase's outcome. Keep its hard diagnosis instead of interrupted.
		if d.Reason != windowsservice.ReasonInterrupted || reason == windowsservice.ReasonInterrupted {
			return err
		}
	}
	return windowsservice.Mark(phase, reason, err)
}
func reportDiagnostic(out io.Writer, err error) {
	d := windowsservice.Diagnostic(err)
	_, _ = fmt.Fprintf(out, "TRACEBOLT_WINDOWS phase=%s reason=%s serviceSpecificExitCode=%d\n", d.Phase, d.Reason, d.ServiceCode)
}
