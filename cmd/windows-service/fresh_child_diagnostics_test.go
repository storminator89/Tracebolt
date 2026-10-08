package main

import (
	"localrmm/internal/windowsacceptance/freshgate"
	"localrmm/internal/windowsservice"
)

// Test-only metadata decoding cannot expose raw errors, native numbers or text.
func freshChildFailureCode(err error) int {
	if err == nil {
		return 0
	}
	// A retained first-failure pair outranks a subsequent receipt failure.
	if stage, category := setupFirstFailureDiagnostic(err); stage != "unknown" {
		return freshgate.ChildFailureExitCode(stage, category)
	}
	if stage, category := windowsservice.SetupDiagnostic(err); stage != "unknown" {
		return freshgate.ChildFailureExitCode(stage, category)
	}
	stage, category := setupFailureDiagnostic(err)
	return freshgate.ChildFailureExitCode(stage, category)
}
