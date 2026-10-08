//go:build windows

package main

import (
	"testing"

	"golang.org/x/sys/windows"
)

// Constants only: no SCM, filesystem, console or other native operation.
func TestSetupWindowsPermissionCauseHasFiniteStartupCode(t *testing.T) {
	for _, stage := range []string{"startup_activate", "service_start"} {
		returned := setupFailed(stage, windows.ERROR_ACCESS_DENIED)
		assertSetupDiagnosis(t, returned, stage, "access_denied")
	}
}
