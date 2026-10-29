package main

import (
	"errors"
	"fmt"
	"localrmm/internal/windowspackage"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowssetup"
)

// Only the coordinator's proven phase may establish that no writes occurred.
// A compatibility sentinel alone cannot prove that, and raw causes stay private.
func setupWizardFailure(err error, progress func(string)) {
	if outcome, ok := err.(*setupWizardOutcomeError); ok && outcome.beforeMutation {
		if errors.Is(outcome.cause, windowssetup.ErrCompatibility) {
			progress("Manager compatibility check failed before installation: the manager could not be reached, TLS could not be verified, or its response did not match this Setup contract. Check connectivity from this computer, the selected origin and approved HTTPS CA; compare manager/Setup versions. No new service, identity or scope grants were created. Never bypass TLS or silently change transport.")
			return
		}
		progress("Setup stopped before installation writes. No new service, identity or scope grants were created. Review the package, platform, public export and existing-installation boundary; existing state is never overwritten or repaired. Package diagnostic: " + windowspackage.Code(outcome.cause))
		return
	}
	if outcome, ok := err.(*setupWizardOutcomeError); ok {
		err = outcome.cause
	}
	code := windowspackage.Code(err)
	d := windowsservice.Diagnostic(err)
	progress(fmt.Sprintf("Setup stopped. Package diagnostic: %s; service phase: %s; reason: %s. Retained state may be incomplete or startup indeterminate. Do not rerun installation or delete state. An administrator can use the installed tracebolt-windows-service.exe --inspect for read-only SCM status; retain the displayed public diagnostic for review.", code, d.Phase, d.Reason))
}
