//go:build !linux

package managersetup

import (
	"localrmm/internal/lanconfig"
	"time"
)

func unsupported(operation string) Report {
	return Failure(operation, "unsupported_platform", "This protected manager setup contract is Linux-only.", "Run the command inside the intended Linux runtime and network namespace as its explicit nonroot UID; no host changes were performed.")
}
func doctor(string, Options, time.Time) Report                       { return unsupported("doctor") }
func initialize(lanconfig.Config, string, Options, time.Time) Report { return unsupported("init") }
