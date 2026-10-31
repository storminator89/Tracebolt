// Package managersetup provides bounded, redacted, configuration-only preflight
// and create-only LAN configuration initialization. It never starts a manager.
package managersetup

import (
	"localrmm/internal/lanconfig"
	"time"
)

const SchemaVersion = "tracebolt.manager-setup.v1"

type Check struct {
	Code     string `json:"code"`
	Status   string `json:"status"`
	Message  string `json:"message"`
	NextStep string `json:"nextStep,omitempty"`
}

type Report struct {
	SchemaVersion string   `json:"schemaVersion"`
	Operation     string   `json:"operation"`
	Scope         string   `json:"scope"`
	OK            bool     `json:"ok"`
	Created       bool     `json:"created"`
	Checks        []Check  `json:"checks"`
	Limitations   []string `json:"limitations"`
}

type Options struct {
	// ExpectedUID must explicitly name the nonroot manager runtime UID. Running
	// as root instead is not evidence about that UID's ability to read material.
	ExpectedUID      int
	EnrollmentConfig string
	RequireWindows   bool
}

func NewReport(operation string) Report {
	return Report{SchemaVersion: SchemaVersion, Operation: operation, Scope: "guided-tls-configuration-only", OK: true, Checks: []Check{}, Limitations: []string{
		"No listeners, connections, login, certificate issuance or host changes are performed.",
		"Database contents, mode/identity compatibility, revocation/replay floors, runtime startup and native Windows enrollment are not verified.",
		"Optional startup arguments beyond the selected LAN/enrollment configuration are not checked.",
		"Port results cover the current Linux network namespace and instant only; no port is reserved.",
	}}
}

func (r *Report) add(code, status, message, next string) {
	r.Checks = append(r.Checks, Check{code, status, message, next})
	if status == "fail" || status == "unknown" {
		r.OK = false
	}
}

// Failure constructs a redacted argument-level result. Callers must supply only
// static messages, never errors or user-controlled arguments.
func Failure(operation, code, message, next string) Report {
	r := NewReport(operation)
	r.add(code, "fail", message, next)
	return r
}

// Doctor reads protected local configuration and material only. In particular it
// must never call lan-manager prepare, PrepareMode or a database Open function.
func Doctor(path string, options Options, now time.Time) Report {
	return doctor(path, options, now)
}

// Initialize writes only a new LAN configuration file, after read-only preflight.
// Keys, auth and the separate issuer config must already have been provisioned by
// an authorized custodian. Existing target/state is never adopted or reset.
func Initialize(c lanconfig.Config, output string, options Options, now time.Time) Report {
	return initialize(c, output, options, now)
}
