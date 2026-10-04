// Package agentinstall models explicit local Linux service installation. It does
// not enroll remotely, download artifacts, or grant permission to change a host.
package agentinstall

import (
	"errors"
	"path/filepath"
	"regexp"
	"strings"
)

const Account = "tracebolt-agent"
const UnitName = "tracebolt-agent.service"
const InstallDirectory = "/opt/tracebolt-agent"
const StateDirectory = "/var/lib/tracebolt-agent"
const EnrollmentDirectory = StateDirectory + "/enrollment"
const ConfigPath = EnrollmentDirectory + "/agent.json"
const BootstrapPath = "/etc/tracebolt-agent/bootstrap.json"
const UnitPath = "/etc/systemd/system/" + UnitName
const AgentPath = InstallDirectory + "/lan-agent"
const EnrollPath = InstallDirectory + "/enroll-agent"
const ManifestPath = InstallDirectory + "/installation.json"

var ErrPreflight = errors.New("installer preflight failed; no service change is authorized")
var ErrContract = errors.New("installer request is invalid")
var ErrApplyRequired = errors.New("explicit apply confirmation is required")
var ErrState = errors.New("installation state is unavailable or incompatible; identity is preserved")
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Action string

const (
	Install   Action = "install"
	Upgrade   Action = "upgrade"
	Restart   Action = "restart"
	Uninstall Action = "uninstall"
)

type Request struct {
	Action           Action
	Apply            bool
	PendingService   bool
	Resume           bool
	AgentBinary      string
	AgentSHA256      string
	EnrollBinary     string
	EnrollSHA256     string
	BootstrapFile    string
	InsecureHTTPTest bool
	SourceArchive    string
	SourceSHA256     string
	BootstrapSHA256  string
}

// HostFacts are observations made by a trusted local preflight, never network or
// bootstrap claims. BuildPlan is not authority to skip rechecking them at apply.
type HostFacts struct {
	Linux, SystemdAvailable, Root, AccountCompatible, InstallationOwned, EnrollmentReady bool
	Profile                                                                              string
	RetainedPreparation, InstallationRemoved                                             bool
	PendingService                                                                       bool
}
type Step struct {
	Kind        string `json:"kind"`
	Description string `json:"description"`
}
type Plan struct {
	SchemaVersion                      string `json:"schemaVersion"`
	Action                             Action `json:"action"`
	DryRun                             bool   `json:"dryRun"`
	RequiresPrivilege                  bool   `json:"requiresPrivilege"`
	IdentityRetained                   bool   `json:"identityRetained"`
	ServiceStartRequiresEnrollment     bool   `json:"serviceStartRequiresEnrollment"`
	ServiceStartRequiresCommittedClaim bool   `json:"serviceStartRequiresCommittedClaim,omitempty"`
	Steps                              []Step `json:"steps"`
}

func BuildPlan(r Request, h HostFacts) (Plan, error) {
	if r.Action != Install && r.Action != Upgrade && r.Action != Restart && r.Action != Uninstall {
		return Plan{}, ErrContract
	}
	if !h.Linux || !h.SystemdAvailable || !h.AccountCompatible {
		return Plan{}, ErrPreflight
	}
	if r.Apply && !h.Root {
		return Plan{}, ErrPreflight
	}
	if h.Profile != "tls" && h.Profile != "http-test" {
		return Plan{}, ErrContract
	}
	if h.Profile == "http-test" && !r.InsecureHTTPTest {
		return Plan{}, ErrPreflight
	}
	if h.Profile == "tls" && r.InsecureHTTPTest {
		return Plan{}, ErrContract
	}
	if r.PendingService && r.Action != Install {
		return Plan{}, ErrContract
	}
	if r.Resume && r.Action != Install {
		return Plan{}, ErrContract
	}
	if r.Action == Install && r.Resume != (h.RetainedPreparation || h.InstallationRemoved) {
		return Plan{}, ErrState
	}
	if r.Action == Install && r.Resume && r.PendingService != h.PendingService {
		return Plan{}, ErrState
	}
	if (r.Action == Upgrade || r.Action == Restart) && h.InstallationRemoved {
		return Plan{}, ErrState
	}
	if r.Action != Install && !h.InstallationOwned {
		return Plan{}, ErrState
	}
	if r.Action == Install && h.InstallationOwned && !h.InstallationRemoved {
		return Plan{}, ErrState
	}
	if r.Action == Install || r.Action == Upgrade {
		if !validDigest(r.AgentSHA256) || !validDigest(r.EnrollSHA256) || !validInputPath(r.AgentBinary) || !validInputPath(r.EnrollBinary) || !validInputPath(r.SourceArchive) || !validDigest(r.SourceSHA256) {
			return Plan{}, ErrContract
		}
	}
	if r.Action == Install && (!validInputPath(r.BootstrapFile) || !validDigest(r.BootstrapSHA256)) {
		return Plan{}, ErrContract
	}
	p := Plan{SchemaVersion: "tracebolt.agent-install-plan.v1", Action: r.Action, DryRun: !r.Apply, RequiresPrivilege: true, IdentityRetained: true, ServiceStartRequiresEnrollment: true, Steps: []Step{{"preflight", "Check systemd, fixed paths, trusted ownership, local artifact hashes and existing installation state."}}}
	pending := r.Action == Install && r.PendingService || r.Action != Install && h.PendingService
	if pending {
		p.SchemaVersion = "tracebolt.agent-install-plan.v2"
		p.ServiceStartRequiresEnrollment = false
		p.ServiceStartRequiresCommittedClaim = true
	}
	switch r.Action {
	case Install:
		p.Steps = append(p.Steps, Step{"prepare", "Prepare the dedicated non-login service account and protected fixed directories."}, Step{"artifacts", "Stage and verify local native binaries; no download or shell pipeline."}, Step{"enroll", "Run the verified enrollment client as the dedicated account with hidden terminal input; wait for explicit operator approval."}, Step{"validate", "Validate the guided-v2 handoff and existing bound sender ledger."}, Step{"service", "Install the sandboxed unit, then enable/start only after valid enrollment."})
	case Upgrade:
		p.Steps = append(p.Steps, Step{"stage", "Stage verified replacement binaries without changing identity or pending observations."}, Step{"stop", "Stop the owned service before validating its exclusive sender ledger."}, Step{"validate", "Validate the existing guided-v2 identity/counter; never initialize missing state."}, Step{"replace", "Atomically replace owned binaries/unit and restart; retain the previous version for bounded rollback."})
	case Restart:
		p.Steps = append(p.Steps, Step{"stop", "Stop the owned service."}, Step{"validate", "Validate the existing guided-v2 identity and bound ledger without resetting it."}, Step{"service", "Restart only after validation succeeds."})
	case Uninstall:
		p.Steps = append(p.Steps, Step{"stop", "Disable and stop only the owned Tracebolt service."}, Step{"remove-owned", "Remove only manifest-owned unit and binaries; retain the dedicated account, bootstrap and all private identity/counter data."})
	}
	if pending && r.Action == Install {
		p.Steps = []Step{{"preflight", "Check fixed paths, exact local artifacts, immutable v2 mode and retained state."}, {"prepare", "Prepare the dedicated non-login account and private paths."}, {"artifacts", "Stage and reverify only selected local native binaries."}, {"claim", "Use hidden local invitation entry and save only a status-confirmed same-key claim; no observations collected."}, {"validate", "Validate the existing bound service enrollment locally with no network or initialization."}, {"service", "Publish the v2 waiting-capable unit and observe process start. Approval, activation and reporting remain separate phases."}}
	}
	return p, nil
}
func validDigest(v string) bool { return digestPattern.MatchString(v) && strings.Trim(v, "0") != "" }

func validInputPath(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p && !strings.ContainsAny(p, "\x00\r\n")
}
