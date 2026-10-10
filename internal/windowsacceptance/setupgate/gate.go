// Package setupgate defines an inert, distinct authorization and finite evidence
// contract for the actual packaged GUI. It never invokes native code on import.
package setupgate

import (
	"errors"
	"regexp"
	"time"
)

const Profile = "packaged-setup-gui-v1"
const Schema = "tracebolt.windows-setup-acceptance.v2"

var ErrGuard = errors.New("packaged Setup acceptance boundary rejected")
var Approvals = []string{"APP_ACLS", "SERVICES", "IDENTITY", "FIVE_READ_SCOPES", "SYNTHETIC_CONSOLE", "LOOPBACK_TLS", "HTTP_PLAINTEXT", "STOP_REMOVE_OWNED_SERVICE", "RETAIN_FOR_VM_DISPOSAL"}
var Cases = []string{"install-uninstall", "cancel-hidden-input", "pending-transport", "http-install-uninstall"}
var Checks = map[string][]string{
	"install-uninstall":   {"preflightCancelUnchanged", "acknowledgementsOff", "publicBootstrapChosen", "realGUIExercised", "hiddenConsoleExercised", "noEchoVerified", "pendingStoppedDisabled", "approvalWithheld", "managerFixtureApproved", "completedReceipt", "limitedServiceToken", "twoFiveScopeFrames", "volumeCapacity", "processCPUDelta", "tcpFixture", "reopenBlocked", "uninstallCancelUnchanged", "deletePendingObserved", "serviceAbsent", "receiptAndGrantsVerified", "filesAndStateRetained", "workerTerminated", "consoleReleased"},
	"cancel-hidden-input": {"acknowledgementsOff", "publicBootstrapChosen", "realGUIExercised", "hiddenConsoleExercised", "noEchoVerified", "pendingStoppedDisabled", "cancelWhileHiddenInput", "partialStateRetained", "reopenBlocked", "incompleteUninstallBlocked", "filesAndStateRetained", "workerTerminated", "consoleReleased"},
	"pending-transport":   {"acknowledgementsOff", "publicBootstrapChosen", "realGUIExercised", "hiddenConsoleExercised", "noEchoVerified", "pendingStoppedDisabled", "approvalWithheld", "transportInterrupted", "sameIdentityAndDeadline", "noFalseConnected", "partialStateRetained", "reopenBlocked", "incompleteUninstallBlocked", "filesAndStateRetained", "workerTerminated", "consoleReleased"},
}

func init() {
	Stages = append(Stages, RemovalFailureStages...)
	Stages = append(Stages, ChooserClickFailureStages...)
	Stages = append(Stages, RetentionFailureStages...)
	Checks["http-install-uninstall"] = append(append([]string{}, Checks["install-uninstall"]...), "httpAcknowledgementOff", "httpExplicitlyAcknowledged")
}
func NormalCase(which string) bool {
	return which == "install-uninstall" || which == "http-install-uninstall"
}

var Stages = []string{"bootstrap-launch", "chooser-click", "chooser-dialog", "chooser-title", "chooser-edit", "chooser-set-text", "chooser-open", "chooser-validated", "uninstall-held-status-delete-pending", "uninstall-held-status-invalid-handle", "uninstall-held-status-access-denied", "uninstall-pending-close-failed", "uninstall-pending-close-completed", "authorization", "desktop", "fresh", "fresh-environment", "fresh-layout", "fresh-service", "fresh-program-files", "fresh-program-data", "fixture", "preflight-cancel", "bootstrap", "consent", "install", "hidden-input", "pending", "pending-capture", "pending-claim", "pending-service", "pending-console", "pending-invariant", "pending-retention", "transport", "transport-service", "completion", "frames", "frames-evidence", "reopen", "uninstall-cancel", "uninstall", "verify-retention", "completed", "consent-back", "consent-first-compared", "consent-first-disabled", "consent-first-enabled", "consent-first-http", "consent-first-http-reset", "consent-first-identity", "consent-first-reset", "consent-first-scope", "consent-first-service", "consent-http-absent", "consent-input", "consent-open", "consent-reopen", "consent-review", "consent-review-reset", "consent-second-compared", "consent-second-disabled", "consent-second-enabled", "consent-second-http", "consent-second-http-reset", "consent-second-identity", "consent-second-reset", "consent-second-scope", "consent-second-service", "preflight-cancel-click", "preflight-choose", "preflight-consent", "preflight-exit", "preflight-fresh-service", "preflight-fresh-program-files", "preflight-fresh-program-data", "preflight-launch", "uninstall-absence-inspect", "uninstall-absence-present", "uninstall-cancel-confirmation", "uninstall-cancel-invariant", "uninstall-cancel-return", "uninstall-confirmation", "uninstall-exit", "uninstall-finish", "uninstall-finish-message", "uninstall-held-close", "uninstall-held-close-completed", "uninstall-held-close-failed", "uninstall-held-status", "uninstall-held-stopped", "uninstall-hold-scm", "uninstall-hold-service", "uninstall-launch", "uninstall-operation-failed", "uninstall-owned", "uninstall-pending-close", "uninstall-pending-text", "uninstall-receipt", "uninstall-release", "uninstall-removing", "uninstall-stopping"}
var FalseCoverage = []string{"humanUAC", "humanInvitation", "realLinuxManager", "sharedDashboard", "arm64Runtime", "osReboot", "upgrade", "vmDisposalVerified", "secretsExported", "rawTelemetryExported"}
var hex40 = regexp.MustCompile(`^[0-9a-f]{40}$`)
var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var safeID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)
var decimal = regexp.MustCompile(`^[1-9][0-9]{0,23}$`)

func Contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

type Binding struct {
	Source, CompiledSource, DriverHash, SetupHash, ServiceHash, SourceInputsHash, Machine, Case, RunID string
	Deadline                                                                                           time.Time
}

func Authorize(env map[string]string, b Binding, now time.Time) error {
	if !hex40.MatchString(b.Source) || b.Source != b.CompiledSource || env["GITHUB_SHA"] != b.Source || env["TRACEBOLT_SETUP_SOURCE"] != b.Source || env["TRACEBOLT_SETUP_PROFILE"] != Profile || !Contains(Cases, b.Case) || env["TRACEBOLT_SETUP_CASE"] != b.Case || !safeID.MatchString(b.Machine) || env["COMPUTERNAME"] != b.Machine || env["TRACEBOLT_SETUP_MACHINE"] != b.Machine || !now.Before(b.Deadline) || b.Deadline.Sub(now) > 15*time.Minute {
		return ErrGuard
	}
	for key, value := range map[string]string{"GITHUB_REPOSITORY": "storminator89/Tracebolt", "GITHUB_REPOSITORY_OWNER": "storminator89", "GITHUB_REPOSITORY_OWNER_ID": "30489872", "GITHUB_ACTOR": "storminator89", "GITHUB_ACTOR_ID": "30489872", "GITHUB_TRIGGERING_ACTOR": "storminator89", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_ACTIONS": "true", "RUNNER_OS": "Windows", "RUNNER_ARCH": "X64", "RUNNER_ENVIRONMENT": "github-hosted"} {
		if env[key] != value {
			return ErrGuard
		}
	}
	if !decimal.MatchString(b.RunID) || b.RunID != env["GITHUB_RUN_ID"] || env["TRACEBOLT_SETUP_RUN_ID"] != env["GITHUB_RUN_ID"] {
		return ErrGuard
	}
	for _, name := range Approvals {
		if env["TRACEBOLT_SETUP_APPROVE_"+name] != "true" {
			return ErrGuard
		}
	}
	for name, hash := range map[string]string{"DRIVER": b.DriverHash, "SETUP": b.SetupHash, "SERVICE": b.ServiceHash, "SOURCE_INPUTS": b.SourceInputsHash} {
		if !hex64.MatchString(hash) || env["TRACEBOLT_SETUP_"+name+"_SHA256"] != hash {
			return ErrGuard
		}
	}
	if b.DriverHash == b.SetupHash || b.DriverHash == b.ServiceHash || b.SetupHash == b.ServiceHash {
		return ErrGuard
	}
	return nil
}

type Report struct {
	SetupHash                string          `json:"setupSHA256"`
	ServiceHash              string          `json:"serviceSHA256"`
	DriverHash               string          `json:"driverSHA256"`
	SourceInputsHash         string          `json:"sourceInputsSHA256"`
	RunID                    string          `json:"runID"`
	Machine                  string          `json:"machine"`
	Schema                   string          `json:"schema"`
	Source                   string          `json:"source"`
	Case                     string          `json:"case"`
	Status                   string          `json:"status"`
	Stage                    string          `json:"stage"`
	Reason                   string          `json:"reason"`
	ApprovalValidated        bool            `json:"approvalValidated"`
	NativeActionsAttempted   bool            `json:"nativeActionsAttempted"`
	Checks                   map[string]bool `json:"checks"`
	Coverage                 map[string]bool `json:"coverage"`
	Startup                  string          `json:"startup"`
	FrameProgress            FrameProgress   `json:"frameProgress"`
	Frames                   uint64          `json:"frames"`
	PlatformDisposalRequired bool            `json:"platformDisposalRequired"`
}

func NewReport(b Binding) Report {
	source, which := b.Source, b.Case
	r := Report{SetupHash: b.SetupHash, ServiceHash: b.ServiceHash, DriverHash: b.DriverHash, SourceInputsHash: b.SourceInputsHash, RunID: b.RunID, Machine: b.Machine, Schema: Schema, Source: source, Case: which, Status: "blocked", Stage: "authorization", Reason: "authorization", Startup: "inspection_required", FrameProgress: ZeroFrameProgress(), Checks: map[string]bool{}, Coverage: map[string]bool{}}
	for _, s := range Checks[which] {
		r.Checks[s] = false
	}
	for _, s := range FalseCoverage {
		r.Coverage[s] = false
	}
	return r
}
func (r Report) Validate() error {
	if !hex64.MatchString(r.SetupHash) || !hex64.MatchString(r.ServiceHash) || !hex64.MatchString(r.DriverHash) || !hex64.MatchString(r.SourceInputsHash) || !decimal.MatchString(r.RunID) || !safeID.MatchString(r.Machine) || r.Schema != Schema || !hex40.MatchString(r.Source) || !Contains(Cases, r.Case) || !Contains(Stages, r.Stage) || !Contains([]string{"blocked", "failed", "passed_packaged_gui_subset"}, r.Status) || (!Contains([]string{"none", "authorization", "desktop_unavailable", "operation_failed", "deadline", "inspection_required"}, r.Reason) && !RemovalFailureReason(r.Reason)) || !Contains([]string{"inspection_required", "disabled", "automatic", "absent"}, r.Startup) || r.Frames > 64 || len(r.Checks) != len(Checks[r.Case]) || len(r.Coverage) != len(FalseCoverage) {
		return ErrGuard
	}
	if Contains(RetentionFailureStages, r.Stage) && (r.Status != "failed" || !NormalCase(r.Case)) {
		return ErrGuard
	}
	if Contains(ChooserClickFailureStages, r.Stage) && r.Status != "failed" {
		return ErrGuard
	}
	if Contains(RemovalFailureStages, r.Stage) || !Contains([]string{"none", "authorization", "desktop_unavailable", "operation_failed", "deadline", "inspection_required"}, r.Reason) {
		if r.Status != "failed" || !NormalCase(r.Case) || !Contains(RemovalFailureStages, r.Stage) || !RemovalFailureReason(r.Reason) {
			return ErrGuard
		}
	}

	if r.FrameProgress.Validate() != nil || r.Frames != r.FrameProgress.Extensions.V5Frames || !r.NativeActionsAttempted && r.FrameProgress.Reason != "not_started" || !NormalCase(r.Case) && r.FrameProgress.Reason != "not_started" {
		return ErrGuard
	}
	for _, s := range Checks[r.Case] {
		v, ok := r.Checks[s]
		if !ok || r.Status == "passed_packaged_gui_subset" && !v || r.Status == "blocked" && v {
			return ErrGuard
		}
	}
	for _, s := range FalseCoverage {
		v, ok := r.Coverage[s]
		if !ok || v {
			return ErrGuard
		}
	}
	if r.NativeActionsAttempted && !r.ApprovalValidated || r.PlatformDisposalRequired && !r.NativeActionsAttempted || r.Status == "blocked" && (r.NativeActionsAttempted || r.Frames != 0 || r.Startup != "inspection_required") {
		return ErrGuard
	}
	if r.Status == "passed_packaged_gui_subset" && (!r.NativeActionsAttempted || !r.PlatformDisposalRequired || r.Stage != "completed" || r.Reason != "none" || NormalCase(r.Case) && (r.Startup != "absent" || r.Frames < 2 || !r.FrameProgress.Ready()) || !NormalCase(r.Case) && (r.Startup != "disabled" || r.Frames != 0)) {
		return ErrGuard
	}
	return nil
}
