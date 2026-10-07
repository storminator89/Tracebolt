// Package gate binds the manually authorized Windows acceptance scope to one
// exact hosted workflow source. Validation and report encoding are side-effect free.
package gate

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"time"

	"localrmm/internal/windowsacceptance/native"
	"localrmm/internal/windowsacceptance/profile"
)

const Repository = "storminator89/Tracebolt"
const Schema = "tracebolt.windows-native-acceptance.v2"
const MaxReportBytes = 32 << 10
const MaxLifetime = 20 * time.Minute

var ErrGate = errors.New("manual exact-source Windows acceptance approval is missing or invalid")

type Approval struct {
	ExpectedSource                                 string
	Services, Identity, AppACLs, Loopback, Cleanup bool
	Selection                                      profile.Selection
	InventoryMetadata, HTTPPlaintext               bool
}
type Environment struct{ Event, Actions, RunnerOS, RunnerEnvironment, Repository, Source, RunID string }
type Grant struct {
	source    string
	selection profile.Selection
	expires   time.Time
	active    atomic.Bool
	now       func() time.Time
}

func ValidSource(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 20 && strings.ToLower(s) == s
}
func Authorize(a Approval, e Environment, compiled string) (*Grant, error) {
	return authorize(a, e, compiled, time.Now)
}
func authorize(a Approval, e Environment, compiled string, now func() time.Time) (*Grant, error) {
	if a.Selection.Validate() != nil || a.InventoryMetadata != a.Selection.Inventory() || a.HTTPPlaintext != a.Selection.HTTPTest() || now == nil || !ValidSource(compiled) || a.ExpectedSource != compiled || e.Source != compiled || !a.Services || !a.Identity || !a.AppACLs || !a.Loopback || !a.Cleanup || e.Event != "workflow_dispatch" || e.Actions != "true" || e.RunnerOS != "Windows" || e.RunnerEnvironment != "github-hosted" || e.Repository != Repository || len(e.RunID) == 0 || len(e.RunID) > 24 {
		return nil, ErrGate
	}
	for _, c := range e.RunID {
		if c < '0' || c > '9' {
			return nil, ErrGate
		}
	}
	if strings.Trim(e.RunID, "0") == "" {
		return nil, ErrGate
	}
	g := &Grant{source: compiled, selection: a.Selection, expires: now().Add(MaxLifetime), now: now}
	g.active.Store(true)
	return g, nil
}
func (g *Grant) Check() bool {
	return g != nil && g.now != nil && g.active.Load() && g.now().Before(g.expires)
}
func (g *Grant) Close() {
	if g != nil {
		g.active.Store(false)
	}
}
func (g *Grant) Selection() profile.Selection {
	if g == nil {
		return profile.Selection{}
	}
	return g.selection
}
func (g *Grant) Source() string {
	if g == nil {
		return ""
	}
	return g.source
}

var CheckNames = []string{"prerequisites", "app_only_provisioning", "service_prepare", "pending_claim", "limited_token", "pending_stop_identity", "delayed_approval_report", "profile_report", "unrelated_service_denied", "outage_pending_retained", "outage_restart_same_bytes", "recovery_same_identity", "uninstall_retains_state", "owned_cleanup"}

type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}
type Report struct {
	Selection                      profile.Selection   `json:"selection"`
	Inventory                      profile.Observation `json:"inventory"`
	LoopbackPeerExercised          bool                `json:"loopbackPeerExercised"`
	NativeInventorySenderExercised bool                `json:"nativeInventorySenderExercised"`
	ProductionIngressExercised     bool                `json:"productionIngressExercised"`
	SharedDashboardExercised       bool                `json:"sharedDashboardExercised"`
	Schema                         string              `json:"schema"`
	Source                         string              `json:"source"`
	Status                         string              `json:"status"`
	Stage                          string              `json:"stage"`
	Reason                         native.Reason       `json:"reason"`
	ApprovalValidated              bool                `json:"approvalValidated"`
	NativeActionsAttempted         bool                `json:"nativeActionsAttempted"`
	Native                         native.Evidence     `json:"native"`
	Checks                         []Check             `json:"checks"`
	ProductionManagerExercised     bool                `json:"productionManagerExercised"`
	HiddenConsoleExercised         bool                `json:"hiddenConsoleExercised"`
	OSShutdownExercised            bool                `json:"osShutdownExercised"`
	OSRebootExercised              bool                `json:"osRebootExercised"`
	BroadAncestorACLChanged        bool                `json:"broadAncestorAclChanged"`
	ExistingResourcesAdopted       bool                `json:"existingResourcesAdopted"`
	SecretsExported                bool                `json:"secretsExported"`
	RawTelemetryExported           bool                `json:"rawTelemetryExported"`
}

func NewReport(source string) Report { return NewSelectedReport(source, profile.BasicTLS()) }
func NewSelectedReport(source string, selected profile.Selection) Report {
	r := Report{Selection: selected, Inventory: profile.ZeroObservation(), Schema: Schema, Source: source, Status: "failed", Stage: "prerequisites", Reason: native.ReasonNone, ApprovalValidated: true, Checks: []Check{}, Native: native.Evidence{Stage: native.StageIdle, Reason: native.ReasonNone}}
	for _, name := range CheckNames {
		r.Checks = append(r.Checks, Check{name, "not_run"})
	}
	return r
}
func (r *Report) Mark(name, status string) {
	for i, c := range r.Checks {
		if c.Name == name {
			r.Checks[i].Status = status
			return
		}
	}
}
func finiteStage(v native.Stage) bool {
	switch v {
	case native.StageIdle, native.StagePreflight, native.StageProvision, native.StageInstall, native.StagePrepare, native.StageClaim, native.StageStart, native.StageToken, native.StageStatus, native.StageContinuity, native.StageProbe, native.StageStop, native.StageUninstall, native.StageCleanup:
		return true
	}
	return false
}
func finiteReason(v native.Reason) bool {
	switch v {
	case native.ReasonNone, native.ReasonGuard, native.ReasonUnsupported, native.ReasonPrerequisite, native.ReasonExisting, native.ReasonArtifact, native.ReasonOwnership, native.ReasonOperation, native.ReasonTimeout, native.ReasonState:
		return true
	}
	return false
}
func Validate(r Report) error {
	if (r.LoopbackPeerExercised && !r.NativeActionsAttempted) || r.Selection.Validate() != nil || r.Inventory.Validate() != nil || (!r.Selection.Inventory() && r.Inventory.Frames != 0) || r.NativeInventorySenderExercised != (r.Selection.Inventory() && r.Inventory.Frames > 0 && r.LoopbackPeerExercised) || r.ProductionIngressExercised || r.SharedDashboardExercised || r.Schema != Schema || !ValidSource(r.Source) || !r.ApprovalValidated || r.ProductionManagerExercised || r.HiddenConsoleExercised || r.OSShutdownExercised || r.OSRebootExercised || r.BroadAncestorACLChanged || r.ExistingResourcesAdopted || r.SecretsExported || r.RawTelemetryExported || !finiteStage(r.Native.Stage) || !finiteReason(r.Native.Reason) || !finiteReason(r.Reason) || len(r.Checks) != len(CheckNames) {
		return ErrGate
	}
	if r.Status != "passed_native_subset" && r.Status != "failed" && r.Status != "blocked" {
		return ErrGate
	}
	stageOK := false
	allPass := true
	for i, c := range r.Checks {
		if c.Name != CheckNames[i] {
			return ErrGate
		}
		if c.Name == r.Stage {
			stageOK = true
		}
		switch c.Status {
		case "pass":
		case "fail", "blocked", "not_run":
			allPass = false
		default:
			return ErrGate
		}
	}
	if !stageOK {
		return ErrGate
	}
	if r.Status == "passed_native_subset" && (!r.LoopbackPeerExercised || (r.Selection.Inventory() && (!r.NativeInventorySenderExercised || !r.Inventory.Usable())) || !allPass || !r.NativeActionsAttempted || r.Reason != native.ReasonNone || r.Stage != "owned_cleanup" || r.Native.Stage != native.StageCleanup || r.Native.Reason != native.ReasonNone || !r.Native.Prerequisites || !r.Native.Provisioned || r.Native.Installed || !r.Native.Prepared || !r.Native.ClaimCommitted || !r.Native.Ready || !r.Native.Stopped || !r.Native.Cleaned || !r.Native.Uninstalled || !r.Native.LimitedToken || !r.Native.IdentityRetained || !r.Native.SenderFloorRetained || !r.Native.PendingBytesRetained || !r.Native.UnrelatedServiceDenied || !r.Native.UninstallStateRetained || r.Native.Running || r.Native.PendingPresent || r.Native.CleanupRetained) {
		return ErrGate
	}
	if r.Status == "blocked" && (r.Stage != "prerequisites" || r.LoopbackPeerExercised || r.Inventory.Frames != 0 || r.NativeActionsAttempted || r.Native.Provisioned || r.Native.Installed || r.Native.Prepared || r.Native.ClaimCommitted) {
		return ErrGate
	}
	return nil
}
func Encode(r Report) ([]byte, error) {
	if Validate(r) != nil {
		return nil, ErrGate
	}
	b, err := json.Marshal(r)
	if err != nil || len(b)+1 > MaxReportBytes {
		return nil, ErrGate
	}
	return append(b, '\n'), nil
}
