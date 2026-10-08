package freshgate

import (
	"encoding/json"
	"localrmm/internal/windowsacceptance/profile"
)

const ReportSchema = "tracebolt.windows-fresh-conpty-acceptance.v1"

type Report struct {
	OwnedServiceStopped                 bool                         `json:"ownedServiceStopped"`
	ServiceDisabled                     bool                         `json:"serviceDisabled"`
	AutomaticStartConfigurationRetained bool                         `json:"automaticStartConfigurationRetained"`
	ServiceAndAppStateRetained          bool                         `json:"serviceAndAppStateRetained"`
	ApplicationCleanupVerified          bool                         `json:"applicationCleanupVerified"`
	VMDisposalVerified                  bool                         `json:"vmDisposalVerified"`
	PlatformDisposalRequired            bool                         `json:"platformDisposalRequired"`
	Schema                              string                       `json:"schema"`
	Source                              string                       `json:"source"`
	Status                              string                       `json:"status"`
	ApprovalValidated                   bool                         `json:"approvalValidated"`
	NativeActionsAttempted              bool                         `json:"nativeActionsAttempted"`
	HiddenConsoleExercised              bool                         `json:"hiddenConsoleExercised"`
	SyntheticInput                      bool                         `json:"syntheticInput"`
	HumanEntry                          bool                         `json:"humanEntry"`
	HumanManagerApproval                bool                         `json:"humanManagerApproval"`
	NoEchoVerified                      bool                         `json:"noEchoVerified"`
	DisabledStageVerified               bool                         `json:"disabledStageVerified"`
	FreshOrchestrationAcceptance        bool                         `json:"freshOrchestrationAcceptance"`
	ReceiptAndGrantsVerified            bool                         `json:"receiptAndGrantsVerified"`
	LimitedServiceTokenVerified         bool                         `json:"limitedServiceTokenVerified"`
	OwnedChildReaped                    bool                         `json:"ownedChildReaped"`
	ConsoleClosed                       bool                         `json:"consoleClosed"`
	FixtureClosed                       bool                         `json:"fixtureClosed"`
	AppStateRetainedForVMDisposal       bool                         `json:"appStateRetainedForVMDisposal"`
	ProductionManagerExercised          bool                         `json:"productionManagerExercised"`
	ProductionIngressExercised          bool                         `json:"productionIngressExercised"`
	SharedDashboardExercised            bool                         `json:"sharedDashboardExercised"`
	OSRebootExercised                   bool                         `json:"osRebootExercised"`
	NativeInterruptionAcceptance        bool                         `json:"nativeInterruptionAcceptance"`
	Inventory                           profile.Observation          `json:"inventory"`
	Extensions                          profile.ExtensionObservation `json:"extensions"`
}

func NewReport(source string) Report {
	return Report{Schema: ReportSchema, Source: source, Status: "blocked", Inventory: profile.ZeroObservation(), Extensions: profile.ZeroExtensionObservation()}
}
func (r Report) Validate() error {
	if r.Schema != ReportSchema || !validHex(r.Source, 20) || r.Status != "blocked" && r.Status != "failed" && r.Status != "passed_fresh_native_subset" || r.ApplicationCleanupVerified || r.VMDisposalVerified || r.HumanEntry || r.HumanManagerApproval || r.ProductionManagerExercised || r.ProductionIngressExercised || r.SharedDashboardExercised || r.OSRebootExercised || r.NativeInterruptionAcceptance || r.Inventory.Validate() != nil || r.Extensions.Validate() != nil {
		return ErrGuard
	}
	if r.ServiceDisabled && r.AutomaticStartConfigurationRetained || (r.ServiceDisabled || r.AutomaticStartConfigurationRetained) && !r.OwnedServiceStopped {
		return ErrGuard
	}
	if r.NativeActionsAttempted && !r.ApprovalValidated || r.SyntheticInput && !r.NativeActionsAttempted || r.HiddenConsoleExercised && (!r.SyntheticInput || !r.NoEchoVerified || !r.ReceiptAndGrantsVerified) || r.FreshOrchestrationAcceptance && (!r.HiddenConsoleExercised || !r.DisabledStageVerified || !r.LimitedServiceTokenVerified || !r.Inventory.Usable() || !r.Extensions.Usable()) {
		return ErrGuard
	}
	if r.Status == "blocked" && r.NativeActionsAttempted {
		return ErrGuard
	}
	if r.Status == "passed_fresh_native_subset" && (!r.FreshOrchestrationAcceptance || !r.OwnedChildReaped || !r.ConsoleClosed || !r.FixtureClosed || !r.AppStateRetainedForVMDisposal || !r.OwnedServiceStopped || r.ServiceDisabled || !r.AutomaticStartConfigurationRetained || !r.ServiceAndAppStateRetained || !r.PlatformDisposalRequired) {
		return ErrGuard
	}
	return nil
}
func (r Report) Encode() ([]byte, error) {
	if r.Validate() != nil {
		return nil, ErrGuard
	}
	b, e := json.Marshal(r)
	if e != nil || len(b) > 16<<10 {
		return nil, ErrGuard
	}
	return b, nil
}
