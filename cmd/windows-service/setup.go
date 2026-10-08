package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowsservice"
)

var errLifecycle = errors.New("Windows lifecycle authority unavailable")

type installReceipt struct {
	Version   int                    `json:"version"`
	Service   windowsservice.Receipt `json:"service"`
	Prepared  bool                   `json:"prepared"`
	ReadSetup *readSetupProgress     `json:"readSetup,omitempty"`
}
type setupJournal interface {
	Write(string, []byte) error
	Close() error
}
type setupSteps struct {
	plan              func(context.Context) (windowsservice.InstallPlan, error)
	readBootstrap     func(string) ([]byte, error)
	validateBootstrap func([]byte) error
	createJournal     func(windowsservice.Layout) (setupJournal, error)
	apply             func(context.Context, windowsservice.InstallPlan) (windowsservice.Receipt, error)
	prepare           func(windowsservice.Layout, windowsservice.Receipt, []byte) error
	verifyOwned       func(context.Context, windowsservice.Receipt) error
	enroll            func(context.Context, windowsservice.Layout) error
	start             func(context.Context, windowsservice.Receipt) (windowsservice.ApplyResult, error)
}

// setup runs only after the command's explicit apply and selected-scope gate. Its
// dependencies keep transaction ordering testable without a Windows mutation.
func setup(ctx context.Context, bootstrapPath string, s setupSteps) (result any, err error) {
	stage := "setup_validate"
	defer func() {
		if err != nil {
			err = setupFailed(stage, err)
		}
	}()
	if ctx == nil || s.plan == nil || s.readBootstrap == nil || s.validateBootstrap == nil || s.createJournal == nil || s.apply == nil || s.prepare == nil || s.verifyOwned == nil || s.enroll == nil || s.start == nil {
		return nil, marked(windowsservice.PhaseSetup, windowsservice.ReasonInvalidConfiguration, nil)
	}
	stage = "setup_context"
	if ctx.Err() != nil {
		return nil, marked(windowsservice.PhaseSetup, windowsservice.ReasonInterrupted, ctx.Err())
	}
	stage = "service_plan"
	plan, err := s.plan(ctx)
	if err != nil || plan.Existing.Exists {
		return nil, marked(windowsservice.PhaseRuntimeInstallation, windowsservice.ReasonInvalidConfiguration, err)
	}
	stage = "bootstrap_read"
	raw, err := s.readBootstrap(bootstrapPath)
	if err != nil {
		return nil, marked(windowsservice.PhaseBootstrap, windowsservice.ReasonStateUnavailable, err)
	}
	defer clear(raw)
	stage = "bootstrap_validate"
	if err = s.validateBootstrap(raw); err != nil {
		return nil, marked(windowsservice.PhaseBootstrap, windowsservice.ReasonInvalidConfiguration, err)
	}
	stage = "journal_create"
	admin, err := s.createJournal(plan.Layout)
	if err != nil || admin == nil {
		return nil, marked(windowsservice.PhaseReceipt, windowsservice.ReasonStateRejected, err)
	}
	defer admin.Close()
	stage = "intent_encode"
	intent, err := json.Marshal(plan)
	if err != nil {
		return nil, marked(windowsservice.PhaseReceipt, windowsservice.ReasonResultEncoding, err)
	}
	stage = "intent_write"
	if err = admin.Write("intent.json", intent); err != nil {
		return nil, marked(windowsservice.PhaseReceipt, windowsservice.ReasonStateRejected, err)
	}
	stage = "service_install"
	receipt, installErr := s.apply(ctx, plan)
	retained := installReceipt{Version: 1, Service: receipt}
	stage = "receipt_encode"
	saved, err := json.Marshal(retained)
	if err != nil {
		return nil, setupFirstInstallFailure(installErr, marked(windowsservice.PhaseReceipt, windowsservice.ReasonResultEncoding, err))
	}
	stage = "receipt_write"
	if err = admin.Write("receipt.json", saved); err != nil {
		return nil, setupFirstInstallFailure(installErr, marked(windowsservice.PhaseReceipt, windowsservice.ReasonStateRejected, err))
	}
	stage = "service_install"
	if installErr != nil || !receipt.Complete {
		return nil, marked(windowsservice.PhaseSetup, windowsservice.ReasonOperationFailed, installErr)
	}
	stage = "runtime_prepare"
	if err = s.prepare(plan.Layout, receipt, raw); err != nil {
		return nil, marked(windowsservice.PhaseRetainedState, windowsservice.ReasonStateRejected, err)
	}
	retained.Prepared = true
	stage = "prepared_receipt_encode"
	saved, err = json.Marshal(retained)
	if err != nil {
		return nil, marked(windowsservice.PhaseReceipt, windowsservice.ReasonResultEncoding, err)
	}
	stage = "prepared_receipt_write"
	if err = admin.Write("receipt.json", saved); err != nil {
		return nil, marked(windowsservice.PhaseReceipt, windowsservice.ReasonStateRejected, err)
	}
	stage = "journal_close"
	if err = admin.Close(); err != nil {
		return nil, marked(windowsservice.PhaseReceipt, windowsservice.ReasonStateRejected, err)
	}
	stage = "owned_verify"
	if err = s.verifyOwned(ctx, receipt); err != nil {
		return nil, marked(windowsservice.PhaseRuntimeInstallation, windowsservice.ReasonInvalidConfiguration, err)
	}
	stage = "enrollment"
	if err = s.enroll(ctx, plan.Layout); err != nil {
		return nil, marked(windowsservice.PhaseEnrollment, windowsservice.ReasonEnrollmentFailed, err)
	}
	stage = "service_start"
	result, err = s.start(ctx, receipt)
	if err != nil {
		return nil, marked(windowsservice.PhaseLifecycle, windowsservice.ReasonOperationFailed, err)
	}
	return result, nil
}

// Selected local consent must match the retained public bootstrap exactly.
func validateWindowsBootstrapProfile(b enrollmentclient.Bootstrap, selected string) error {
	return validateWindowsBootstrapConsent(b, selected, false)
}

func validateWindowsBootstrapConsent(b enrollmentclient.Bootstrap, selected string, insecure bool) error {
	transportOK := b.Profile == "tls" && !insecure || b.Profile == "http-test" && insecure && selected == enrollmentcrypto.CollectionProfileWindowsInventory
	if !transportOK || b.CollectionProfile != selected || (selected != enrollmentcrypto.CollectionProfile && selected != enrollmentcrypto.CollectionProfileWindowsInventory) {
		return errLifecycle
	}
	return nil
}

// Strict canonical receipt decoding keeps every legacy v1 byte shape unchanged.
// Fresh v2 is usable by ordinary lifecycle only after the exact startup transition
// has completed; unfinished or indeterminate records remain inspection-only.
func decodeInstallReceipt(raw []byte, layout windowsservice.Layout) (installReceipt, error) {
	var r installReceipt
	if len(raw) == 0 || len(raw) > 64<<10 || json.Unmarshal(raw, &r) != nil || !(r.Version == 1 && r.ReadSetup == nil || completeReadSetup(r)) || !r.Prepared || !r.Service.Complete || r.Service.Version != 1 || r.Service.Layout != layout {
		return installReceipt{}, marked(windowsservice.PhaseReceipt, windowsservice.ReasonStateRejected, errLifecycle)
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(canonical, raw) {
		return installReceipt{}, marked(windowsservice.PhaseReceipt, windowsservice.ReasonStateRejected, errLifecycle)
	}
	return r, nil
}
