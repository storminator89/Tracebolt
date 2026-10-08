package main

import (
	"context"
	"path/filepath"
	"reflect"

	"localrmm/internal/lanclient"
	"localrmm/internal/windowsacceptance/freshgate"
	"localrmm/internal/windowsservice"
)

// Test-only verification is split around the existing owned-service stop. The
// sender owns its exclusive ledger for its full running lifetime. Never open
// that ledger through the handoff/identity/grant APIs while the service runs.
type freshCompletionSteps struct {
	receipt  func() (installReceipt, error)
	service  func(context.Context, windowsservice.Receipt) error
	identity func(string, lanclient.WindowsCapabilityConsent) (string, error)
	grants   func(string, lanclient.WindowsCapabilityConsent) ([]lanclient.WindowsCapabilityGrantDigest, error)
}

func freshCompletionAllowed(ctx context.Context, check func() bool) bool {
	return ctx != nil && ctx.Err() == nil && check != nil && check()
}

// Live verification reads the protected completion receipt and actual running
// service token only. It does not claim independent sender/grant verification.
func freshLiveCompletion(ctx context.Context, check func() bool, s freshCompletionSteps) (installReceipt, error) {
	if !freshCompletionAllowed(ctx, check) || s.receipt == nil || s.service == nil {
		return installReceipt{}, setupFailed("completion_context", freshgate.ErrGuard)
	}
	r, err := s.receipt()
	if err != nil || !completeReadSetup(r) {
		return installReceipt{}, setupFailed("completion_receipt", freshgate.ErrGuard)
	}
	if !freshCompletionAllowed(ctx, check) {
		return installReceipt{}, setupFailed("completion_context", freshgate.ErrGuard)
	}
	if s.service(ctx, r.Service) != nil {
		return installReceipt{}, setupFailed("completion_token", freshgate.ErrGuard)
	}
	if !freshCompletionAllowed(ctx, check) {
		return installReceipt{}, setupFailed("completion_context", freshgate.ErrGuard)
	}
	return r, nil
}

// Stopped verification is additional readback of the SAME live receipt. The
// caller has already reaped the child and stopped the exact owned automatic
// service. Independently require stopped state before any exclusive-store read,
// and again afterward. Existing identity/grant APIs and lock rules stay intact.
func freshStoppedCompletion(ctx context.Context, check func() bool, expected installReceipt, s freshCompletionSteps) error {
	if !freshCompletionAllowed(ctx, check) || !completeReadSetup(expected) || s.receipt == nil || s.service == nil || s.identity == nil || s.grants == nil {
		return setupFailed("completion_context", freshgate.ErrGuard)
	}
	if s.service(ctx, expected.Service) != nil {
		return setupFailed("completion_receipt", freshgate.ErrGuard)
	}
	if !freshCompletionAllowed(ctx, check) {
		return setupFailed("completion_context", freshgate.ErrGuard)
	}
	r, err := s.receipt()
	if err != nil || !completeReadSetup(r) || !reflect.DeepEqual(r, expected) {
		return setupFailed("completion_receipt", freshgate.ErrGuard)
	}
	if !freshCompletionAllowed(ctx, check) {
		return setupFailed("completion_context", freshgate.ErrGuard)
	}
	path := filepath.Join(r.Service.Layout.EnrollmentRoot, "agent.json")
	binding, err := s.identity(path, r.ReadSetup.Consent)
	if err != nil || binding != r.ReadSetup.SenderBinding {
		return setupFailed("completion_identity", freshgate.ErrGuard)
	}
	if !freshCompletionAllowed(ctx, check) {
		return setupFailed("completion_context", freshgate.ErrGuard)
	}
	digests, err := s.grants(path, r.ReadSetup.Consent)
	if err != nil || !reflect.DeepEqual(digests, r.ReadSetup.GrantDigests) {
		return setupFailed("completion_grants", freshgate.ErrGuard)
	}
	if !freshCompletionAllowed(ctx, check) {
		return setupFailed("completion_context", freshgate.ErrGuard)
	}
	if s.service(ctx, expected.Service) != nil {
		return setupFailed("completion_receipt", freshgate.ErrGuard)
	}
	if !freshCompletionAllowed(ctx, check) {
		return setupFailed("completion_context", freshgate.ErrGuard)
	}
	return nil
}

// Keep the existing stop evidence even when completion readback fails. Stopping
// retains automatic startup configuration; it is never reported as disabling.
type freshQuiescence struct{ Stopped, Disabled, Automatic bool }

func freshFinalizeCompletion(r *freshgate.Report, ready bool, stop func() (freshQuiescence, error), verify func() error) {
	if r == nil {
		return
	}
	r.Status = "failed"
	if !r.OwnedChildReaped || stop == nil {
		return
	}
	q, err := stop()
	r.OwnedServiceStopped, r.ServiceDisabled, r.AutomaticStartConfigurationRetained = q.Stopped, q.Disabled, q.Automatic
	if err != nil || !q.Stopped || !ready || !r.ConsoleClosed || q.Disabled || !q.Automatic || verify == nil {
		return
	}
	if verify() != nil {
		return
	}
	r.ReceiptAndGrantsVerified = true
	r.HiddenConsoleExercised = true
	r.ControllerStage = "completed"
	r.FreshOrchestrationAcceptance = true
	r.Status = "passed_fresh_native_subset"
}
