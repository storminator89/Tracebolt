package main

import (
	"context"
	"reflect"

	"localrmm/internal/lanclient"
	"localrmm/internal/windowsacceptance/setupgate"
	"localrmm/internal/windowsservice"
)

// setupPendingObservation belongs only to the acceptance driver. Capture its
// protected receipt while the worker waits for hidden input, before submitting
// the invitation. It deliberately retains no installer-store reader: opening
// that exclusively locked store during the worker's phase writes can make
// either the observer or the worker fail. Native ownership/configuration and
// executable checks still run on every observation of the cached binding.
type setupPendingObservation struct {
	service windowsservice.Receipt
	consent lanclient.WindowsCapabilityConsent
	inspect func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error)
}

func captureSetupPendingObservation(ctx context.Context, read func() (installReceipt, error), inspect func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error)) (setupPendingObservation, error) {
	if ctx == nil || ctx.Err() != nil || read == nil || inspect == nil {
		return setupPendingObservation{}, setupgate.ErrGuard
	}
	r, err := read()
	if err != nil || !validSetupPendingReceipt(r) {
		return setupPendingObservation{}, setupgate.ErrGuard
	}
	consent := r.ReadSetup.Consent
	consent.Scopes = append([]string(nil), consent.Scopes...)
	o := setupPendingObservation{service: r.Service, consent: consent, inspect: inspect}
	if o.inspectDisabled(ctx) != nil {
		return setupPendingObservation{}, setupgate.ErrGuard
	}
	return o, nil
}

func validSetupPendingReceipt(r installReceipt) bool {
	return r.Version == 2 && r.Prepared && r.Service.Version == 2 && r.Service.Complete && r.ReadSetup != nil && validateReadSetupConsent(r.ReadSetup.Consent) == nil
}

// inspectDisabled uses only the original binding and the injected exact-owned
// inspector (InspectFreshReadSetup in the native controller). There is no store
// access here, including when the worker owns its exclusive phase-write lock.
func (o setupPendingObservation) inspectDisabled(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || o.inspect == nil || o.service.Version != 2 || !o.service.Complete || validateReadSetupConsent(o.consent) != nil {
		return setupgate.ErrGuard
	}
	s, err := o.inspect(ctx, o.service)
	if err != nil || ctx.Err() != nil || !s.Exists || s.ServiceSID != o.service.ServiceSID || s.State != windowsservice.Stopped || s.Configuration.StartType != 4 {
		return setupgate.ErrGuard
	}
	return nil
}

// verifyRetained may only be called after the setup worker is quiescent. It
// requires a fresh authoritative protected-store read; the captured receipt is
// never sufficient evidence that partial durable state was retained. Phase is
// intentionally not compared: claim-started can become activation-started while
// the same service and consent remain bound. Successful automatic transitions
// use the controller's separate completed-receipt and grant verification path.
func (o setupPendingObservation) verifyRetained(ctx context.Context, read func() (installReceipt, error)) error {
	if ctx == nil || ctx.Err() != nil || read == nil || o.inspect == nil {
		return setupgate.ErrGuard
	}
	r, err := read()
	if err != nil || !validSetupPendingReceipt(r) || r.Service != o.service || !reflect.DeepEqual(r.ReadSetup.Consent, o.consent) {
		return setupgate.ErrGuard
	}
	return o.inspectDisabled(ctx)
}
