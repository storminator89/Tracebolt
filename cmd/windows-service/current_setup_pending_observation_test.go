package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"

	"localrmm/internal/lanclient"
	"localrmm/internal/windowsacceptance/setupgate"
	"localrmm/internal/windowsservice"
)

// currentSetupPendingObservation belongs only to the acceptance driver. Capture its
// protected receipt-file snapshot while the worker waits for hidden input, before
// submitting the invitation. The worker holds its exclusive installer journal
// for the WHOLE transaction, including this prompt; the observer must never
// reopen that store. This snapshot is provisional, not manifest verification.
// Native ownership/configuration and executable checks still run on every
// observation. A full-store read after worker quiescence must validate the same
// original binding on both the retained and completed paths.
type currentSetupPendingObservation struct {
	service windowsservice.Receipt
	consent lanclient.WindowsCapabilityConsent
	inspect func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error)
}

func captureCurrentSetupPendingObservation(ctx context.Context, read func() (installReceipt, error), inspect func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error)) (currentSetupPendingObservation, error) {
	if ctx == nil || ctx.Err() != nil || read == nil || inspect == nil {
		return currentSetupPendingObservation{}, setupgate.ErrGuard
	}
	r, err := read()
	if err != nil || !validCurrentSetupPendingReceipt(r) || !reflect.DeepEqual(*r.ReadSetup, readSetupProgress{Consent: freshReadAdminSetupConsent(false), Phase: "claim-started"}) {
		return currentSetupPendingObservation{}, setupgate.ErrGuard
	}
	consent := r.ReadSetup.Consent
	consent.Scopes = append([]string(nil), consent.Scopes...)
	o := currentSetupPendingObservation{service: r.Service, consent: consent, inspect: inspect}
	if o.inspectDisabled(ctx) != nil {
		return currentSetupPendingObservation{}, setupgate.ErrGuard
	}
	return o, nil
}

func validCurrentSetupPendingReceipt(r installReceipt) bool {
	return r.Version == 12 && r.Prepared && r.Service.Version == 2 && r.Service.Complete && r.ReadSetup != nil && reflect.DeepEqual(r.ReadSetup.Consent, freshReadAdminSetupConsent(false))
}

// inspectDisabled uses only the original binding and the injected exact-owned
// inspector (InspectFreshReadSetup in the native controller). There is no store
// access here, including when the worker owns its exclusive phase-write lock.
func (o currentSetupPendingObservation) inspectDisabled(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || o.inspect == nil || o.service.Version != 2 || !o.service.Complete || !reflect.DeepEqual(o.consent, freshReadAdminSetupConsent(false)) {
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
func (o currentSetupPendingObservation) verifyRetained(ctx context.Context, read func() (installReceipt, error)) error {
	if ctx == nil || ctx.Err() != nil || read == nil || o.inspect == nil {
		return setupgate.ErrGuard
	}
	r, err := read()
	if err != nil || !validCurrentSetupPendingReceipt(r) || r.Service != o.service || !reflect.DeepEqual(r.ReadSetup.Consent, o.consent) {
		return setupgate.ErrGuard
	}
	return o.inspectDisabled(ctx)
}

func completeCurrentReadSetup(r installReceipt) bool {
	return r.Version == 12 && r.ReadSetup != nil && reflect.DeepEqual(r.ReadSetup.Consent, freshReadAdminSetupConsent(false)) && completeReadSetup(r)
}

// readCurrentSetupPendingReceipt reads only the admin-protected receipt file.
// The existing protected-file reader pins ancestry and the file, verifies the
// exact installer ACL policy, rejects replacement/reparse/hardlink paths and
// checks bounded bytes twice before releasing its handles. It does not open the
// journal lock or claim to verify its manifest. The hidden prompt is the stable
// capture boundary; all file handles are released before invitation submission.
func readCurrentSetupPendingReceipt(ctx context.Context, layout windowsservice.Layout, read func(string, int64) ([]byte, error)) (installReceipt, error) {
	if ctx == nil || ctx.Err() != nil || read == nil {
		return installReceipt{}, setupgate.ErrGuard
	}
	raw, err := read(filepath.Join(layout.StateRoot+"-installer", "receipt.json"), 64<<10)
	defer clear(raw)
	if err != nil || ctx.Err() != nil {
		return installReceipt{}, setupgate.ErrGuard
	}
	return decodeCurrentSetupReceipt(raw, layout)
}

// Both the provisional protected-file snapshot and quiescent full-store reader
// use exactly the same canonical layout/current-consent checks.
func decodeCurrentSetupReceipt(raw []byte, layout windowsservice.Layout) (installReceipt, error) {
	var r installReceipt
	if len(raw) == 0 || len(raw) > 64<<10 || json.Unmarshal(raw, &r) != nil || r.Version != 12 || r.ReadSetup == nil || r.Service.Layout != layout {
		return installReceipt{}, setupgate.ErrGuard
	}
	canonical, err := json.Marshal(r)
	defer clear(canonical)
	if err != nil || !bytes.Equal(raw, canonical) || !reflect.DeepEqual(r.ReadSetup.Consent, freshReadAdminSetupConsent(false)) {
		return installReceipt{}, setupgate.ErrGuard
	}
	return r, nil
}

// The successful path must also read the authoritative journal after worker
// quiescence. Only the documented disabled-to-automatic version/configuration
// transition may differ; the completed native inspector verifies that digest.
// Identity, executable, layout and original scope consent cannot be substituted.
func (o currentSetupPendingObservation) verifyCompleted(ctx context.Context, read func() (installReceipt, error), inspect func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error)) (installReceipt, error) {
	if ctx == nil || ctx.Err() != nil || o.inspect == nil || read == nil || inspect == nil || o.service.Version != 2 || !o.service.Complete || !reflect.DeepEqual(o.consent, freshReadAdminSetupConsent(false)) {
		return installReceipt{}, setupgate.ErrGuard
	}
	r, err := read()
	if err != nil || ctx.Err() != nil || !completeCurrentReadSetup(r) || !reflect.DeepEqual(r.ReadSetup.Consent, o.consent) {
		return installReceipt{}, setupgate.ErrGuard
	}
	previous := r.Service
	previous.Version = o.service.Version
	previous.ConfigurationSHA256 = o.service.ConfigurationSHA256
	if previous != o.service {
		return installReceipt{}, setupgate.ErrGuard
	}
	s, err := inspect(ctx, r.Service)
	if err != nil || ctx.Err() != nil || !s.Exists || s.ServiceSID != o.service.ServiceSID || s.Configuration.StartType != 2 {
		return installReceipt{}, setupgate.ErrGuard
	}
	return r, nil
}
