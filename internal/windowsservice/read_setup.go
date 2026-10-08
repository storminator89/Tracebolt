package windowsservice

import (
	"context"
	"reflect"
)

// PlanFreshReadSetup preserves the ordinary fixed configuration except that SCM
// startup is disabled. It grants no authority and creates no service.
func PlanFreshReadSetup(ctx context.Context) (InstallPlan, error) {
	p, err := Plan(ctx)
	if err == nil {
		p.Configuration.StartType = 4
	}
	return p, err
}

// ApplyFreshReadSetup is create-only. Its version-2 receipt cannot be passed to
// ordinary lifecycle functions. Disabled means neither boot nor StartService
// can run it; a trusted administrator changing configuration is outside this guard.
func ApplyFreshReadSetup(ctx context.Context, p InstallPlan) (Receipt, error) {
	return installMode(ctx, nativeBackend(), p, true)
}
func InspectFreshReadSetup(ctx context.Context, r Receipt) (Snapshot, error) {
	s, snapshot, err := openOwnedMode(ctx, nativeBackend(), r, readAccess, true, true)
	if s != nil {
		_ = s.Close()
	}
	return snapshot, err
}

// ActivateFreshReadSetup only changes the exact owned disabled service to the
// ordinary automatic configuration. The caller must first durably record its
// activated identity and complete combined grants, then a transition intent.
// An error can have an indeterminate SCM outcome: retain both receipts and never
// retry, reset, delete or adopt state to recover. Reconcile is read-only.
func ActivateFreshReadSetup(ctx context.Context, r Receipt) (Receipt, error) {
	return activateFreshReadSetup(ctx, nativeBackend(), r)
}
func automaticReceipt(r Receipt) Receipt {
	r.Version = 1
	r.ConfigurationSHA256 = digestConfig(configuration(r.Layout, r.InstallationID, r.ExecutableSHA256))
	return r
}
func activateFreshReadSetup(ctx context.Context, b backend, r Receipt) (result Receipt, err error) {
	s, snapshot, err := openOwnedMode(ctx, b, r, configureAccess, true, true)
	if err != nil {
		return Receipt{}, err
	}
	defer func() {
		if closeErr := s.Close(); err == nil && closeErr != nil {
			// The startup effect may already have succeeded. Preserve the staged
			// receipt for explicit read-only reconciliation; never imply completion.
			result = Receipt{}
			err = closeErr
		}
	}()
	if snapshot.State != Stopped {
		return Receipt{}, ErrNotStopped
	}
	change, ok := s.(interface{ SetAutomatic() error })
	if !ok {
		return Receipt{}, ErrMismatch
	}
	if err = ctx.Err(); err != nil {
		return Receipt{}, err
	}
	if err = change.SetAutomatic(); err != nil {
		return Receipt{}, err
	}
	expected := automaticReceipt(r)
	observed, err := s.Inspect()
	if err != nil {
		return Receipt{}, err
	}
	if !observed.Exists || observed.State != Stopped || observed.ServiceSID != r.ServiceSID || !reflect.DeepEqual(observed.Configuration, configuration(r.Layout, r.InstallationID, r.ExecutableSHA256)) {
		return Receipt{}, ErrMismatch
	}
	return expected, nil
}

// ReconcileFreshReadSetup returns only an exact disabled or exact automatic
// binding. It never changes SCM or authorizes receipt replacement/resume.
func ReconcileFreshReadSetup(ctx context.Context, r Receipt) (Receipt, error) {
	return reconcileFreshReadSetup(ctx, nativeBackend(), r)
}
func reconcileFreshReadSetup(ctx context.Context, b backend, r Receipt) (Receipt, error) {
	s, _, err := openOwnedMode(ctx, b, r, readAccess, true, true)
	if err == nil {
		_ = s.Close()
		return r, nil
	}
	// Validate the staged receipt before deriving the only allowable successor.
	c := configuration(r.Layout, r.InstallationID, r.ExecutableSHA256)
	c.StartType = 4
	if r.Version != 2 || !r.Complete || r.ConfigurationSHA256 != digestConfig(c) {
		return Receipt{}, ErrMismatch
	}
	next := automaticReceipt(r)
	s, _, err = openOwned(ctx, b, next, readAccess, true)
	if s != nil {
		_ = s.Close()
	}
	if err != nil {
		return Receipt{}, err
	}
	return next, nil
}
