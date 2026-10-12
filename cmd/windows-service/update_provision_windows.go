//go:build windows

package main

import (
	"context"
	"errors"
	"io/fs"
	job "localrmm/internal/windowsupdatejob"
	"path/filepath"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclient"
	fence "localrmm/internal/windowsmutationfence"
	"localrmm/internal/windowspackage"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
	"localrmm/internal/windowsupdateipc"
	"localrmm/internal/windowsupdateservice"
	"localrmm/internal/windowsupdatesetup"
)

func nativeUpdateProvision(ctx context.Context, in updateProvisionInput) (result updateProvisionResult, err error) {
	_, err = withReceiptLease(ctx, openReceiptStore, func(receipt installReceipt, lease receiptStore) (any, error) {
		return nativeUpdateProvisionUnderLease(ctx, in, &result, receipt, lease)
	})
	if err != nil {
		result.registration = job.SetupRegistration{}
	}
	return
}

func nativeUpdateProvisionUnderLease(ctx context.Context, in updateProvisionInput, result *updateProvisionResult, receipt installReceipt, lease receiptStore) (any, error) {
	profile := func() error {
		if in.coordinated == nil {
			if in.background {
				return windowspackage.CheckBackgroundUpdateFresh(ctx)
			}
			return windowspackage.CheckManagedMSIAbsent(ctx)
		}
		exclusive := windowspackage.CheckCoordinatedMutationExclusive
		if in.background {
			exclusive = windowspackage.CheckBackgroundMutationExclusive
		}
		if e := exclusive(ctx); e != nil {
			return e
		}
		return fence.VerifyStaged(ctx, in.coordinated.Roster)
	}
	if e := profile(); e != nil {
		return nil, e
	}
	path := filepath.Join(receipt.Service.Layout.EnrollmentRoot, "agent.json")
	check := func(ctx context.Context) (lanclient.WindowsUpdateSetupIdentity, error) {
		if ctx.Err() != nil || lease.Verify() != nil || profile() != nil {
			return lanclient.WindowsUpdateSetupIdentity{}, errLifecycle
		}
		current, e := windowsservice.InspectOwned(ctx, receipt.Service)
		if e != nil || current.State != windowsservice.Stopped {
			return lanclient.WindowsUpdateSetupIdentity{}, errLifecycle
		}
		original, e := bootstrap(receipt.Service.Layout)
		if e != nil || original.Profile != "tls" || original.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory || original.ManagerInstanceID != in.offer.ManagerID || original.AgentOrigin != in.offer.ManagerOrigin {
			return lanclient.WindowsUpdateSetupIdentity{}, errLifecycle
		}
		identity, e := lanclient.InspectWindowsUpdateSetupIdentity(path, in.offer)
		if e != nil {
			return identity, e
		}
		if ctx.Err() != nil || lease.Verify() != nil {
			return identity, errLifecycle
		}
		return identity, nil
	}
	identity, e := check(ctx)
	if e != nil {
		return nil, e
	}
	newPlan := windowsupdatesetup.NewPlan
	if in.background {
		newPlan = windowsupdatesetup.NewBackgroundPlan
	}
	if in.schedule {
		newPlan = windowsupdatesetup.NewScheduledPlan
		if in.background {
			newPlan = windowsupdatesetup.NewScheduledBackgroundPlan
		}
	}
	p, e := newPlan(in.offer, in.artifact, identity, receipt.Service)
	if e != nil {
		return nil, e
	}
	if in.coordinated != nil {
		p, e = windowsupdatesetup.NewCoordinatedPlan(p, in.coordinated.Roster.Plan.PlanDigest)
		if e != nil {
			return nil, e
		}
	}
	result.plan = p
	imageFunc := windowspackage.OpenUpdateExecutorImage
	options := windowsupdateipc.StoreOptions()
	if in.background {
		imageFunc = windowspackage.OpenUpdateServiceImage
		options = windowsupdateipc.ServiceStoreOptions()
	}
	image, e := imageFunc(ctx, receipt.Service)
	if e != nil {
		return nil, e
	}
	defer image.Close()
	exact := func(ctx context.Context, p windowsupdatesetup.Plan) error {
		current, e := check(ctx)
		if e != nil || current != p.Identity || p.Observer != receipt.Service {
			return windowsupdatesetup.ErrChanged
		}
		return nil
	}
	fresh := func(ctx context.Context, p windowsupdatesetup.Plan) error {
		if exact(ctx, p) != nil || image.CheckAbsent(ctx) != nil || in.background && windowsupdateservice.CheckAbsent(ctx) != nil {
			return windowsupdatesetup.ErrExisting
		}
		s, e := windowsstate.Open(p.StateRoot, options)
		if s != nil {
			_ = s.Close()
			return windowsupdatesetup.ErrExisting
		}
		if !errors.Is(e, fs.ErrNotExist) {
			return windowsupdatesetup.ErrExisting
		}
		if e = lanclient.CheckWindowsUpdateRelayAbsent(path, p.Offer); e != nil {
			return e
		}
		return exact(ctx, p)
	}
	if !in.apply {
		if e = fresh(ctx, p); e != nil {
			return nil, e
		}
		return nil, image.Close()
	}
	hooks := windowsupdatesetup.Hooks{CreateService: windowsupdateservice.CreateDisabled, VerifyService: func(ctx context.Context, c windowsupdateipc.Config) error {
		return windowsupdateservice.CheckInstalled(ctx, c, false)
	}, Check: exact, Fresh: fresh, CreateStore: func(ctx context.Context, p windowsupdatesetup.Plan) (windowsupdatesetup.Store, error) {
		if exact(ctx, p) != nil {
			return nil, errLifecycle
		}
		o := options
		o.Create = true
		return windowsstate.Open(p.StateRoot, o)
	}, CreateImage: image.Create, VerifyImage: image.Verify, CreateRelay: func(ctx context.Context, g lanclient.WindowsUpdateRelayGrant) error {
		if exact(ctx, p) != nil {
			return errLifecycle
		}
		return lanclient.InitializeWindowsUpdateRelayCreateOnly(path, g)
	}, VerifyRelay: func(ctx context.Context, g lanclient.WindowsUpdateRelayGrant) error {
		if exact(ctx, p) != nil {
			return errLifecycle
		}
		return lanclient.VerifyWindowsUpdateRelaySetup(path, g)
	}}
	if in.coordinated == nil {
		result.registration, e = windowsupdatesetup.Apply(ctx, p, in.payload, in.approval, hooks)
	} else {
		if in.approval.Digest != in.coordinated.Roster.Plan.PlanDigest {
			return nil, job.ErrAuthority
		}
		approval := in.approval
		approval.Digest = p.Digest()
		result.registration, e = windowsupdatesetup.ApplyCoordinated(ctx, p, in.payload, approval, hooks, *in.coordinated)
	}
	e = errors.Join(e, image.Close())
	if e != nil {
		return nil, e
	}
	return nil, exact(ctx, p)
}

// Keep a failed/uncertain setup from emitting apparently usable registration.
func nativeUpdateRemove(ctx context.Context, apply bool, approved string) (plan windowsupdatesetup.RemovalPlan, err error) {
	_, err = withReceiptLease(ctx, openReceiptStore, func(receipt installReceipt, lease receiptStore) (any, error) {
		if e := windowspackage.CheckManagedMSIAbsent(ctx); e != nil {
			return nil, e
		}
		check := func(ctx context.Context, p windowsupdatesetup.Plan) error {
			if ctx.Err() != nil || lease.Verify() != nil || p.Observer != receipt.Service {
				return errLifecycle
			}
			s, e := windowsservice.InspectOwned(ctx, receipt.Service)
			if e != nil || s.State != windowsservice.Stopped {
				return errLifecycle
			}
			return nil
		}
		root, e := windowsupdateipc.RootPath()
		if e != nil {
			return nil, e
		}
		s, e := windowsstate.Open(root, windowsupdateipc.StoreOptions())
		if e != nil {
			return nil, e
		}
		defer s.Close()
		var p windowsupdatesetup.Plan
		plan, p, _, e = windowsupdatesetup.InspectRemoval(s)
		if e != nil || check(ctx, p) != nil {
			return nil, windowsupdatesetup.ErrSetup
		}
		image, e := windowspackage.OpenUpdateExecutorImage(ctx, receipt.Service)
		if e != nil {
			return nil, e
		}
		defer image.Close()
		if image.Verify(ctx, plan.Image) != nil || check(ctx, p) != nil {
			return nil, windowsupdatesetup.ErrSetup
		}
		if apply {
			e = windowsupdatesetup.Remove(ctx, s, approved, windowsupdatesetup.RemovalHooks{Check: check, VerifyImage: image.Verify, RetireRelay: func(ctx context.Context, g lanclient.WindowsUpdateRelayGrant) error {
				if check(ctx, p) != nil {
					return errLifecycle
				}
				return lanclient.RetireWindowsUpdateRelay(receipt.Service.Layout, receipt.Service.ServiceSID, g)
			}, RemoveImage: image.Remove, ImageAbsent: image.CheckAbsent})
		}
		if e != nil {
			return nil, e
		}
		return nil, errors.Join(image.Close(), s.Close())
	})
	return
}

// Observer-only uninstall must not strand live separately provisioned update
// authority. Missing final root is old behavior; every other unknown blocks.
func guardUpdateExecutorRemoval(ctx context.Context, r windowsservice.Receipt) error {
	root, e := windowsupdateipc.RootPath()
	if e != nil {
		return e
	}
	s, e := windowsstate.Open(root, windowsupdateipc.StoreOptions())
	if errors.Is(e, fs.ErrNotExist) {
		return nil
	}
	if e != nil || s == nil {
		return windowsupdatesetup.ErrSetup
	}
	defer s.Close()
	if windowsupdatesetup.VerifyRemoved(s) != nil {
		return windowsupdatesetup.ErrSetup
	}
	image, e := windowspackage.OpenUpdateExecutorImage(ctx, r)
	if e != nil {
		return e
	}
	defer image.Close()
	if image.CheckAbsent(ctx) != nil {
		return windowsupdatesetup.ErrSetup
	}
	return errors.Join(image.Close(), s.Close())
}
func uninstallWithUpdateOwnership(ctx context.Context, r windowsservice.Receipt) (windowsservice.ApplyResult, error) {
	if e := windowspackage.CheckManagedMSIAbsent(ctx); e != nil {
		return windowsservice.ApplyResult{}, e
	}
	if e := guardSoftwareExecutorRemoval(ctx, r); e != nil {
		return windowsservice.ApplyResult{}, e
	}
	if e := guardUpdateExecutorRemoval(ctx, r); e != nil {
		return windowsservice.ApplyResult{}, e
	}
	return windowsservice.ApplyUninstall(ctx, r)
}
func nativeUpdateExport(ctx context.Context) (registration job.SetupRegistration, err error) {
	_, err = withReceiptLease(ctx, openReceiptStore, func(receipt installReceipt, lease receiptStore) (any, error) {
		if e := windowspackage.CheckManagedMSIAbsent(ctx); e != nil {
			return nil, e
		}
		snapshot, e := windowsservice.InspectOwned(ctx, receipt.Service)
		if e != nil || snapshot.State != windowsservice.Stopped || lease.Verify() != nil {
			return nil, errLifecycle
		}
		root, e := windowsupdateipc.RootPath()
		if e != nil {
			return nil, e
		}
		s, e := windowsstate.Open(root, windowsupdateipc.StoreOptions())
		if e != nil {
			return nil, e
		}
		defer s.Close()
		registration, e = windowsupdatesetup.Registration(s)
		if e != nil {
			return nil, e
		}
		raw, e := s.Read("config.json")
		if e != nil {
			return nil, e
		}
		config, e := windowsupdateipc.DecodeConfig(raw)
		if e != nil || config.ObserverReceipt != receipt.Service {
			return nil, errLifecycle
		}
		original, e := bootstrap(receipt.Service.Layout)
		if e != nil || original.Profile != "tls" || original.ManagerInstanceID != registration.Offer.ManagerID || original.AgentOrigin != registration.Offer.ManagerOrigin {
			return nil, errLifecycle
		}
		path := filepath.Join(receipt.Service.Layout.EnrollmentRoot, "agent.json")
		if _, e = lanclient.InspectWindowsUpdateSetupIdentity(path, registration.Offer); e != nil {
			return nil, e
		}
		review, plan, _, e := windowsupdatesetup.InspectRemoval(s)
		if e != nil {
			return nil, e
		}
		image, e := windowspackage.OpenUpdateExecutorImage(ctx, receipt.Service)
		if e != nil {
			return nil, e
		}
		defer image.Close()
		if image.Verify(ctx, review.Image) != nil {
			return nil, errLifecycle
		}
		relay, e := windowsupdatesetup.Relay(plan, config)
		if e != nil || lanclient.VerifyWindowsUpdateRelaySetup(path, relay) != nil || lease.Verify() != nil {
			return nil, errLifecycle
		}
		return nil, errors.Join(image.Close(), s.Close())
	})
	if err != nil {
		registration = job.SetupRegistration{}
	}
	return
}
