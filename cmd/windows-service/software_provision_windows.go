//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	job "localrmm/internal/windowssoftwarejob"
	"path/filepath"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowspackage"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowssoftwareipc"
	"localrmm/internal/windowssoftwaresetup"
	"localrmm/internal/windowsstate"
)

func nativeSoftwareProvision(ctx context.Context, in softwareProvisionInput) (result softwareProvisionResult, err error) {
	_, err = withReceiptLease(ctx, openReceiptStore, func(receipt installReceipt, lease receiptStore) (any, error) {
		if e := windowspackage.CheckManagedMSIAbsent(ctx); e != nil {
			return nil, e
		}
		path := filepath.Join(receipt.Service.Layout.EnrollmentRoot, "agent.json")
		check := func(ctx context.Context) (lanclient.WindowsSoftwareSetupIdentity, error) {
			if ctx.Err() != nil || lease.Verify() != nil {
				return lanclient.WindowsSoftwareSetupIdentity{}, errLifecycle
			}
			current, e := windowsservice.InspectOwned(ctx, receipt.Service)
			if e != nil || current.State != windowsservice.Stopped {
				return lanclient.WindowsSoftwareSetupIdentity{}, errLifecycle
			}
			original, e := bootstrap(receipt.Service.Layout)
			if e != nil || original.Profile != "tls" || original.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory || original.ManagerInstanceID != in.offer.ManagerID || original.AgentOrigin != in.offer.ManagerOrigin {
				return lanclient.WindowsSoftwareSetupIdentity{}, errLifecycle
			}
			identity, e := lanclient.InspectWindowsSoftwareSetupIdentity(path, in.offer)
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
		p, e := windowssoftwaresetup.NewPlan(in.offer, in.artifact, identity, receipt.Service, in.selection, in.acceptance)
		if e != nil {
			return nil, e
		}
		result.plan = p
		image, e := windowspackage.OpenSoftwareExecutorImage(ctx, receipt.Service)
		if e != nil {
			return nil, e
		}
		defer image.Close()
		exact := func(ctx context.Context, p windowssoftwaresetup.Plan) error {
			current, e := check(ctx)
			if e != nil || current != p.Identity || p.Observer != receipt.Service {
				return windowssoftwaresetup.ErrChanged
			}
			return nil
		}
		fresh := func(ctx context.Context, p windowssoftwaresetup.Plan) error {
			if exact(ctx, p) != nil || image.CheckAbsent(ctx) != nil || windowspackage.CheckPreparedMSIAbsent(ctx, receipt.Service) != nil {
				return windowssoftwaresetup.ErrExisting
			}
			s, e := windowsstate.Open(p.StateRoot, windowssoftwareipc.StoreOptions())
			if s != nil {
				_ = s.Close()
				return windowssoftwaresetup.ErrExisting
			}
			if !errors.Is(e, fs.ErrNotExist) {
				return windowssoftwaresetup.ErrExisting
			}
			if e = lanclient.CheckWindowsSoftwareRelayAbsent(path, p.Offer); e != nil {
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
		hooks := windowssoftwaresetup.Hooks{Check: exact, Fresh: fresh, CreateStore: func(ctx context.Context, p windowssoftwaresetup.Plan) (windowssoftwaresetup.Store, error) {
			if exact(ctx, p) != nil {
				return nil, errLifecycle
			}
			o := windowssoftwareipc.StoreOptions()
			o.Create = true
			return windowsstate.Open(p.StateRoot, o)
		}, StagePackage: func(ctx context.Context, payload []byte, selection job.Selection) (windowspackage.PreparedMSIReceipt, error) {
			return windowspackage.StagePreparedMSI(ctx, receipt.Service, payload, selection)
		}, VerifyPackage: func(ctx context.Context, r windowspackage.PreparedMSIReceipt) error {
			p, e := windowspackage.OpenPreparedMSI(ctx, r)
			if e != nil {
				return e
			}
			return p.Close()
		}, CreateImage: image.Create, VerifyImage: image.Verify, CreateRelay: func(ctx context.Context, g lanclient.WindowsSoftwareRelayGrant) error {
			if exact(ctx, p) != nil {
				return errLifecycle
			}
			return lanclient.InitializeWindowsSoftwareRelayCreateOnly(path, g)
		}, VerifyRelay: func(ctx context.Context, g lanclient.WindowsSoftwareRelayGrant) error {
			if exact(ctx, p) != nil {
				return errLifecycle
			}
			return lanclient.VerifyWindowsSoftwareRelaySetup(path, g)
		}}
		result.registration, e = windowssoftwaresetup.Apply(ctx, p, in.payload, in.packagePayload, in.approval, hooks)
		e = errors.Join(e, image.Close())
		if e != nil {
			return nil, e
		}
		return nil, exact(ctx, p)
	})
	if err != nil {
		result.registration = job.SetupRegistration{}
	}
	return
}

// Without a separately reviewed retirement workflow, any software authority
// blocks observer removal. Missing or partial used state is never reset.
func guardSoftwareExecutorRemoval(ctx context.Context, r windowsservice.Receipt) error {
	root, e := windowssoftwareipc.RootPath()
	if e != nil {
		return e
	}
	s, e := windowsstate.Open(root, windowssoftwareipc.StoreOptions())
	if s != nil {
		_ = s.Close()
		return windowssoftwaresetup.ErrSetup
	}
	if !errors.Is(e, fs.ErrNotExist) {
		return windowssoftwaresetup.ErrSetup
	}
	return windowspackage.CheckPreparedMSIAbsent(ctx, r)
}
func nativeSoftwareExport(ctx context.Context) (registration job.SetupRegistration, err error) {
	_, err = withReceiptLease(ctx, openReceiptStore, func(receipt installReceipt, lease receiptStore) (any, error) {
		if e := windowspackage.CheckManagedMSIAbsent(ctx); e != nil {
			return nil, e
		}
		snapshot, e := windowsservice.InspectOwned(ctx, receipt.Service)
		if e != nil || snapshot.State != windowsservice.Stopped || lease.Verify() != nil {
			return nil, errLifecycle
		}
		root, e := windowssoftwareipc.RootPath()
		if e != nil {
			return nil, e
		}
		s, e := windowsstate.Open(root, windowssoftwareipc.StoreOptions())
		if e != nil {
			return nil, e
		}
		defer s.Close()
		registration, e = windowssoftwaresetup.Registration(s)
		if e != nil {
			return nil, e
		}
		raw, e := s.Read("config.json")
		if e != nil {
			return nil, e
		}
		config, e := windowssoftwareipc.DecodeConfig(raw)
		if e != nil || config.ObserverReceipt != receipt.Service {
			return nil, errLifecycle
		}
		original, e := bootstrap(receipt.Service.Layout)
		if e != nil || original.Profile != "tls" || original.ManagerInstanceID != registration.Offer.ManagerID || original.AgentOrigin != registration.Offer.ManagerOrigin {
			return nil, errLifecycle
		}
		path := filepath.Join(receipt.Service.Layout.EnrollmentRoot, "agent.json")
		if _, e = lanclient.InspectWindowsSoftwareSetupIdentity(path, registration.Offer); e != nil {
			return nil, e
		}
		// Registration already validated the exact complete immutable plan and
		// progress. Recheck both owned image and package custody before export.
		var plan windowssoftwaresetup.Plan
		planRaw, e := s.Read("provision.json")
		if e != nil || json.Unmarshal(planRaw, &plan) != nil {
			return nil, errLifecycle
		}
		var progress windowssoftwaresetup.Progress
		progressRaw, e := s.Read("progress.json")
		if e != nil || json.Unmarshal(progressRaw, &progress) != nil || progress.Image == nil || progress.Package == nil {
			return nil, errLifecycle
		}
		prepared, e := windowspackage.OpenPreparedMSI(ctx, *progress.Package)
		if e != nil {
			return nil, errLifecycle
		}
		defer prepared.Close()

		image, e := windowspackage.OpenSoftwareExecutorImage(ctx, receipt.Service)
		if e != nil {
			return nil, e
		}
		defer image.Close()
		if image.Verify(ctx, *progress.Image) != nil {
			return nil, errLifecycle
		}
		relay, e := windowssoftwaresetup.Relay(plan, config)
		if e != nil || lanclient.VerifyWindowsSoftwareRelaySetup(path, relay) != nil || lease.Verify() != nil {
			return nil, errLifecycle
		}
		if windowssoftwaresetup.VerifyInstalled(s, config) != nil || prepared.Verify(ctx) != nil {
			return nil, errLifecycle
		}
		return nil, errors.Join(prepared.Close(), image.Close(), s.Close())
	})
	if err != nil {
		registration = job.SetupRegistration{}
	}
	return
}
