//go:build windows

package main

import (
	"bytes"
	"context"
	"path/filepath"
	"time"

	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsagentconfig"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
)

func nativeReadAdminContinuation(ctx context.Context, input readAdminContinuationRequest) (result readAdminContinuationPlan, err error) {
	layout, err := windowsservice.ResolveLayout()
	if err != nil {
		return result, err
	}
	// Create remains false. Missing used state and schema/manifest differences
	// fail; there is no adoption, store upgrade, ACL or binary replacement.
	store, err := windowsstate.Open(installerPath(layout), windowsagentconfig.Installer(false))
	if err != nil {
		return result, err
	}
	defer func() {
		if closeErr := store.Close(); err == nil && closeErr != nil {
			result = readAdminContinuationPlan{}
			err = closeErr
		}
	}()
	intent, err := store.Read("intent.json")
	if err != nil {
		return result, err
	}
	defer clear(intent)
	receipt, err := store.Read("receipt.json")
	if err != nil {
		return result, err
	}
	defer clear(receipt)
	var r installReceipt
	if !canonicalRecoveryRecord(receipt, &r) || r.Service.Layout != layout {
		return result, errLifecycle
	}
	b, err := bootstrap(layout)
	if err != nil || b.Profile != "tls" || b.RenewalPolicy != "" || validateWindowsBootstrapConsent(b, enrollmentcrypto.CollectionProfileWindowsInventory, false) != nil {
		return result, errLifecycle
	}
	verifyBytes := func(expected []byte) error {
		if ctx.Err() != nil || store.Verify() != nil {
			return errLifecycle
		}
		i, e := store.Read("intent.json")
		defer clear(i)
		if e != nil || !bytes.Equal(i, intent) {
			return errLifecycle
		}
		current, e := store.Read("receipt.json")
		defer clear(current)
		if e != nil || !bytes.Equal(current, expected) {
			return errLifecycle
		}
		return nil
	}
	var originalRecoveryDeadline int64
	var originalRecoveryBinding string
	verify := func(ctx context.Context, expected []byte) error {
		if originalRecoveryDeadline != 0 && time.Now().Unix() >= originalRecoveryDeadline || verifyBytes(expected) != nil {
			return errLifecycle
		}
		snapshot, e := windowsservice.InspectFreshReadSetup(ctx, r.Service)
		if e != nil || snapshot.State != windowsservice.Stopped || ctx.Err() != nil {
			return errLifecycle
		}
		return nil
	}
	return continueReadAdmin(ctx, intent, receipt, input.apply, input.approval, readAdminContinuationSteps{
		now:    time.Now,
		verify: verify,
		absent: func() error { return lanclient.WindowsReadAdminScopesV14Absent(layout.StateRoot, r.Service.ServiceSID) },
		enrollment: func() (enrollmentclient.ServiceRecoveryState, error) {
			state, e := enrollmentclient.InspectServiceRecovery(b, layout.EnrollmentRoot)
			if e == nil && originalRecoveryDeadline == 0 {
				originalRecoveryDeadline = state.DeadlineAt
				originalRecoveryBinding = state.Binding
			}
			return state, e
		},
		resume: func(ctx context.Context) error {
			_, e := enrollmentclient.ResumeServiceRecovery(ctx, b, layout.EnrollmentRoot, enrollmentclient.ServiceRecoveryState{Binding: originalRecoveryBinding, DeadlineAt: originalRecoveryDeadline})
			return e
		},
		update: func(previous, next []byte) error {
			if verifyBytes(previous) != nil {
				return errLifecycle
			}
			if e := store.Write("receipt.json", next); e != nil {
				return e
			}
			return store.Verify()
		},
		identity: lanclient.WindowsCapabilityIdentity,
		configure: func(path string, consent lanclient.WindowsCapabilityConsent) (lanclient.WindowsCapabilityConsentResult, error) {
			raw, e := store.Read("receipt.json")
			if e != nil {
				return lanclient.WindowsCapabilityConsentResult{}, e
			}
			defer clear(raw)
			return lanclient.ConfigureWindowsReadAdminCapabilities(path, consent, func() error {
				if verify(ctx, raw) != nil {
					return errLifecycle
				}
				binding, e := lanclient.WindowsCapabilityIdentity(filepath.Join(layout.EnrollmentRoot, "agent.json"), consent)
				if e != nil {
					return e
				}
				_, e = readAdminFreshGrantReceipt(raw, consent, binding)
				return e
			})
		},
		verifyGrants: lanclient.VerifyWindowsCapabilities,
		grantDigests: lanclient.WindowsCapabilityGrantDigests,
		activate:     windowsservice.ActivateFreshReadSetup,
		start:        windowsservice.ApplyStart,
	})
}
