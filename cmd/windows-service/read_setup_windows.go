//go:build windows

package main

import (
	"bytes"
	"context"
	"io"

	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsagentconfig"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
)

// installReadObservation is intentionally not dispatched by nativeOperation or
// exposed as a command. A future verified installer must show every scope's full
// privacy disclosure (including every HTTP warning), obtain one explicit local
// acknowledgement, and satisfy real release/native gates before invoking it.
func installReadObservation(ctx context.Context, bootstrapPath string, consent lanclient.WindowsCapabilityConsent, out, stderr io.Writer) (any, error) {
	if validateReadSetupConsent(consent) != nil {
		return nil, errLifecycle
	}
	if err := writeReadSetupDisclosure(out, consent); err != nil {
		return nil, err
	}
	s := nativeSetupSteps(enrollmentcrypto.CollectionProfileWindowsInventory, consent.InsecureHTTPAcknowledged, out, stderr)
	s.plan = windowsservice.PlanFreshReadSetup
	s.apply = windowsservice.ApplyFreshReadSetup
	s.verifyOwned = func(ctx context.Context, receipt windowsservice.Receipt) error {
		snapshot, err := windowsservice.InspectFreshReadSetup(ctx, receipt)
		if err != nil {
			return err
		}
		if snapshot.State != windowsservice.Stopped {
			return windowsservice.ErrNotStopped
		}
		return nil
	}
	return setupReadObservation(ctx, bootstrapPath, consent, readSetupSteps{
		setup: s,
		updateReceipt: func(layout windowsservice.Layout, previous, next []byte) error {
			store, err := windowsstate.Open(installerPath(layout), windowsagentconfig.Installer(false))
			if err != nil {
				return err
			}
			defer store.Close()
			raw, err := store.Read("receipt.json")
			if err != nil || !bytes.Equal(raw, previous) {
				return errLifecycle
			}
			if err = store.Write("receipt.json", next); err != nil {
				return err
			}
			return store.Close()
		},
		ensureFreshScopes: func(receipt windowsservice.Receipt) error {
			return lanclient.WindowsCapabilityScopesAbsent(receipt.Layout.StateRoot, receipt.ServiceSID)
		},
		activateIdentity: func(ctx context.Context, receipt windowsservice.Receipt) error {
			b, err := bootstrap(receipt.Layout)
			if err != nil {
				return err
			}
			if err = validateWindowsBootstrapConsent(b, enrollmentcrypto.CollectionProfileWindowsInventory, consent.InsecureHTTPAcknowledged); err != nil {
				return err
			}
			// ResumeService cannot create a new identity or ask for another invitation.
			// Original pending expiry and bounded enrollment session remain authoritative.
			if _, err = enrollmentclient.ResumeService(ctx, b, receipt.Layout.EnrollmentRoot, consent.InsecureHTTPAcknowledged, nil); err != nil {
				return err
			}
			state, err := enrollmentclient.InspectService(b, receipt.Layout.EnrollmentRoot, consent.InsecureHTTPAcknowledged)
			if err != nil || !state.Ready {
				return errLifecycle
			}
			return nil
		},
		identity:        lanclient.WindowsCapabilityIdentity,
		configure:       lanclient.ConfigureWindowsCapabilities,
		verifyGrants:    lanclient.VerifyWindowsCapabilities,
		grantDigests:    lanclient.WindowsCapabilityGrantDigests,
		activateStartup: windowsservice.ActivateFreshReadSetup,
	})
}

// reconcileReadObservationInstallation has no CLI dispatch. Its sole possible
// mutation is completion-receipt finalization after exact protected readback.
// It never starts/reconfigures SCM, reenrolls, or writes a scope grant.
func reconcileReadObservationInstallation(ctx context.Context) (readSetupReconciliation, error) {
	zero := readSetupReconciliation{}
	layout, err := windowsservice.ResolveLayout()
	if err != nil {
		return zero, err
	}
	store, err := windowsstate.Open(installerPath(layout), windowsagentconfig.Installer(false))
	if err != nil {
		return zero, err
	}
	defer store.Close()
	intent, err := store.Read("intent.json")
	if err != nil {
		return zero, err
	}
	receipt, err := store.Read("receipt.json")
	if err != nil {
		return zero, err
	}
	return reconcileReadObservation(ctx, intent, receipt, readSetupReconcileSteps{
		identity:       lanclient.WindowsCapabilityIdentity,
		grantDigests:   lanclient.WindowsCapabilityGrantDigests,
		inspectStartup: windowsservice.ReconcileFreshReadSetup,
		finalizeReceipt: func(previous, next []byte) error {
			currentIntent, err := store.Read("intent.json")
			if err != nil || !bytes.Equal(currentIntent, intent) {
				return errLifecycle
			}
			currentReceipt, err := store.Read("receipt.json")
			if err != nil || !bytes.Equal(currentReceipt, previous) {
				return errLifecycle
			}
			if err = store.Write("receipt.json", next); err != nil {
				return err
			}
			return store.Close()
		},
	})
}
