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

// installReadObservation is not dispatched by the ordinary lifecycle CLI. The
// separate Setup build must show every scope's full
// privacy disclosure (including every HTTP warning), obtain one explicit local
// acknowledgement, and satisfy real release/native gates before invoking it.
func installReadObservation(ctx context.Context, bootstrapPath string, consent lanclient.WindowsCapabilityConsent, out, stderr io.Writer) (any, error) {
	return installReadObservationWithProgress(ctx, bootstrapPath, consent, out, stderr, nil)
}

func installReadObservationWithProgress(ctx context.Context, bootstrapPath string, consent lanclient.WindowsCapabilityConsent, out, stderr io.Writer, progress func(string), renewal ...bool) (any, error) {
	if progress == nil {
		progress = func(string) {}
	}
	if validateReadSetupConsent(consent) != nil {
		return nil, setupFailed("fresh_consent", errLifecycle)
	}
	if err := writeReadSetupDisclosure(out, consent); err != nil {
		return nil, setupFailedCategory("fresh_disclosure", "failed", err)
	}
	s := nativeSetupSteps(enrollmentcrypto.CollectionProfileWindowsInventory, consent.InsecureHTTPAcknowledged, out, stderr, renewal...)
	// Progress writes borrow the create-only journal that setup already holds.
	// Reopening it would deadlock/fail its existing cross-process exclusive lock.
	var journal *windowsstate.Store
	var journalLayout windowsservice.Layout
	createJournal := s.createJournal
	s.createJournal = func(layout windowsservice.Layout) (setupJournal, error) {
		created, err := createJournal(layout)
		if err != nil {
			return created, err
		}
		var ok bool
		journal, ok = created.(*windowsstate.Store)
		if !ok {
			if created != nil {
				_ = created.Close()
			}
			return nil, errLifecycle
		}
		journalLayout = layout
		return journal, nil
	}

	s.plan = windowsservice.PlanFreshReadSetup
	s.apply = windowsservice.ApplyFreshReadSetup
	enrollStep := s.enroll
	s.enroll = func(ctx context.Context, layout windowsservice.Layout) error {
		progress("Service staged disabled. Verify public trust and enter the invitation in the dedicated hidden console.")
		return enrollStep(ctx, layout)
	}
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
			if journal == nil || layout != journalLayout {
				return errLifecycle
			}
			raw, err := journal.Read("receipt.json")
			if err != nil {
				return err
			}
			defer clear(raw)
			if !bytes.Equal(raw, previous) {
				return errLifecycle
			}
			if err = journal.Write("receipt.json", next); err != nil {
				return err
			}
			return journal.Verify()
		},
		ensureFreshScopes: func(receipt windowsservice.Receipt) error {
			if consent.SchemaVersion == lanclient.WindowsCapabilityConsentVersionV14 {
				return lanclient.WindowsReadAdminScopesV14Absent(receipt.Layout.StateRoot, receipt.ServiceSID)
			}
			if consent.SchemaVersion == lanclient.WindowsCapabilityConsentVersionV13 {
				return lanclient.WindowsReadAdminScopesV13Absent(receipt.Layout.StateRoot, receipt.ServiceSID)
			}
			if consent.SchemaVersion == lanclient.WindowsCapabilityConsentVersionV12 {
				return lanclient.WindowsReadAdminScopesV12Absent(receipt.Layout.StateRoot, receipt.ServiceSID)
			}
			if consent.SchemaVersion == lanclient.WindowsCapabilityConsentVersionV11 {
				return lanclient.WindowsReadAdminScopesV11Absent(receipt.Layout.StateRoot, receipt.ServiceSID)
			}
			if consent.SchemaVersion == lanclient.WindowsCapabilityConsentVersionV10 {
				return lanclient.WindowsReadAdminScopesV10Absent(receipt.Layout.StateRoot, receipt.ServiceSID)
			}
			if consent.SchemaVersion == lanclient.WindowsCapabilityConsentVersionV9 {
				return lanclient.WindowsReadAdminScopesV9Absent(receipt.Layout.StateRoot, receipt.ServiceSID)
			}
			if consent.SchemaVersion == lanclient.WindowsCapabilityConsentVersionV8 {
				return lanclient.WindowsReadAdminScopesV8Absent(receipt.Layout.StateRoot, receipt.ServiceSID)
			}
			if consent.SchemaVersion == lanclient.WindowsCapabilityConsentVersionV7 {
				return lanclient.WindowsReadAdminScopesV7Absent(receipt.Layout.StateRoot, receipt.ServiceSID)
			}
			if consent.SchemaVersion == lanclient.WindowsCapabilityConsentVersionV6 {
				return lanclient.WindowsReadAdminScopesV6Absent(receipt.Layout.StateRoot, receipt.ServiceSID)
			}
			if consent.SchemaVersion == lanclient.WindowsCapabilityConsentVersionV5 {
				return lanclient.WindowsReadAdminScopesAbsent(receipt.Layout.StateRoot, receipt.ServiceSID)
			}
			return lanclient.WindowsCapabilityScopesAbsent(receipt.Layout.StateRoot, receipt.ServiceSID)
		},
		activateIdentity: func(ctx context.Context, receipt windowsservice.Receipt) error {
			progress("Waiting for manager approval of the displayed fingerprint and comparison code. Service remains disabled.")
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
		identity: lanclient.WindowsCapabilityIdentity,
		configure: func(path string, consent lanclient.WindowsCapabilityConsent) (lanclient.WindowsCapabilityConsentResult, error) {
			progress("Manager approved this identity. Applying and verifying only the explicitly selected local read scopes.")
			if consent.SchemaVersion == lanclient.WindowsCapabilityConsentVersionV5 || consent.SchemaVersion == lanclient.WindowsCapabilityConsentVersionV6 || consent.SchemaVersion == lanclient.WindowsCapabilityConsentVersionV7 || consent.SchemaVersion == lanclient.WindowsCapabilityConsentVersionV8 || consent.SchemaVersion == lanclient.WindowsCapabilityConsentVersionV9 || consent.SchemaVersion == lanclient.WindowsCapabilityConsentVersionV10 || consent.SchemaVersion == lanclient.WindowsCapabilityConsentVersionV11 || consent.SchemaVersion == lanclient.WindowsCapabilityConsentVersionV12 || consent.SchemaVersion == lanclient.WindowsCapabilityConsentVersionV13 || consent.SchemaVersion == lanclient.WindowsCapabilityConsentVersionV14 {
				if journal == nil {
					return lanclient.WindowsCapabilityConsentResult{}, errLifecycle
				}
				initial, e := journal.Read("receipt.json")
				if e != nil {
					return lanclient.WindowsCapabilityConsentResult{}, e
				}
				return lanclient.ConfigureWindowsReadAdminCapabilities(path, consent, func() error {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					if journal == nil || journal.Verify() != nil {
						return errLifecycle
					}
					raw, e := journal.Read("receipt.json")
					if e != nil {
						return e
					}
					if !bytes.Equal(raw, initial) {
						return errLifecycle
					}
					binding, e := lanclient.WindowsCapabilityIdentity(path, consent)
					if e != nil {
						return e
					}
					owned, e := readAdminFreshGrantReceipt(raw, consent, binding)
					if e != nil {
						return e
					}
					return s.verifyOwned(ctx, owned)
				})
			}
			return lanclient.ConfigureWindowsCapabilities(path, consent)
		},
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
