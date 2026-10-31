package main

import (
	"bytes"
	"context"
	"io"

	"localrmm/internal/enrollmentclient"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowspackage"
	"localrmm/internal/windowssetupui"
)

// setupFrontendBackend supplies only existing in-process operations. Production
// wiring stays in the Windows Setup entry; no CLI, IPC, secret handoff, dynamic
// loader or alternative native implementation is introduced here.
type setupFrontendBackend struct {
	preflight     func(context.Context) error
	compatibility func(context.Context, []byte, bool) error
	console       func(context.CancelFunc) (io.Writer, func() error, error)
	provision     func(context.Context, []byte, windowspackage.Manifest, []byte) (string, func() error, error)
	install       func(context.Context, string, lanclient.WindowsCapabilityConsent, io.Writer, func(string), bool) error
	uninstall     func(context.Context, func(string)) error
}

// setupFrontend assembles the existing public presentation and guarded hooks for
// an in-process frontend. Construction performs no host/network operation and
// grants no consent. The default caller remains windowssetupui.Run. A future
// Rust frontend still needs independently reviewed consent, lifetime/thread and
// native-link integration; this factory is not a standalone apply authority.
func setupFrontend(payload []byte, manifest windowspackage.Manifest, publicBootstrap []byte, backend setupFrontendBackend) (windowssetupui.Config, windowssetupui.Hooks, error) {
	if backend.preflight == nil || backend.compatibility == nil || backend.console == nil || backend.provision == nil || backend.install == nil || backend.uninstall == nil {
		return windowssetupui.Config{}, windowssetupui.Hooks{}, errLifecycle
	}
	if len(payload) < 512 || len(payload) > windowspackage.MaxPayloadBytes || publicBootstrap != nil && (len(publicBootstrap) == 0 || len(publicBootstrap) > windowspackage.MaxBootstrapBytes) {
		return windowssetupui.Config{}, windowssetupui.Hooks{}, errLifecycle
	}
	// The frontend/caller cannot change the package used by a later hook through
	// its input buffer. Provision retains its existing native snapshot/readback.
	payload = bytes.Clone(payload)
	publicBootstrap = bytes.Clone(publicBootstrap)
	if manifest.Validate(payload) != nil {
		return windowssetupui.Config{}, windowssetupui.Hooks{}, errLifecycle
	}
	if publicBootstrap != nil {
		if _, err := setupWizardBootstrap(publicBootstrap); err != nil {
			return windowssetupui.Config{}, windowssetupui.Hooks{}, errLifecycle
		}
	}
	config := windowssetupui.Config{InitialPublicBootstrap: publicBootstrap, AutomaticRenewalDisclosure: enrollmentclient.AutomaticRenewalPrivacy, Version: manifest.Version, SourceCommit: manifest.SourceCommit, PayloadSHA256: manifest.SHA256, Architecture: manifest.Architecture, Disclosure: setupWizardDisclosure(), HTTPDisclosure: setupWizardHTTPDisclosure(), ReadAdminDisclosure: setupWizardReadAdminDisclosure(false), ReadAdminHTTPDisclosure: setupWizardReadAdminDisclosure(true), ReadAdminSummary: setupWizardReadAdminSummary(), ReadAdminHTTPSummary: setupWizardReadAdminHTTPRiskSummary}

	hooks := windowssetupui.Hooks{Preview: setupWizardPreview}
	installProfile := func(ctx context.Context, raw []byte, insecureAcknowledged bool, readAdmin bool, renewalAcknowledged bool, progress func(string)) error {
		if ctx == nil || progress == nil {
			return errLifecycle
		}
		// One immutable public-bootstrap snapshot is used for validation,
		// compatibility, provisioning and final exact-consent reconstruction.
		if len(raw) <= windowspackage.MaxBootstrapBytes {
			raw = bytes.Clone(raw)
		}
		// Oversized input is rejected by the existing bounded parser in validate,
		// without first allocating an unbounded frontend-owned snapshot.
		acknowledgedBootstrap := setupWizardAcknowledgedBootstrap
		if readAdmin {
			acknowledgedBootstrap = setupWizardReadAdminAcknowledgedBootstrap
		}
		ctx, stop := context.WithCancel(ctx)
		defer stop()
		var console io.Writer
		steps := setupWizardInstallSteps{
			validate: func(b []byte) error {
				if manifest.Validate(payload) != nil {
					return errLifecycle
				}
				_, _, err := acknowledgedBootstrap(b, insecureAcknowledged, renewalAcknowledged)
				if err != nil {
					return errLifecycle
				}
				return nil
			},
			preflight: backend.preflight,
			compatibility: func(ctx context.Context, raw []byte) error {
				return backend.compatibility(ctx, raw, readAdmin)
			},
			console: func() (func() error, error) {
				w, close, err := backend.console(stop)
				console = w
				return close, err
			},
			provision: func(ctx context.Context, raw []byte) (string, func() error, error) {
				return backend.provision(ctx, payload, manifest, raw)
			},
			install: func(ctx context.Context, path string) error {
				_, consent, err := acknowledgedBootstrap(raw, insecureAcknowledged, renewalAcknowledged)
				if err != nil {
					return err
				}
				return backend.install(ctx, path, consent, console, progress, renewalAcknowledged)
			},
		}
		err := setupWizardInstall(ctx, raw, steps, progress)
		if err != nil {
			setupWizardFailure(err, progress)
		}
		return err
	}
	hooks.Install = func(ctx context.Context, raw []byte, insecure bool, progress func(string)) error {
		return installProfile(ctx, raw, insecure, false, false, progress)
	}
	hooks.InstallReadAdmin = func(ctx context.Context, raw []byte, insecure bool, progress func(string)) error {
		return installProfile(ctx, raw, insecure, true, false, progress)
	}
	hooks.InstallRenewable = func(ctx context.Context, raw []byte, renewal bool, progress func(string)) error {
		return installProfile(ctx, raw, false, false, renewal, progress)
	}
	hooks.InstallReadAdminRenewable = func(ctx context.Context, raw []byte, renewal bool, progress func(string)) error {
		return installProfile(ctx, raw, false, true, renewal, progress)
	}
	hooks.Uninstall = func(ctx context.Context, progress func(string)) error {
		if ctx == nil || progress == nil {
			return errLifecycle
		}
		err := backend.uninstall(ctx, progress)
		if err != nil {
			progress(setupRemovalFailureText(err))
		}
		return err
	}
	return config, hooks, nil
}
