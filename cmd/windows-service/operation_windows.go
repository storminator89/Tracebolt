//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsagentconfig"
	"localrmm/internal/windowsconsole"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
)

func installerPath(layout windowsservice.Layout) string { return layout.StateRoot + "-installer" }
func nativeOperation(ctx context.Context, r request, out, stderr io.Writer) (result any, err error) {
	defer func() {
		if err == nil {
			return
		}
		phase := windowsservice.PhaseLifecycle
		switch r.mode {
		case "plan", "inspect":
			phase = windowsservice.PhaseRuntimeInstallation
		case "install":
			phase = windowsservice.PhaseSetup
		case "enroll":
			phase = windowsservice.PhaseEnrollment
		case "run-service":
			phase = windowsservice.PhaseRuntimeDispatch
		}
		err = marked(phase, windowsservice.ReasonOperationFailed, err)
	}()
	switch r.mode {
	case "plan":
		return windowsservice.Plan(ctx)
	case "inspect":
		return windowsservice.Inspect(ctx)
	case "run-service":
		return nil, windowsservice.Run(ctx, runService)
	case "install":
		return install(ctx, r.bootstrap, r.collectionProfile, r.insecureHTTP, out, stderr)
	}
	receipt, err := loadReceipt()
	if err != nil {
		return nil, err
	}
	switch r.mode {
	case "events-preview", "events-enable", "events-disable":
		snapshot, err := windowsservice.InspectOwned(ctx, receipt.Service)
		if err != nil || snapshot.State != windowsservice.Stopped {
			return nil, errLifecycle
		}
		mode := map[string]string{"events-preview": "preview", "events-enable": "enable", "events-disable": "disable"}[r.mode]
		return lanclient.ConfigureWindowsEventMetadata(filepath.Join(receipt.Service.Layout.EnrollmentRoot, "agent.json"), mode, mode == "enable", r.insecureHTTP)
	case "volumes-preview", "volumes-enable", "volumes-disable":
		snapshot, err := windowsservice.InspectOwned(ctx, receipt.Service)
		if err != nil || snapshot.State != windowsservice.Stopped {
			return nil, errLifecycle
		}
		mode := map[string]string{"volumes-preview": "preview", "volumes-enable": "enable", "volumes-disable": "disable"}[r.mode]
		return lanclient.ConfigureWindowsVolumes(filepath.Join(receipt.Service.Layout.EnrollmentRoot, "agent.json"), mode, mode == "enable", r.insecureHTTP)
	case "enroll":
		snapshot, err := windowsservice.InspectOwned(ctx, receipt.Service)
		if err != nil || snapshot.State != windowsservice.Stopped {
			return nil, marked(windowsservice.PhaseRuntimeInstallation, windowsservice.ReasonInvalidConfiguration, err)
		}
		if err = enroll(ctx, receipt.Service.Layout, r.collectionProfile, r.insecureHTTP, out, stderr); err != nil {
			return nil, err
		}
		return struct {
			Status string `json:"status"`
		}{"claim committed; start remains an explicit local operation"}, nil
	case "start":
		return windowsservice.ApplyStart(ctx, receipt.Service)
	case "stop":
		return windowsservice.ApplyStop(ctx, receipt.Service)
	case "uninstall":
		return windowsservice.ApplyUninstall(ctx, receipt.Service)
	}
	return nil, errLifecycle
}
func loadReceipt() (installReceipt, error) {
	layout, err := windowsservice.ResolveLayout()
	if err != nil {
		return installReceipt{}, marked(windowsservice.PhaseReceipt, windowsservice.ReasonStateRejected, errLifecycle)
	}
	store, err := windowsstate.Open(installerPath(layout), windowsagentconfig.Installer(false))
	if err != nil {
		return installReceipt{}, marked(windowsservice.PhaseReceipt, windowsservice.ReasonStateRejected, errLifecycle)
	}
	defer store.Close()
	raw, err := store.Read("receipt.json")
	if err != nil {
		return installReceipt{}, marked(windowsservice.PhaseReceipt, windowsservice.ReasonStateRejected, errLifecycle)
	}
	defer clear(raw)
	var r installReceipt
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&r) != nil || r.Version != 1 || !r.Prepared || !r.Service.Complete || r.Service.Layout != layout {
		return installReceipt{}, marked(windowsservice.PhaseReceipt, windowsservice.ReasonStateRejected, errLifecycle)
	}
	// Canonical bytes reject duplicate/trailing fields and preserve the exact
	// locally persisted ownership record. SCM revalidation occurs before apply.
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(canonical, raw) {
		return installReceipt{}, marked(windowsservice.PhaseReceipt, windowsservice.ReasonStateRejected, errLifecycle)
	}
	return r, nil
}
func install(ctx context.Context, bootstrapPath, selectedProfile string, insecure bool, out, stderr io.Writer) (any, error) {
	return setup(ctx, bootstrapPath, setupSteps{
		plan:          windowsservice.Plan,
		readBootstrap: func(path string) ([]byte, error) { return windowsstate.ReadProtectedInstaller(path, false, 64<<10) },
		validateBootstrap: func(raw []byte) error {
			b, err := enrollmentclient.ParseBootstrap(raw)
			if err != nil || validateWindowsBootstrapConsent(b, selectedProfile, insecure) != nil {
				return errLifecycle
			}
			return nil
		},
		createJournal: func(layout windowsservice.Layout) (setupJournal, error) {
			return windowsstate.Open(installerPath(layout), windowsagentconfig.Installer(true))
		},
		apply:   windowsservice.ApplyInstall,
		prepare: prepareRuntime,
		verifyOwned: func(ctx context.Context, r windowsservice.Receipt) error {
			snapshot, err := windowsservice.InspectOwned(ctx, r)
			if err != nil {
				return err
			}
			if snapshot.State != windowsservice.Stopped {
				return windowsservice.ErrNotStopped
			}
			return nil
		},
		enroll: func(ctx context.Context, layout windowsservice.Layout) error {
			return enroll(ctx, layout, selectedProfile, insecure, out, stderr)
		},
		start: windowsservice.ApplyStart,
	})
}
func prepareRuntime(layout windowsservice.Layout, receipt windowsservice.Receipt, raw []byte) error {
	store, err := windowsstate.Open(layout.StateRoot, windowsagentconfig.RuntimeRoot(receipt.ServiceSID, true))
	if err != nil {
		return errLifecycle
	}
	defer store.Close()
	if store.Write("bootstrap.json", raw) != nil {
		return errLifecycle
	}
	child, err := store.CreateDirectoryStore("enrollment", windowsagentconfig.Enrollment(receipt.ServiceSID, true))
	if err != nil {
		return errLifecycle
	}
	if child.Close() != nil || store.Close() != nil {
		return errLifecycle
	}
	return nil
}
func bootstrap(layout windowsservice.Layout) (enrollmentclient.Bootstrap, error) {
	sid, err := windowsservice.LookupServiceSID()
	if err != nil {
		return enrollmentclient.Bootstrap{}, marked(windowsservice.PhaseBootstrap, windowsservice.ReasonStateUnavailable, errLifecycle)
	}
	store, err := windowsstate.Open(layout.StateRoot, windowsagentconfig.RuntimeRoot(sid, false))
	if err != nil {
		return enrollmentclient.Bootstrap{}, marked(windowsservice.PhaseBootstrap, windowsservice.ReasonStateUnavailable, errLifecycle)
	}
	defer store.Close()
	raw, err := store.Read("bootstrap.json")
	if err != nil {
		return enrollmentclient.Bootstrap{}, marked(windowsservice.PhaseBootstrap, windowsservice.ReasonStateUnavailable, errLifecycle)
	}
	defer clear(raw)
	b, err := enrollmentclient.ParseBootstrap(raw)
	if err != nil || validateWindowsBootstrapConsent(b, b.CollectionProfile, b.Profile == "http-test") != nil {
		return enrollmentclient.Bootstrap{}, marked(windowsservice.PhaseBootstrap, windowsservice.ReasonStateUnavailable, errLifecycle)
	}
	return b, nil
}
func enroll(ctx context.Context, layout windowsservice.Layout, selectedProfile string, insecure bool, out, stderr io.Writer) error {
	b, err := bootstrap(layout)
	if err != nil {
		return err
	}
	if validateWindowsBootstrapConsent(b, selectedProfile, insecure) != nil {
		return marked(windowsservice.PhaseBootstrap, windowsservice.ReasonInvalidConfiguration, errLifecycle)
	}
	result, err := enrollmentclient.Run(ctx, b, enrollmentclient.Options{StateDirectory: layout.EnrollmentRoot, ClaimOnly: true, InsecureHTTPAcknowledged: insecure, WindowsInventoryAcknowledged: selectedProfile == enrollmentcrypto.CollectionProfileWindowsInventory, Display: func(d enrollmentclient.TrustDisplay) error {
		if _, err := fmt.Fprintf(out, "Manager: %s\nEnrollment: %s\nAgent ingress: %s\nScope: %s\n", d.ManagerInstanceID, d.EnrollmentOrigin, d.AgentOrigin, d.CollectionProfile); err != nil {
			return err
		}
		if d.HTTPTest {
			if _, err := fmt.Fprintln(out, enrollmentclient.WindowsInventoryHTTPPrivacy); err != nil {
				return err
			}
		}
		if d.CollectionPrivacy != "" {
			if _, err := fmt.Fprintln(out, d.CollectionPrivacy); err != nil {
				return err
			}
		}
		for _, fp := range d.ServerCAFingerprints {
			if _, err := fmt.Fprintln(out, "Server CA SHA-256: "+fp); err != nil {
				return err
			}
		}
		_, err := fmt.Fprintf(out, "Issuer root SHA-256: %s\nIssuer SHA-256: %s\nDevice SPKI SHA-256: %s\nComparison: %s\nCompare the complete public fingerprint and comparison value in the manager before approving.\n", d.IssuerRootFingerprint, d.IssuerFingerprint, d.KeyFingerprint, d.ComparisonCode)
		return err
	}, Secret: func(ctx context.Context) ([]byte, error) {
		return windowsconsole.ReadInvitation(ctx, func() error {
			_, err := fmt.Fprint(stderr, "Verify public trust and enter the invitation in this console (hidden): ")
			return err
		})
	}})
	if err != nil {
		reason := windowsservice.ReasonEnrollmentFailed
		switch {
		case errors.Is(err, enrollmentclient.ErrInput):
			reason = windowsservice.ReasonInputRejected
		case errors.Is(err, enrollmentclient.ErrServiceDeadline):
			reason = windowsservice.ReasonApprovalExpired
		case errors.Is(err, enrollmentclient.ErrTerminal):
			reason = windowsservice.ReasonEnrollmentTerminal
		}
		return marked(windowsservice.PhaseEnrollment, reason, err)
	}
	if !result.Pending || result.ServerAuthenticated != (b.Profile == "tls") {
		return marked(windowsservice.PhaseEnrollment, windowsservice.ReasonInvalidConfiguration, nil)
	}
	return nil
}
func runService(ctx context.Context, ready func()) error {
	if err := windowsservice.ValidateRuntimeIdentity(); err != nil {
		return marked(windowsservice.PhaseRuntimeIdentity, windowsservice.ReasonIdentityRejected, err)
	}
	layout, err := windowsservice.ResolveLayout()
	if err != nil {
		return marked(windowsservice.PhaseRuntimeInstallation, windowsservice.ReasonInvalidConfiguration, err)
	}
	b, err := bootstrap(layout)
	if err != nil {
		return marked(windowsservice.PhaseBootstrap, windowsservice.ReasonInvalidConfiguration, err)
	}
	return runPendingWindowsProfile(ctx, filepath.Join(layout.EnrollmentRoot, "agent.json"), b.Profile == "http-test", ready, pendingHooks{
		identity: windowsservice.ValidateRuntimeIdentity,
		inspect: func() (enrollmentclient.ServiceState, error) {
			return enrollmentclient.InspectService(b, layout.EnrollmentRoot, b.Profile == "http-test")
		},
		resume: func(ctx context.Context) error {
			_, err := enrollmentclient.ResumeService(ctx, b, layout.EnrollmentRoot, b.Profile == "http-test", nil)
			return err
		},
		stopDeadline: func() error {
			return enrollmentclient.StopServiceAtDeadline(b, layout.EnrollmentRoot, b.Profile == "http-test")
		},
		markReady: func() (enrollmentclient.ServiceState, error) {
			return enrollmentclient.MarkServiceReady(b, layout.EnrollmentRoot, b.Profile == "http-test")
		},
		sender: func(ctx context.Context, path string) error {
			material, err := lanclient.Load(path)
			if err != nil {
				return marked(windowsservice.PhaseHandoff, windowsservice.ReasonHandoffInvalid, err)
			}
			_, err = lanclient.RunForeground(ctx, material, time.Minute, nil)
			return err
		},
		wait: func(ctx context.Context) error {
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		},
	})
}
