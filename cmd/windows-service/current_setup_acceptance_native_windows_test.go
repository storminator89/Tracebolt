//go:build windows && tracebolt_setup_native

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"io"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanclient"
	currentgate "localrmm/internal/windowsacceptance/currentsetupgate"
	"localrmm/internal/windowsacceptance/fixture"
	"localrmm/internal/windowsacceptance/native"
	"localrmm/internal/windowsacceptance/setupgate"
	"localrmm/internal/windowsagentconfig"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

var currentSetupCompiledSource, currentSetupCompiledTree string

func currentSetupArtifactHash(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", setupgate.ErrGuard
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Size() < 1 || s.Size() > 128<<20 {
		return "", setupgate.ErrGuard
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, 128<<20+1))
	if e != nil || n != s.Size() {
		return "", setupgate.ErrGuard
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func currentSetupAuthorization() (currentgate.Binding, error) {
	env := map[string]string{}
	for _, v := range os.Environ() {
		k, value, ok := strings.Cut(v, "=")
		if ok {
			env[k] = value
		}
	}
	deadline, e := strconv.ParseInt(env["TRACEBOLT_SETUP_EXPIRES_UNIX"], 10, 64)
	if e != nil {
		return currentgate.Binding{}, setupgate.ErrGuard
	}
	b := currentgate.Binding{Source: env["TRACEBOLT_SETUP_SOURCE"], CompiledSource: currentSetupCompiledSource, DriverHash: env["TRACEBOLT_SETUP_DRIVER_SHA256"], SetupHash: env["TRACEBOLT_SETUP_SETUP_SHA256"], ServiceHash: env["TRACEBOLT_SETUP_SERVICE_SHA256"], SourceInputsHash: env["TRACEBOLT_SETUP_SOURCE_INPUTS_SHA256"], RunID: env["TRACEBOLT_SETUP_RUN_ID"], Machine: env["TRACEBOLT_SETUP_MACHINE"], Case: env["TRACEBOLT_SETUP_CASE"], SourceTree: env["TRACEBOLT_SETUP_TREE"], CompiledTree: currentSetupCompiledTree, MachineIDHash: env["TRACEBOLT_SETUP_MACHINE_ID_SHA256"], OSBuild: 26100, OSRevision: 1, Deadline: time.Unix(deadline, 0)}
	if currentgate.Authorize(env, b, time.Now()) != nil || currentSetupNativeProfile() != nil {
		return b, setupgate.ErrGuard
	}
	b.Machine, e = os.Hostname()
	if e != nil {
		return b, setupgate.ErrGuard
	}
	exe, e := os.Executable()
	if e != nil {
		return b, setupgate.ErrGuard
	}
	b.DriverHash, e = currentSetupArtifactHash(exe)
	if e != nil {
		return b, e
	}
	b.SetupHash, e = currentSetupArtifactHash(env["TRACEBOLT_SETUP_SETUP_ARTIFACT"])
	if e != nil {
		return b, e
	}
	b.ServiceHash, e = currentSetupArtifactHash(env["TRACEBOLT_SETUP_SERVICE_ARTIFACT"])
	if e != nil {
		return b, e
	}
	b.SourceInputsHash, e = currentSetupArtifactHash(env["TRACEBOLT_SETUP_SOURCE_INPUTS_ARTIFACT"])
	if e != nil {
		return b, e
	}
	b.MachineIDHash, b.OSBuild, b.OSRevision, e = currentSetupPlatform()
	if e != nil {
		return b, e
	}
	return b, currentgate.Authorize(env, b, time.Now())
}
func TestCurrentPackagedSetupGUINative(t *testing.T) {
	b, e := currentSetupAuthorization()
	if e != nil {
		t.Skip("separate exact-source packaged GUI approval unavailable")
		return
	}
	ctx, cancel := context.WithDeadline(context.Background(), b.Deadline.Add(-time.Minute))
	defer cancel()
	r := currentSetupGUIController(ctx, b)
	if r.Validate() != nil {
		t.Fatal("finite packaged GUI evidence rejected")
	}
	raw, e := json.Marshal(r)
	if e != nil {
		t.Fatal("finite packaged GUI report encoding failed")
	}
	fmt.Printf("current-setup-gui-report=%s\n", raw)
	if r.Status != "passed_packaged_gui_subset" {
		t.Fatal("packaged GUI subset incomplete; retained state requires inspection and VM disposal")
	}
}
func currentSetupReceipt(layout windowsservice.Layout) (installReceipt, error) {
	s, e := windowsstate.Open(installerPath(layout), windowsagentconfig.Installer(false))
	if e != nil {
		return installReceipt{}, setupgate.ErrGuard
	}
	defer s.Close()
	raw, e := s.Read("receipt.json")
	if e != nil {
		return installReceipt{}, setupgate.ErrGuard
	}
	defer clear(raw)
	var r installReceipt
	if len(raw) > 64<<10 || json.Unmarshal(raw, &r) != nil || r.Version != 12 || r.ReadSetup == nil || r.Service.Layout != layout {
		return r, setupgate.ErrGuard
	}
	canonical, e := json.Marshal(r)
	defer clear(canonical)
	if e != nil || !reflect.DeepEqual(raw, canonical) || !reflect.DeepEqual(r.ReadSetup.Consent, freshReadAdminSetupConsent(false)) {
		return r, setupgate.ErrGuard
	}
	return r, s.Close()
}
func currentSetupDisabled(ctx context.Context, l windowsservice.Layout) (installReceipt, error) {
	r, e := currentSetupReceipt(l)
	if e != nil || r.Service.Version != 2 || !r.Prepared {
		return r, setupgate.ErrGuard
	}
	s, e := windowsservice.InspectFreshReadSetup(ctx, r.Service)
	if e != nil || s.State != windowsservice.Stopped || s.Configuration.StartType != 4 {
		return r, setupgate.ErrGuard
	}
	return r, nil
}
func currentSetupFreshService(ctx context.Context) error {
	s, e := windowsservice.Inspect(ctx)
	if e != nil || s.Exists {
		return setupgate.ErrGuard
	}
	return nil
}
func currentSetupFreshDirectory(root string) error {
	_, e := os.Lstat(filepath.Join(root, "Tracebolt"))
	if !errors.Is(e, os.ErrNotExist) {
		return setupgate.ErrGuard
	}
	return nil
}
func currentSetupFresh(ctx context.Context, l windowsservice.Layout) bool {
	return currentSetupFreshService(ctx) == nil && currentSetupFreshDirectory(l.ProgramFiles) == nil && currentSetupFreshDirectory(l.ProgramData) == nil
}
func currentSetupFileTree(l windowsservice.Layout) (map[string][32]byte, error) {
	out := map[string][32]byte{}
	var bytes int64
	for _, root := range []string{filepath.Join(l.ProgramFiles, "Tracebolt"), filepath.Join(l.ProgramData, "Tracebolt")} {
		e := filepath.WalkDir(root, func(path string, d os.DirEntry, e error) error {
			if e != nil || d.Type()&os.ModeSymlink != 0 {
				return setupgate.ErrGuard
			}
			info, e := d.Info()
			if e != nil || info.Mode()&os.ModeSymlink != 0 {
				return setupgate.ErrGuard
			}
			if info.IsDir() {
				return nil
			}
			if !info.Mode().IsRegular() || info.Size() > 128<<20 || len(out) >= 256 {
				return setupgate.ErrGuard
			}
			bytes += info.Size()
			if bytes > 256<<20 {
				return setupgate.ErrGuard
			}
			raw, e := os.ReadFile(path)
			if e != nil {
				return setupgate.ErrGuard
			}
			out[path] = sha256.Sum256(raw)
			clear(raw)
			return nil
		})
		if e != nil {
			return nil, e
		}
	}
	if len(out) == 0 {
		return nil, setupgate.ErrGuard
	}
	return out, nil
}
func currentSetupTrust(text string) (string, string, bool) {
	compact := strings.Join(strings.Fields(text), "")
	fp := regexp.MustCompile(`DeviceSPKISHA-256:([0-9a-f]{64})`).FindStringSubmatch(compact)
	comparison := regexp.MustCompile(`Comparison:([0-9a-f]{32})`).FindStringSubmatch(compact)
	if len(fp) != 2 || len(comparison) != 2 {
		return "", "", false
	}
	return fp[1], comparison[1], true
}
func currentSetupStartInstall(ctx context.Context, g *setupGUI, path string, http bool) error {
	if g.choose(ctx, path) != nil || g.currentConsentObserved(ctx, func(string) {}) != nil || setupClick(g.window, 1) != nil {
		return setupgate.ErrGuard
	}
	return nil
}
func currentSetupGUIController(ctx context.Context, b currentgate.Binding) (r currentgate.Report) {
	r = currentgate.NewReport(b)
	// Recheck actual authorization/artifact/VM binding even for a direct test
	// controller call; profile source compatibility alone grants no authority.
	verified, authorizationErr := currentSetupAuthorization()
	if authorizationErr != nil || verified != b || currentSetupNativeProfile() != nil {
		return r
	}
	r.ApprovalValidated = true
	r.Stage = "desktop"
	r.Reason = "desktop_unavailable"
	defer func() {
		if recover() != nil {
			r.Status = "failed"
			r.Reason = "inspection_required"
			r.Startup = "inspection_required"
		}
	}()
	if !setupInteractiveDesktop() {
		return r
	} // No service/session bypass for hosted GUI absence.
	r.Stage = "fresh-environment"
	r.Reason = "operation_failed"
	var l windowsservice.Layout
	// bind_run intentionally discards ambient SystemDrive. Restore only the
	// validated OS-derived drive before this process first resolves KnownFolders.
	e := setupgate.CheckFreshPrerequisites(func(stage string) { r.Stage = stage }, setupgate.FreshPrerequisites{
		Environment: func() error {
			return setupgate.PrepareControllerEnvironment(windows.GetSystemWindowsDirectory, os.Setenv)
		},
		Layout:       func() error { var err error; l, err = windowsservice.ResolveLayout(); return err },
		Service:      func() error { return currentSetupFreshService(ctx) },
		ProgramFiles: func() error { return currentSetupFreshDirectory(l.ProgramFiles) },
		ProgramData:  func() error { return currentSetupFreshDirectory(l.ProgramData) },
	})
	if e != nil {
		return r
	}
	r.NativeActionsAttempted = true
	r.PlatformDisposalRequired = true
	r.Status = "failed"
	r.Stage = "fixture"
	http := false
	f, e := fixture.StartCurrentReadAdmin(ctx)
	if e != nil {
		return r
	}
	defer f.Close()
	secret, e := f.Secret(ctx)
	if e != nil {
		return r
	}
	defer clear(secret)
	public := os.Getenv("TRACEBOLT_SETUP_PUBLIC_INPUT")
	if !filepath.IsAbs(public) {
		return r
	}
	raw, e := json.Marshal(f.Bootstrap())
	if e != nil {
		return r
	}
	file, e := os.OpenFile(public, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return r
	}
	_, writeErr := file.Write(raw)
	clear(raw)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return r
	}
	exe := os.Getenv("TRACEBOLT_SETUP_SETUP_ARTIFACT")
	if currentgate.NormalCase(b.Case) {
		var preflight *setupGUI
		defer func() {
			if preflight != nil {
				preflight.dispose()
			}
		}()
		stage := func(value string) { r.Stage = value }
		if setupgate.CheckPreflight(stage, setupgate.PreflightSteps{
			Launch:       func() error { var err error; preflight, err = setupLaunch(ctx, exe); return err },
			Choose:       func() error { return preflight.chooseObserved(ctx, public, stage) },
			Consent:      func() error { return preflight.currentConsentObserved(ctx, stage) },
			Cancel:       func() error { return setupClick(preflight.window, 2) },
			Exit:         func() error { return preflight.waitExit(ctx, 0) },
			Service:      func() error { return currentSetupFreshService(ctx) },
			ProgramFiles: func() error { return currentSetupFreshDirectory(l.ProgramFiles) },
			ProgramData:  func() error { return currentSetupFreshDirectory(l.ProgramData) },
		}) != nil {
			return r
		}
		r.Checks["preflightCancelUnchanged"] = true
	}
	r.Stage = "bootstrap-launch"
	g, e := setupLaunch(ctx, exe)
	if e != nil {
		return r
	}
	defer g.dispose()
	if g.chooseObserved(ctx, public, func(s string) { r.Stage = s }) != nil {
		return r
	}
	r.Checks["publicBootstrapChosen"] = true
	r.Checks["realGUIExercised"] = true
	r.Stage = "consent"
	if g.currentConsentObserved(ctx, func(string) {}) != nil {
		return r
	}
	r.Checks["acknowledgementsOff"] = true
	r.Checks["renewalConsentOff"] = true
	r.Checks["renewalConsentExplicit"] = true
	r.Stage = "current-optionals"
	if currentSetupOptionalsOff(l) != nil {
		return r
	}
	r.Checks["optionalActionsOff"] = true
	if http {
		r.Checks["httpAcknowledgementOff"] = true
		r.Checks["httpExplicitlyAcknowledged"] = true
	}
	if setupClick(g.window, 1) != nil {
		return r
	}
	r.Stage = "hidden-input"
	var screen string
	if setupAwait(ctx, 40*time.Second, func() bool {
		text, hidden, err := setupConsole(g.pid, secret, nil, false)
		if err != nil {
			return false
		}
		screen = text
		return hidden && strings.Contains(strings.Join(strings.Fields(text), " "), "invitation in this console (hidden):")
	}) != nil {
		return r
	}
	r.Checks["hiddenConsoleExercised"] = true
	r.Stage = "pending-capture"
	// Capture the protected receipt while the worker is blocked at hidden input.
	// Active pending observations must not reopen its exclusive installer store.
	pending, e := captureCurrentSetupPendingObservation(ctx, func() (installReceipt, error) {
		return currentSetupReceipt(l)
	}, windowsservice.InspectFreshReadSetup)
	if e != nil {
		return r
	}
	r.Checks["pendingStoppedDisabled"] = true
	r.Startup = "disabled"
	if b.Case == "cancel-hidden-input" {
		if _, _, e = setupConsole(g.pid, secret, secret[:8], false); e != nil {
			return r
		}
		time.Sleep(250 * time.Millisecond)
		if _, hidden, err := setupConsole(g.pid, secret, nil, false); err != nil || !hidden {
			return r
		}
		r.Checks["noEchoVerified"] = true
		if setupClick(g.window, 2) != nil || g.finished(ctx) != nil {
			return r
		}
		r.Checks["cancelWhileHiddenInput"] = true
	} else {
		fp, comparison, ok := currentSetupTrust(screen)
		if !ok {
			return r
		}
		if _, _, e = setupConsole(g.pid, secret, secret, true); e != nil {
			return r
		}
		r.Stage = "pending-claim"
		if setupAwait(ctx, 15*time.Second, func() bool { return f.Evidence().State == enrollmentstate.ClaimedPending }) != nil {
			return r
		}
		before := f.Snapshot()
		until := time.Now().Add(2 * time.Second)
		for time.Now().Before(until) {
			r.Stage = "pending-service"
			if e = pending.inspectDisabled(ctx); e != nil {
				return r
			}
			r.Stage = "pending-console"
			if _, _, e = setupConsole(g.pid, secret, nil, false); e != nil {
				return r
			}
			r.Stage = "pending-invariant"
			if f.Evidence().Frames != 0 || f.Evidence().State != enrollmentstate.ClaimedPending {
				return r
			}
			time.Sleep(100 * time.Millisecond)
		}
		r.Checks["approvalWithheld"] = true
		r.Checks["noEchoVerified"] = true
		if b.Case == "pending-transport" {
			r.Stage = "transport"
			f.ToggleUnavailable(true)
			if setupAwait(ctx, 20*time.Second, func() bool { return f.Evidence().UnavailableRequests > 0 }) != nil {
				return r
			}
			r.Checks["transportInterrupted"] = true
			after := f.Snapshot()
			if after.Claim != before.Claim || after.DeadlineAt != before.DeadlineAt || after.InvitationID != before.InvitationID || after.State != enrollmentstate.ClaimedPending || f.Evidence().Frames != 0 {
				return r
			}
			r.Checks["sameIdentityAndDeadline"] = true
			r.Stage = "transport-service"
			if e = pending.inspectDisabled(ctx); e != nil {
				return r
			}
			if strings.Contains(strings.ToLower(g.operationText()), "connected") || strings.Contains(g.operationText(), "Service start requested.") {
				return r
			}
			if setupEnabled(setupControl(g.window, 2)) && strings.ReplaceAll(setupText(setupControl(g.window, 2)), "&", "") != "Close" {
				if setupClick(g.window, 2) != nil {
					return r
				}
			}
			if g.finished(ctx) != nil {
				return r
			}
			r.Checks["noFalseConnected"] = true
		} else {
			if f.Approve(fp, comparison) != nil {
				return r
			}
			r.Checks["managerFixtureApproved"] = true
			r.Startup = "inspection_required"
			r.Stage = "completion"
			if g.finished(ctx) != nil || !strings.Contains(g.operationText(), "Service start requested") {
				return r
			}
			receipt, e := currentSetupReceipt(l)
			if e != nil || !completeCurrentReadSetup(receipt) {
				return r
			}
			r.Checks["completedReceipt"] = true
			if setupAwait(ctx, 20*time.Second, func() bool { return native.VerifySetupServiceToken(ctx, receipt.Service) == nil }) != nil {
				return r
			}
			r.Checks["limitedServiceToken"] = true
			r.Startup = "automatic"
			r.Stage = "frames"
			progressInvalid := false
			if setupAwait(ctx, 4*time.Minute, func() bool {
				progress := f.CurrentEvidence()
				if progress.Validate() != nil {
					progressInvalid = true
					return true
				}
				r.FrameProgress = progress
				r.Frames = progress.AcceptedFrames
				return progress.Ready() && progress.AcceptedFrames >= 2
			}) != nil || progressInvalid {
				if progressInvalid {
					r.Stage = "frames-evidence"
				}
				return r
			}
			r.Checks["currentFrames"] = true

		}
	}
	if !currentgate.NormalCase(b.Case) {
		text := g.operationText()
		if !strings.Contains(text, "did not complete") || !strings.Contains(text, "retained") || strings.Contains(text, "Service start requested") {
			return r
		}
	}

	if !setupConsoleGone(g.pid) {
		return r
	}
	r.Checks["consoleReleased"] = true
	expectedExit := uint32(0)
	if !currentgate.NormalCase(b.Case) {
		expectedExit = 1
	}
	if g.exit(ctx, expectedExit) != nil {
		return r
	}
	r.Checks["workerTerminated"] = true
	if !currentgate.NormalCase(b.Case) {
		r.Stage = "pending-retention"
		if e = pending.verifyRetained(ctx, func() (installReceipt, error) { return currentSetupReceipt(l) }); e != nil {
			return r
		}
		r.Checks["partialStateRetained"] = true
	}
	r.Stage = "reopen"
	var partial map[string][32]byte
	if !currentgate.NormalCase(b.Case) {
		partial, e = currentSetupFileTree(l)
		if e != nil {
			return r
		}
	}
	reopened, e := setupLaunch(ctx, exe)
	if e != nil {
		return r
	}
	defer reopened.dispose()
	if currentSetupStartInstall(ctx, reopened, public, http) != nil || reopened.finished(ctx) != nil {
		return r
	}
	text := reopened.operationText()
	if !strings.Contains(text, "did not complete") || strings.Contains(text, "Service start requested") || !setupConsoleGone(reopened.pid) {
		return r
	}
	if reopened.exit(ctx, 1) != nil {
		return r
	}
	r.Checks["reopenBlocked"] = true
	if !currentgate.NormalCase(b.Case) {
		after, e := currentSetupFileTree(l)
		if e != nil || !reflect.DeepEqual(partial, after) {
			return r
		}
		r.Stage = "uninstall"
		u, e := setupLaunch(ctx, exe)
		if e != nil {
			return r
		}
		defer u.dispose()
		if u.uninstall(ctx, true) != nil || u.finished(ctx) != nil || !strings.Contains(u.operationText(), "did not complete") || u.exit(ctx, 1) != nil {
			return r
		}
		after, e = currentSetupFileTree(l)
		if e != nil || !reflect.DeepEqual(partial, after) {
			return r
		}
		if _, e = currentSetupDisabled(ctx, l); e != nil {
			return r
		}
		r.Checks["incompleteUninstallBlocked"] = true
		r.Checks["filesAndStateRetained"] = true
	} else {
		r.Stage = "uninstall-receipt"
		receipt, e := currentSetupReceipt(l)
		if e != nil || !completeCurrentReadSetup(receipt) {
			return r
		}
		r.Stage = "uninstall-owned"
		before, e := windowsservice.InspectOwned(ctx, receipt.Service)
		if e != nil {
			return r
		}
		r.Stage = "uninstall-launch"
		u, e := setupLaunch(ctx, exe)
		if e != nil {
			return r
		}
		defer u.dispose()
		r.Stage = "uninstall-cancel-confirmation"
		if u.uninstall(ctx, false) != nil {
			return r
		}
		r.Stage = "uninstall-cancel-return"
		if setupAwait(ctx, 5*time.Second, func() bool { return setupWindow(u.pid, "#32770") == 0 && setupEnabled(setupControl(u.window, 103)) }) != nil {
			return r
		}
		r.Stage = "uninstall-cancel-invariant"
		after, e := windowsservice.InspectOwned(ctx, receipt.Service)
		again, receiptErr := currentSetupReceipt(l)
		if e != nil || receiptErr != nil || !reflect.DeepEqual(receipt, again) || !reflect.DeepEqual(before, after) {
			return r
		}
		r.Checks["uninstallCancelUnchanged"] = true
		openRetained := func(path string, options windowsstate.Options) (currentRetentionStore, error) {
			store, err := windowsstate.Open(path, options)
			if err != nil {
				return nil, err
			}
			return store, nil
		}
		retentionStage := func(stage string) { r.Stage = stage }
		retained, e := captureCurrentRetainedState(ctx, receipt, l, openRetained, windowsservice.InspectOwned, func(path string) error {
			// Load validates material with the live SID, without trying to take
			// the foreground sender's lifetime-exclusive state lock.
			_, err := lanclient.Load(path)
			return err
		}, retentionStage)
		if e != nil {
			return r
		}
		// This read-only handle deliberately makes DeleteService's pending state
		// observable. The GUI must wait; releasing it permits SCM absence to occur.
		r.Stage = "uninstall-hold-scm"
		scm, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
		if e != nil {
			return r
		}
		r.Stage = "uninstall-hold-service"
		hold, e := windows.OpenService(scm, setupUTF(windowsservice.Name), windows.SERVICE_QUERY_STATUS)
		windows.CloseServiceHandle(scm)
		if e != nil {
			return r
		}
		defer func() {
			if hold != 0 {
				windows.CloseServiceHandle(hold)
			}
		}()
		r.Stage = "uninstall-confirmation"
		if u.uninstall(ctx, true) != nil {
			return r
		}
		r.Startup = "inspection_required"
		r.Stage = "uninstall-pending-text"
		if setupAwait(ctx, 25*time.Second, func() bool {
			text := u.operationText()
			observation := setupgate.ObserveUninstallPending(strings.Contains(text, "Service deletion is pending. Waiting for SCM to confirm absence."), func() (setupgate.UninstallHeldStatus, bool) {
				var status windows.SERVICE_STATUS
				err := windows.QueryServiceStatus(hold, &status)
				outcome := setupgate.UninstallStatusFailed
				switch err {
				case nil:
					outcome = setupgate.UninstallStatusObserved
				case windows.ERROR_SERVICE_MARKED_FOR_DELETE:
					outcome = setupgate.UninstallStatusDeletePending
				case windows.ERROR_INVALID_HANDLE:
					outcome = setupgate.UninstallStatusInvalidHandle
				case windows.ERROR_ACCESS_DENIED:
					outcome = setupgate.UninstallStatusAccessDenied
				}
				return outcome, status.CurrentState == windows.SERVICE_STOPPED
			}, func() bool {
				return strings.ReplaceAll(setupText(setupControl(u.window, 2)), "&", "") == "Close"
			})
			r.Stage = observation.Stage(text)
			r.Reason = "operation_failed"
			if stage, reason, ok := setupgate.ParseRemovalFailure(text); ok {
				r.Stage = stage
				r.Reason = reason
			}
			return observation.Ready()
		}) != nil {
			return r
		}
		// Keep the observed exact stopped SCM handle alive a little longer:
		// successful removal cannot be announced while deletion is held pending.
		r.Stage = "uninstall-held-close"
		time.Sleep(500 * time.Millisecond)
		if strings.ReplaceAll(setupText(setupControl(u.window, 2)), "&", "") == "Close" {
			r.Stage = setupgate.UninstallHeldCloseStage(u.operationText())
			return r
		}

		r.Checks["deletePendingObserved"] = true
		// The exact held handle was successfully queried as Stopped, and GUI
		// deletion is pending. Only now may observation acquire sender/grant
		// locks. Use the fixture's actual accepted sequence, never frame count.
		if retained.captureStopped(ctx, f.Evidence().LastSequence, openRetained, retentionStage) != nil {
			return r
		}
		r.Stage = "uninstall-release"
		windows.CloseServiceHandle(hold)
		hold = 0
		r.Stage = "uninstall-finish"
		if u.finished(ctx) != nil {
			return r
		}
		r.Stage = "uninstall-finish-message"
		if !strings.Contains(u.operationText(), "Service removal confirmed") {
			return r
		}
		r.Stage = "uninstall-exit"
		if u.exit(ctx, 0) != nil {
			return r
		}
		r.Stage = "uninstall-absence-inspect"
		if setupAwait(ctx, 5*time.Second, func() bool {
			s, e := windowsservice.Inspect(ctx)
			r.Stage = "uninstall-absence-inspect"
			if e == nil && s.Exists {
				r.Stage = "uninstall-absence-present"
			}
			return e == nil && !s.Exists
		}) != nil {
			return r
		}
		r.Startup = "absent"
		r.Checks["serviceAbsent"] = true
		r.Stage = "verify-retention"
		// An absent service no longer has an account name to resolve. Retained
		// state is verified with the original protected receipt SID instead,
		// preserving all Store manifest, ACL, pinned-path and rollback checks.
		if retained.verifyAbsent(ctx, f.Evidence().LastSequence, openRetained, retentionStage) != nil {
			return r
		}
		r.ReceiptProof = retained.proof
		r.Checks["receiptAndGrantsVerified"] = true
		r.Stage = "verify-retention-binary"
		hash, e := currentSetupArtifactHash(l.Executable)
		if e != nil || hash != b.ServiceHash {
			return r
		}
		r.Stage = "verify-retention-tree"
		if _, e = currentSetupFileTree(l); e != nil {
			return r
		}
		r.Checks["filesAndStateRetained"] = true
	}
	if ctx.Err() != nil {
		return r
	}
	if currentSetupOptionalsOff(l) != nil {
		r.Stage = "current-optionals"
		return r
	}
	if f.Close() != nil {
		return r
	}
	r.Stage = "completed"
	r.Reason = "none"
	r.Status = "passed_packaged_gui_subset"
	return r
}

func currentSetupNativeProfile() error {
	c := freshReadAdminSetupConsent(false)
	if c.SchemaVersion != lanclient.WindowsCapabilityConsentVersionV14 || len(c.Scopes) != 21 || c.Validate() != nil {
		return setupgate.ErrGuard
	}
	return nil
}
func currentSetupPlatform() (string, uint32, uint32, error) {
	v := windows.RtlGetVersion()
	if v == nil || v.MajorVersion != 10 || v.MinorVersion != 0 || v.BuildNumber != 26100 || v.ProductType != 3 {
		return "", 0, 0, setupgate.ErrGuard
	}
	k, e := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if e != nil {
		return "", 0, 0, setupgate.ErrGuard
	}
	id, _, e := k.GetStringValue("MachineGuid")
	closeErr := k.Close()
	if e != nil || closeErr != nil || !regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`).MatchString(id) {
		return "", 0, 0, setupgate.ErrGuard
	}
	k, e = registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if e != nil {
		return "", 0, 0, setupgate.ErrGuard
	}
	ubr, _, e := k.GetIntegerValue("UBR")
	closeErr = k.Close()
	if e != nil || closeErr != nil || ubr == 0 || ubr > 1<<32-1 {
		return "", 0, 0, setupgate.ErrGuard
	}
	hash := sha256.Sum256([]byte("Tracebolt current hosted machine v1\n" + strings.ToLower(id)))
	return hex.EncodeToString(hash[:]), v.BuildNumber, uint32(ubr), nil
}
func currentSetupOptionalsOff(l windowsservice.Layout) error {
	paths := []string{filepath.Join(l.ProgramData, "Tracebolt-action-broker"), filepath.Join(l.ProgramData, "Tracebolt-action-broker-setup"), filepath.Join(filepath.Dir(l.StateRoot), "windows-update-executor"), filepath.Join(l.ProgramFiles, "Tracebolt", "tracebolt-windows-action-broker.exe"), filepath.Join(l.ProgramFiles, "Tracebolt", "tracebolt-windows-update-executor.exe")}
	for _, suffix := range []string{"event-content", "updates", "update-job-relay", "action-relay", "user-software"} {
		paths = append(paths, l.StateRoot+"-"+suffix)
	}
	for _, path := range paths {
		_, e := os.Lstat(path)
		if !errors.Is(e, os.ErrNotExist) {
			return setupgate.ErrGuard
		}
	}
	return nil
}
func (g *setupGUI) currentConsentObserved(ctx context.Context, stage func(string)) error {
	// Exact current profile, separate unchecked renewal consent, and Back reset.
	stage("current-consent")
	for pass := 0; pass < 2; pass++ {
		if setupClick(g.window, 1) != nil || setupAwait(ctx, 5*time.Second, func() bool { return setupControl(g.window, 111) != 0 }) != nil {
			return setupgate.ErrGuard
		}
		if setupControl(g.window, 108) != 0 || setupEnabled(setupControl(g.window, 1)) || !strings.Contains(setupText(setupControl(g.window, 204)), "21 read scopes") {
			return setupgate.ErrGuard
		}
		for _, id := range []int{104, 105, 106, 107, 111} {
			v, e := setupSend(setupControl(g.window, id), 0x00f0, 0, 0)
			if e != nil || v != 0 {
				return setupgate.ErrGuard
			}
		}
		for _, id := range []int{104, 105, 106, 107} {
			if setupClick(g.window, id) != nil || setupAwait(ctx, 2*time.Second, func() bool { v, e := setupSend(setupControl(g.window, id), 0x00f0, 0, 0); return e == nil && v == 1 }) != nil {
				return setupgate.ErrGuard
			}
		}
		if setupEnabled(setupControl(g.window, 1)) || setupClick(g.window, 111) != nil || setupAwait(ctx, 3*time.Second, func() bool {
			v, e := setupSend(setupControl(g.window, 111), 0x00f0, 0, 0)
			return e == nil && v == 1 && setupEnabled(setupControl(g.window, 1))
		}) != nil {
			return setupgate.ErrGuard
		}
		if pass == 0 {
			if setupClick(g.window, 101) != nil || setupAwait(ctx, 3*time.Second, func() bool { return setupControl(g.window, 203) != 0 && setupEnabled(setupControl(g.window, 1)) }) != nil {
				return setupgate.ErrGuard
			}
		}
	}
	return nil
}
