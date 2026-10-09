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
	"io"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsacceptance/fixture"
	"localrmm/internal/windowsacceptance/native"
	"localrmm/internal/windowsacceptance/profile"
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

var setupCompiledSource string

func setupArtifactHash(path string) (string, error) {
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
func setupAuthorization() (setupgate.Binding, error) {
	env := map[string]string{}
	for _, v := range os.Environ() {
		k, value, ok := strings.Cut(v, "=")
		if ok {
			env[k] = value
		}
	}
	deadline, e := strconv.ParseInt(env["TRACEBOLT_SETUP_EXPIRES_UNIX"], 10, 64)
	if e != nil {
		return setupgate.Binding{}, setupgate.ErrGuard
	}
	b := setupgate.Binding{Source: env["TRACEBOLT_SETUP_SOURCE"], CompiledSource: setupCompiledSource, DriverHash: env["TRACEBOLT_SETUP_DRIVER_SHA256"], SetupHash: env["TRACEBOLT_SETUP_SETUP_SHA256"], ServiceHash: env["TRACEBOLT_SETUP_SERVICE_SHA256"], SourceInputsHash: env["TRACEBOLT_SETUP_SOURCE_INPUTS_SHA256"], RunID: env["TRACEBOLT_SETUP_RUN_ID"], Machine: env["TRACEBOLT_SETUP_MACHINE"], Case: env["TRACEBOLT_SETUP_CASE"], Deadline: time.Unix(deadline, 0)}
	if setupgate.Authorize(env, b, time.Now()) != nil {
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
	b.DriverHash, e = setupArtifactHash(exe)
	if e != nil {
		return b, e
	}
	b.SetupHash, e = setupArtifactHash(env["TRACEBOLT_SETUP_SETUP_ARTIFACT"])
	if e != nil {
		return b, e
	}
	b.ServiceHash, e = setupArtifactHash(env["TRACEBOLT_SETUP_SERVICE_ARTIFACT"])
	if e != nil {
		return b, e
	}
	b.SourceInputsHash, e = setupArtifactHash(env["TRACEBOLT_SETUP_SOURCE_INPUTS_ARTIFACT"])
	if e != nil {
		return b, e
	}
	return b, setupgate.Authorize(env, b, time.Now())
}
func TestPackagedSetupGUINative(t *testing.T) {
	b, e := setupAuthorization()
	if e != nil {
		t.Skip("separate exact-source packaged GUI approval unavailable")
		return
	}
	ctx, cancel := context.WithDeadline(context.Background(), b.Deadline.Add(-time.Minute))
	defer cancel()
	r := setupGUIController(ctx, b)
	if r.Validate() != nil {
		t.Fatal("finite packaged GUI evidence rejected")
	}
	raw, e := json.Marshal(r)
	if e != nil {
		t.Fatal("finite packaged GUI report encoding failed")
	}
	fmt.Printf("setup-gui-report=%s\n", raw)
	if r.Status != "passed_packaged_gui_subset" {
		t.Fatal("packaged GUI subset incomplete; retained state requires inspection and VM disposal")
	}
}
func setupReceipt(layout windowsservice.Layout) (installReceipt, error) {
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
	if len(raw) > 64<<10 || json.Unmarshal(raw, &r) != nil || r.Version != 2 || r.ReadSetup == nil || r.Service.Layout != layout {
		return r, setupgate.ErrGuard
	}
	canonical, e := json.Marshal(r)
	defer clear(canonical)
	if e != nil || !reflect.DeepEqual(raw, canonical) || validateReadSetupConsent(r.ReadSetup.Consent) != nil {
		return r, setupgate.ErrGuard
	}
	return r, s.Close()
}
func setupDisabled(ctx context.Context, l windowsservice.Layout) (installReceipt, error) {
	r, e := setupReceipt(l)
	if e != nil || r.Service.Version != 2 || !r.Prepared {
		return r, setupgate.ErrGuard
	}
	s, e := windowsservice.InspectFreshReadSetup(ctx, r.Service)
	if e != nil || s.State != windowsservice.Stopped || s.Configuration.StartType != 4 {
		return r, setupgate.ErrGuard
	}
	return r, nil
}
func setupFresh(ctx context.Context, l windowsservice.Layout) bool {
	s, e := windowsservice.Inspect(ctx)
	if e != nil || s.Exists {
		return false
	}
	for _, p := range []string{filepath.Join(l.ProgramFiles, "Tracebolt"), filepath.Join(l.ProgramData, "Tracebolt")} {
		_, e := os.Lstat(p)
		if !errors.Is(e, os.ErrNotExist) {
			return false
		}
	}
	return true
}
func setupFileTree(l windowsservice.Layout) (map[string][32]byte, error) {
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
func setupTrust(text string) (string, string, bool) {
	compact := strings.Join(strings.Fields(text), "")
	fp := regexp.MustCompile(`DeviceSPKISHA-256:([0-9a-f]{64})`).FindStringSubmatch(compact)
	comparison := regexp.MustCompile(`Comparison:([0-9a-f]{32})`).FindStringSubmatch(compact)
	if len(fp) != 2 || len(comparison) != 2 {
		return "", "", false
	}
	return fp[1], comparison[1], true
}
func setupStartInstall(ctx context.Context, g *setupGUI, path string, http bool) error {
	if g.choose(ctx, path) != nil || g.consent(ctx, http) != nil || setupClick(g.window, 1) != nil {
		return setupgate.ErrGuard
	}
	return nil
}
func setupGUIController(ctx context.Context, b setupgate.Binding) (r setupgate.Report) {
	r = setupgate.NewReport(b)
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
	r.Stage = "fresh"
	r.Reason = "operation_failed"
	l, e := windowsservice.ResolveLayout()
	if e != nil || !setupFresh(ctx, l) {
		return r
	}
	r.NativeActionsAttempted = true
	r.PlatformDisposalRequired = true
	r.Status = "failed"
	r.Stage = "fixture"
	selection := profile.Selection{CollectionProfile: "windows-inventory-v1", Transport: "tls"}
	http := b.Case == "http-install-uninstall"
	if http {
		selection.Transport = "http-test"
	}
	f, e := fixture.StartExpanded(ctx, selection)
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
	if setupgate.NormalCase(b.Case) {
		r.Stage = "preflight-cancel"
		g, e := setupLaunch(ctx, exe)
		if e != nil {
			return r
		}
		defer g.dispose()
		if g.choose(ctx, public) != nil || g.consent(ctx, http) != nil || g.exit(ctx, 0) != nil || !setupFresh(ctx, l) {
			return r
		}
		r.Checks["preflightCancelUnchanged"] = true
	}
	r.Stage = "bootstrap"
	g, e := setupLaunch(ctx, exe)
	if e != nil {
		return r
	}
	defer g.dispose()
	if g.choose(ctx, public) != nil {
		return r
	}
	r.Checks["publicBootstrapChosen"] = true
	r.Checks["realGUIExercised"] = true
	r.Stage = "consent"
	if g.consent(ctx, http) != nil {
		return r
	}
	r.Checks["acknowledgementsOff"] = true
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
	if _, e = setupDisabled(ctx, l); e != nil {
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
		fp, comparison, ok := setupTrust(screen)
		if !ok {
			return r
		}
		if _, _, e = setupConsole(g.pid, secret, secret, true); e != nil {
			return r
		}
		r.Stage = "pending"
		if setupAwait(ctx, 15*time.Second, func() bool { return f.Evidence().State == enrollmentstate.ClaimedPending }) != nil {
			return r
		}
		before := f.Snapshot()
		until := time.Now().Add(2 * time.Second)
		for time.Now().Before(until) {
			if _, e = setupDisabled(ctx, l); e != nil {
				return r
			}
			if _, _, e = setupConsole(g.pid, secret, nil, false); e != nil {
				return r
			}
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
			if _, e = setupDisabled(ctx, l); e != nil {
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
			receipt, e := setupReceipt(l)
			if e != nil || !completeReadSetup(receipt) {
				return r
			}
			r.Checks["completedReceipt"] = true
			if setupAwait(ctx, 20*time.Second, func() bool { return native.VerifySetupServiceToken(ctx, receipt.Service) == nil }) != nil {
				return r
			}
			r.Checks["limitedServiceToken"] = true
			r.Startup = "automatic"
			r.Stage = "frames"
			if setupAwait(ctx, 4*time.Minute, func() bool {
				v := f.Evidence()
				return v.Inventory.Usable() && v.Extensions.Usable() && v.Extensions.V5Frames >= 2
			}) != nil {
				return r
			}
			v := f.Evidence()
			r.Frames = v.Extensions.V5Frames
			r.Checks["twoFiveScopeFrames"] = true
			r.Checks["volumeCapacity"] = v.Extensions.VolumeCapacityCounts.Observed > 0
			r.Checks["processCPUDelta"] = v.Extensions.ProcessCPUCounts.Observed > 0
			r.Checks["tcpFixture"] = v.Extensions.PeerLoopbackRows > 0
		}
	}
	if !setupgate.NormalCase(b.Case) {
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
	if !setupgate.NormalCase(b.Case) {
		expectedExit = 1
	}
	if g.exit(ctx, expectedExit) != nil {
		return r
	}
	r.Checks["workerTerminated"] = true
	if !setupgate.NormalCase(b.Case) {
		if _, e = setupDisabled(ctx, l); e != nil {
			return r
		}
		r.Checks["partialStateRetained"] = true
	}
	r.Stage = "reopen"
	var partial map[string][32]byte
	if !setupgate.NormalCase(b.Case) {
		partial, e = setupFileTree(l)
		if e != nil {
			return r
		}
	}
	reopened, e := setupLaunch(ctx, exe)
	if e != nil {
		return r
	}
	defer reopened.dispose()
	if setupStartInstall(ctx, reopened, public, http) != nil || reopened.finished(ctx) != nil {
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
	if !setupgate.NormalCase(b.Case) {
		after, e := setupFileTree(l)
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
		after, e = setupFileTree(l)
		if e != nil || !reflect.DeepEqual(partial, after) {
			return r
		}
		if _, e = setupDisabled(ctx, l); e != nil {
			return r
		}
		r.Checks["incompleteUninstallBlocked"] = true
		r.Checks["filesAndStateRetained"] = true
	} else {
		r.Stage = "uninstall-cancel"
		receipt, e := setupReceipt(l)
		if e != nil || !completeReadSetup(receipt) {
			return r
		}
		before, e := windowsservice.InspectOwned(ctx, receipt.Service)
		if e != nil {
			return r
		}
		u, e := setupLaunch(ctx, exe)
		if e != nil {
			return r
		}
		defer u.dispose()
		if u.uninstall(ctx, false) != nil {
			return r
		}
		if setupAwait(ctx, 5*time.Second, func() bool { return setupWindow(u.pid, "#32770") == 0 && setupEnabled(setupControl(u.window, 103)) }) != nil {
			return r
		}
		after, e := windowsservice.InspectOwned(ctx, receipt.Service)
		again, receiptErr := setupReceipt(l)
		if e != nil || receiptErr != nil || !reflect.DeepEqual(receipt, again) || !reflect.DeepEqual(before, after) {
			return r
		}
		r.Checks["uninstallCancelUnchanged"] = true
		// This read-only handle deliberately makes DeleteService's pending state
		// observable. The GUI must wait; releasing it permits SCM absence to occur.
		scm, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
		if e != nil {
			return r
		}
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
		r.Stage = "uninstall"
		if u.uninstall(ctx, true) != nil {
			return r
		}
		r.Startup = "inspection_required"
		if setupAwait(ctx, 25*time.Second, func() bool {
			var status windows.SERVICE_STATUS
			return strings.Contains(u.operationText(), "Service deletion is pending. Waiting for SCM to confirm absence.") && windows.QueryServiceStatus(hold, &status) == nil && status.CurrentState == windows.SERVICE_STOPPED && strings.ReplaceAll(setupText(setupControl(u.window, 2)), "&", "") != "Close"
		}) != nil {
			return r
		}
		// Keep the observed exact stopped SCM handle alive a little longer:
		// successful removal cannot be announced while deletion is held pending.
		time.Sleep(500 * time.Millisecond)
		if strings.ReplaceAll(setupText(setupControl(u.window, 2)), "&", "") == "Close" {
			return r
		}

		r.Checks["deletePendingObserved"] = true
		windows.CloseServiceHandle(hold)
		hold = 0
		if u.finished(ctx) != nil || !strings.Contains(u.operationText(), "Service removal confirmed") || u.exit(ctx, 0) != nil {
			return r
		}
		if setupAwait(ctx, 5*time.Second, func() bool { s, e := windowsservice.Inspect(ctx); return e == nil && !s.Exists }) != nil {
			return r
		}
		r.Startup = "absent"
		r.Checks["serviceAbsent"] = true
		r.Stage = "verify-retention"
		again, e = setupReceipt(l)
		if e != nil || !reflect.DeepEqual(receipt, again) {
			return r
		}
		path := filepath.Join(l.EnrollmentRoot, "agent.json")
		identity, e := lanclient.WindowsCapabilityIdentity(path, receipt.ReadSetup.Consent)
		if e != nil || identity != receipt.ReadSetup.SenderBinding {
			return r
		}
		digests, e := lanclient.WindowsCapabilityGrantDigests(path, receipt.ReadSetup.Consent)
		if e != nil || !reflect.DeepEqual(digests, receipt.ReadSetup.GrantDigests) {
			return r
		}
		r.Checks["receiptAndGrantsVerified"] = true
		hash, e := setupArtifactHash(l.Executable)
		if e != nil || hash != b.ServiceHash {
			return r
		}
		if _, e = setupFileTree(l); e != nil {
			return r
		}
		r.Checks["filesAndStateRetained"] = true
	}
	if ctx.Err() != nil {
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
