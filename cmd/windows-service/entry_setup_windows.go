//go:build windows && tracebolt_setup

package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowspackage"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowssetup"
	"localrmm/internal/windowssetupui"
	"os"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// Build tooling injects only reviewed service bytes and nonsecret provenance
// into its isolated build copy. Checked-in placeholders cannot be installed.
//
//go:embed setup_payload/*
var setupPayload embed.FS

func main() {
	// No command-line state, invitation, silent install or automatic apply surface.
	if len(os.Args) != 1 {
		os.Exit(2)
	}
	payload, e1 := setupPayload.ReadFile("setup_payload/service.exe")
	raw, e2 := setupPayload.ReadFile("setup_payload/manifest.json")
	manifest, e3 := windowspackage.ParseManifest(raw)
	valid := e1 == nil && e2 == nil && e3 == nil && manifest.Validate(payload) == nil
	if !valid {
		// A broken build is never an invitation to download or install another PE.
		setupWizardAlert("This Setup package is incomplete or corrupt. Obtain the reviewed Setup.exe and verify its release provenance. Nothing was installed.")
		os.Exit(2)
	}
	config := windowssetupui.Config{Version: manifest.Version, SourceCommit: manifest.SourceCommit, PayloadSHA256: manifest.SHA256, Architecture: manifest.Architecture, Disclosure: setupWizardDisclosure(), HTTPDisclosure: setupWizardHTTPDisclosure()}
	hooks := windowssetupui.Hooks{Preview: setupWizardPreview}
	hooks.Install = func(ctx context.Context, raw []byte, insecureAcknowledged bool, progress func(string)) error {
		ctx, stop := context.WithCancel(ctx)
		defer stop()
		var console io.Writer
		steps := setupWizardInstallSteps{
			validate: func(b []byte) error {
				if manifest.Validate(payload) != nil {
					return errLifecycle
				}
				_, _, err := setupWizardAcknowledgedBootstrap(b, insecureAcknowledged)
				if err != nil {
					return errLifecycle
				}
				return nil
			},
			preflight: windowspackage.Preflight,
			compatibility: func(ctx context.Context, raw []byte) error {
				b, err := setupWizardBootstrap(raw)
				if err != nil {
					return err
				}
				requestCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
				defer cancel()
				return lanclient.CheckWindowsSetupManager(requestCtx, b.EnrollmentOrigin, b.Profile, []byte(b.ServerCAPEM), windowssetup.Expected(b.ManagerInstanceID, b.EnrollmentOrigin, b.AgentOrigin))
			},
			console: func() (func() error, error) {
				w, close, err := setupWizardConsole(stop)
				console = w
				return close, err
			},
			provision: func(ctx context.Context, raw []byte) (string, func() error, error) {
				r, err := windowspackage.Provision(ctx, payload, manifest, raw)
				if err != nil {
					return "", nil, err
				}
				return r.BootstrapPath, r.Close, nil
			},
			install: func(ctx context.Context, path string) error {
				_, consent, err := setupWizardAcknowledgedBootstrap(raw, insecureAcknowledged)
				if err != nil {
					return err
				}
				_, err = installReadObservationWithProgress(ctx, path, consent, console, console, progress)
				return err
			},
		}
		err := setupWizardInstall(ctx, raw, steps, progress)
		if err != nil {
			setupWizardFailure(err, progress)
		}
		return err
	}
	hooks.Uninstall = func(ctx context.Context, progress func(string)) error {
		err := setupWizardUninstall(ctx, setupWizardRemovalSteps{
			receipt: func() (windowsservice.Receipt, error) { r, e := loadReceipt(); return r.Service, e }, inspectOwned: windowsservice.InspectOwned, inspect: windowsservice.Inspect, stop: windowsservice.ApplyStop, remove: windowsservice.ApplyUninstall,
			pending: func(err error) bool { return errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) },
			wait: func(ctx context.Context) error {
				t := time.NewTimer(250 * time.Millisecond)
				defer t.Stop()
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-t.C:
					return nil
				}
			},
		}, progress)
		if err != nil {
			progress(setupRemovalFailureText(err))
		}
		return err
	}
	if windowssetupui.Run(config, hooks) != nil {
		os.Exit(1)
	}
}

func setupWizardFailure(err error, progress func(string)) {
	if errors.Is(err, windowssetup.ErrCompatibility) {
		progress("Manager compatibility check failed before installation: update the Linux/Docker manager to the same reviewed Setup revision, enable Windows enrollment, and download a new Windows bootstrap export. Check the exact selected origin and HTTPS CA when applicable; never bypass TLS or silently change transport.")
		return
	}
	if outcome, ok := err.(*setupWizardOutcomeError); ok && outcome.beforeMutation {
		progress("Setup stopped before installation writes. No new service, identity or scope grants were created. Review the package, platform, public export and existing-installation boundary; existing state is never overwritten or repaired. Package diagnostic: " + windowspackage.Code(outcome.cause))
		return
	}
	if outcome, ok := err.(*setupWizardOutcomeError); ok {
		err = outcome.cause
	}
	code := windowspackage.Code(err)
	d := windowsservice.Diagnostic(err)
	progress(fmt.Sprintf("Setup stopped. Package diagnostic: %s; service phase: %s; reason: %s. Retained state may be incomplete or startup indeterminate. Do not rerun installation or delete state. An administrator can use the installed tracebolt-windows-service.exe --inspect for read-only SCM status; retain the displayed public diagnostic for review.", code, d.Phase, d.Reason))
}

// A dedicated native console preserves the reviewed CONIN$ no-echo reader and
// public-fingerprint-before-secret ordering. No stdin pipe/secret IPC is used.
var activeSetupConsole atomic.Pointer[setupConsoleControl]
var setupConsoleCallback = syscall.NewCallback(func(event uint32) uintptr {
	if activeSetupConsole.Load().handle(event) {
		return 1
	}
	return 0
})

func setupWizardConsole(cancel context.CancelFunc) (io.Writer, func() error, error) {
	kernel := windows.NewLazySystemDLL("kernel32.dll")
	alloc := kernel.NewProc("AllocConsole")
	free := kernel.NewProc("FreeConsole")
	setHandler := kernel.NewProc("SetConsoleCtrlHandler")
	if cancel == nil || alloc.Find() != nil || free.Find() != nil || setHandler.Find() != nil {
		return nil, nil, errLifecycle
	}
	if ok, _, _ := alloc.Call(); ok == 0 {
		return nil, nil, errLifecycle
	}
	control := &setupConsoleControl{cancel: cancel}
	if !activeSetupConsole.CompareAndSwap(nil, control) {
		free.Call()
		return nil, nil, errLifecycle
	}
	// AllocConsole resets Go's process control-handler table. Register our own
	// handler afterwards; os/signal alone cannot restore it on Windows.
	if ok, _, _ := setHandler.Call(setupConsoleCallback, 1); ok == 0 {
		activeSetupConsole.CompareAndSwap(control, nil)
		free.Call()
		return nil, nil, errLifecycle
	}
	release := func() error {
		unregister, _, _ := setHandler.Call(setupConsoleCallback, 0)
		freed, _, _ := free.Call()
		if unregister != 0 || freed != 0 {
			activeSetupConsole.CompareAndSwap(control, nil)
		}
		if unregister == 0 || freed == 0 {
			return errLifecycle
		}
		return nil
	}
	f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	if err != nil {
		_ = release()
		return nil, nil, errLifecycle
	}
	title, _ := windows.UTF16PtrFromString("Tracebolt Setup: verify trust and enter invitation (hidden)")
	kernel.NewProc("SetConsoleTitleW").Call(uintptr(unsafe.Pointer(title)))
	// OS console closure can terminate the process before cleanup. Remove its
	// Close menu item when exposed, but do not claim this prevents every terminal
	// or shutdown close. GUI Cancel and Ctrl+C/Break are cooperative paths.
	hwnd, _, _ := kernel.NewProc("GetConsoleWindow").Call()
	if hwnd != 0 {
		user := windows.NewLazySystemDLL("user32.dll")
		menu, _, _ := user.NewProc("GetSystemMenu").Call(hwnd, 0)
		if menu != 0 {
			user.NewProc("DeleteMenu").Call(menu, 0xf060, 0)
			user.NewProc("DrawMenuBar").Call(hwnd)
		}
	}
	return f, func() error {
		e := f.Close()
		released := release()
		if e != nil || released != nil {
			return errLifecycle
		}
		return nil
	}, nil
}

func setupWizardAlert(message string) {
	text, _ := windows.UTF16PtrFromString(message)
	title, _ := windows.UTF16PtrFromString("Tracebolt Setup")
	windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)), 0x10)
}
