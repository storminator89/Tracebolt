//go:build windows && tracebolt_setup

package main

import (
	"context"
	"embed"
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
	publicBootstrap, e4 := setupPayload.ReadFile("setup_payload/public-bootstrap.txt")
	if string(publicBootstrap) == "none" {
		publicBootstrap = nil
	} else if e4 == nil {
		_, e4 = setupWizardBootstrap(publicBootstrap)
	}
	valid := e1 == nil && e2 == nil && e3 == nil && e4 == nil && manifest.Validate(payload) == nil
	if !valid {
		// A broken build is never an invitation to download or install another PE.
		setupWizardAlert("This Setup package is incomplete or corrupt. Obtain the reviewed Setup.exe and verify its release provenance. Nothing was installed.")
		os.Exit(2)
	}
	config, hooks, err := setupFrontend(payload, manifest, publicBootstrap, nativeSetupFrontendBackend())
	if err != nil {
		setupWizardAlert("This Setup package is incomplete or corrupt. Obtain the reviewed Setup.exe and verify its release provenance. Nothing was installed.")
		os.Exit(2)
	}
	if windowssetupui.Run(config, hooks) != nil {
		os.Exit(1)
	}
}

// Native operations remain the existing coordinator, called in this process only
// after the frontend and each backend layer's original approval/identity guards.
func nativeSetupFrontendBackend() setupFrontendBackend {
	return setupFrontendBackend{
		preflight: windowspackage.Preflight,
		compatibility: func(ctx context.Context, raw []byte, readAdmin bool) error {
			b, err := setupWizardBootstrap(raw)
			if err != nil {
				return err
			}
			requestCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			expected := windowssetup.Expected(b.ManagerInstanceID, b.EnrollmentOrigin, b.AgentOrigin)
			if readAdmin {
				expected = windowssetup.ExpectedReadAdminV10(b.ManagerInstanceID, b.EnrollmentOrigin, b.AgentOrigin)
			}
			return lanclient.CheckWindowsSetupManager(requestCtx, b.EnrollmentOrigin, b.Profile, []byte(b.ServerCAPEM), expected)
		},
		console: setupWizardConsole,
		provision: func(ctx context.Context, payload []byte, manifest windowspackage.Manifest, raw []byte) (string, func() error, error) {
			r, err := windowspackage.Provision(ctx, payload, manifest, raw)
			if err != nil {
				return "", nil, err
			}
			return r.BootstrapPath, r.Close, nil
		},
		install: func(ctx context.Context, path string, consent lanclient.WindowsCapabilityConsent, console io.Writer, progress func(string), renewal bool) error {
			_, err := installReadObservationWithProgress(ctx, path, consent, console, console, progress, renewal)
			return err
		},
		uninstall: func(ctx context.Context, progress func(string)) error {
			return setupWizardUninstallWithLease(ctx, openReceiptStore, setupWizardRemovalSteps{
				inspectOwned: windowsservice.InspectOwned, inspectRemoval: windowsservice.InspectRemoval, stop: windowsservice.ApplyStop, remove: uninstallWithUpdateOwnership,
				pending: func(err error) bool { return windowsservice.CanWaitRemovalObservation(err) && setupRemovalPending(err) },
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
		},
	}
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
