//go:build windows && tracebolt_setup_rust && cgo

package windowssetupui

/*
#cgo windows LDFLAGS: -ltracebolt_windows_setup -luser32 -lgdi32 -lcomdlg32 -lbcrypt -lkernel32 -lntdll -luserenv -lws2_32 -ldbghelp
#include "rust_bridge.h"
*/
import "C"

import (
	"os"
	"runtime"
	"runtime/cgo"
	"unsafe"
)

func rustFrontendEnabled() bool { return true }

func runRust(c Config, h Hooks) (result error) {
	if runtime.GOARCH != c.Architecture {
		return ErrConfiguration
	}
	if C.tracebolt_setup_abi() != C.TRACEBOLT_SETUP_ABI {
		return ErrUI
	}
	r, err := newRustController(c, h)
	if err != nil {
		return err
	}
	// Reuse the original protected adjacent-file discovery and picker. There is
	// no Rust file parser, invitation reader or alternate provisioning backend.
	w := &wizard{config: c, hooks: h, flow: r.flow, fileName: r.fileName}
	if !activeWizard.CompareAndSwap(nil, w) {
		return ErrUI
	}
	defer activeWizard.Store(nil)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	w.selectAdjacentBootstrap(os.Executable, adjacentBootstrapEntries, readPublicBootstrap)
	r.flow, r.fileName = w.flow, w.fileName
	r.choose = chooseFile
	r.confirm = func(owner uintptr) bool {
		body := "Remove the owned Tracebolt Windows service?\r\n\r\nThis may stop the service and removes its service registration. Installed files, persistent device identity, grants and setup state are retained. It does not revoke the identity in the manager.\r\n\r\nNo files or identity are deleted. A later fresh installation may still be blocked by retained state. This action is separate from installation consent."
		answer, _, _ := messageBox.Call(owner, uintptr(unsafe.Pointer(utf16(body))), uintptr(unsafe.Pointer(utf16("Confirm service-only uninstall"))), 0x4|0x30|0x100)
		return answer == 6 // YESNO, warning, default No.
	}
	handle := cgo.NewHandle(r)
	defer handle.Delete()
	defer func() {
		if err := r.finish(); result == nil {
			result = err
		}
	}()
	if C.tracebolt_setup_go_run(C.uintptr_t(handle)) != 0 {
		return ErrUI
	}
	return nil
}

//export traceboltSetupEvent
func traceboltSetupEvent(handle C.uintptr_t, event *C.TraceboltSetupEvent, out *C.uint8_t, capacity C.size_t) (result C.intptr_t) {
	// Go panic never unwinds into C/Rust. No Go pointer is retained by Rust;
	// handle is an integer and out is Rust-owned synchronous scratch storage.
	result = -1
	defer func() {
		if recover() != nil {
			result = -1
		}
	}()
	if event == nil || out == nil || capacity != rustViewLimit {
		return -1
	}
	r, ok := cgo.Handle(handle).Value().(*rustController)
	if !ok {
		return -1
	}
	if event.code == rustResize {
		r.resize(int(event.width), int(event.height), int(event.dpi))
	} else {
		r.command(int(event.code), int(event.value), uintptr(event.owner))
	}
	data, err := r.view()
	if err != nil || len(data) > int(capacity) {
		return -1
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(out)), int(capacity)), data)
	return C.intptr_t(len(data))
}
