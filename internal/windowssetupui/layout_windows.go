//go:build windows

package windowssetupui

import "unsafe"

const (
	// Caption, system menu, thick frame, minimize and maximize buttons. Native
	// resizing remains bounded by the minimum client geometry below.
	windowStyle         = uintptr(0x00c00000 | 0x00080000 | 0x00040000 | 0x00020000 | 0x00010000)
	windowExtendedStyle = uintptr(0x00010000) // WS_EX_CONTROLPARENT
)

type monitorInfo struct {
	Size          uint32
	Monitor, Work rect
	Flags         uint32
}
type minMaxInfo struct{ Reserved, MaxSize, MaxPosition, MinTrackSize, MaxTrackSize point }

// LPARAM is a pointer-sized native union: most messages carry integer values,
// while WM_DPICHANGED and WM_GETMINMAXINFO carry system-owned structure pointers.
// Decode the pointer from that argument's storage only for those messages. The
// callback must not retain it after returning. Keeping LPARAM itself a uintptr
// avoids exposing arbitrary integer message payloads as Go GC pointers.
func nativeMessagePointer[T any](parameter *uintptr) *T {
	return *(**T)(unsafe.Pointer(parameter))
}

func monitorWorkArea(monitor uintptr) (box, bool) {
	info := monitorInfo{}
	info.Size = uint32(unsafe.Sizeof(info))
	if monitor == 0 {
		return box{}, false
	}
	if ok, _, _ := getMonitorInfo.Call(monitor, uintptr(unsafe.Pointer(&info))); ok == 0 {
		return box{}, false
	}
	r := info.Work
	return box{int(r.Left), int(r.Top), int(r.Right - r.Left), int(r.Bottom - r.Top)}, true
}

func windowWorkArea(hwnd uintptr) (box, bool) {
	monitor, _, _ := monitorFromWindow.Call(hwnd, 2) // MONITOR_DEFAULTTONEAREST
	return monitorWorkArea(monitor)
}

func nonclientFrame(dpi int) (int, int, bool) {
	if dpi < 96 || dpi > 768 {
		return 0, 0, false
	}
	r := rect{}
	if ok, _, _ := adjustWindowRect.Call(uintptr(unsafe.Pointer(&r)), windowStyle, 0, windowExtendedStyle, uintptr(dpi)); ok == 0 {
		return 0, 0, false
	}
	return int(r.Right - r.Left), int(r.Bottom - r.Top), true
}

func (w *wizard) updateFont() bool {
	if w.dpi < 96 || w.dpi > 768 {
		return false
	}
	// Nine-point Segoe UI; both control geometry and font are scaled from the
	// same 96-DPI design units. This thread was made per-monitor-V2 before any
	// window or coordinate query; there is no DPI-virtualized/physical mix.
	font, _, _ := createFont.Call(uintptr(-scale(12, w.dpi)), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0,
		uintptr(unsafe.Pointer(utf16("Segoe UI"))))
	if font == 0 {
		return false
	}
	previous := w.font
	w.font = font
	for _, control := range w.controls {
		sendMessage.Call(control, wmSetFont, font, 1)
	}
	if previous != 0 {
		deleteObject.Call(previous)
	}
	return true
}

func (w *wizard) fitToWorkArea(suggested *rect) bool {
	work, ok := windowWorkArea(w.window)
	if suggested != nil {
		monitor, _, _ := monitorFromRect.Call(uintptr(unsafe.Pointer(suggested)), 2)
		work, ok = monitorWorkArea(monitor)
	}
	if !ok {
		return false
	}
	var current rect
	if suggested != nil {
		current = *suggested
	} else {
		if ok, _, _ := getWindowRect.Call(w.window, uintptr(unsafe.Pointer(&current))); ok == 0 {
			return false
		}
	}
	frameWidth, frameHeight, ok := nonclientFrame(w.dpi)
	if !ok {
		return false
	}
	desired := box{int(current.Left), int(current.Top), int(current.Right - current.Left), int(current.Bottom - current.Top)}
	placement, ok := clampWindow(desired, work, w.dpi, frameWidth, frameHeight)
	if !ok {
		return false
	}
	result, _, _ := setWindowPos.Call(w.window, 0, uintptr(placement.X), uintptr(placement.Y),
		uintptr(placement.Width), uintptr(placement.Height), 0x0004|0x0010) // NOZORDER, NOACTIVATE
	return result != 0
}

func (w *wizard) applyLayout() bool {
	// Geometry may fail after a display/DPI change or an API failure. Keep all
	// actions except Cancel unavailable until the complete layout succeeds.
	w.setLayoutReady(false)
	var client rect
	if ok, _, _ := getClientRect.Call(w.window, uintptr(unsafe.Pointer(&client))); ok == 0 {
		return false
	}
	l, ok := layoutForClient(int(client.Right-client.Left), int(client.Bottom-client.Top), w.dpi, w.flow.page, w.flow.trust.HTTPTest)
	if !ok {
		return false
	}
	for id, b := range l {
		if control := w.controls[id]; control != 0 {
			if ok, _, _ := moveWindow.Call(control, uintptr(b.X), uintptr(b.Y), uintptr(b.Width), uintptr(b.Height), 1); ok == 0 {
				return false
			}
		}
	}
	w.setLayoutReady(true)
	return true
}

func (w *wizard) setLayoutReady(ready bool) {
	w.layoutOK = ready
	w.updateActions()
}

func (w *wizard) updateActions() {
	ready := w.layoutOK && !w.flow.busy && !w.flow.attempted
	enable(w.controls[idNext], ready && ((w.flow.page == pageInput && len(w.flow.bootstrap) > 0) || w.flow.canInstall()))
	enable(w.controls[idBack], ready && w.flow.page == pageReview)
	for _, id := range []int{idChoose, idUninstall} {
		enable(w.controls[id], ready && w.flow.page == pageInput)
	}
	for _, id := range []int{idScope, idService, idIdentity, idCompared, idHTTPRisk} {
		enable(w.controls[id], ready && w.flow.page == pageReview)
	}
}

// A monitor that cannot contain even the minimum client is unsupported. Before
// apply this ends the inert wizard; during an operation it requests cancellation
// and keeps the window/message pump alive until the hook releases its console.
func (w *wizard) layoutUnavailable() {
	w.setLayoutReady(false)
	if !w.flow.busy {
		w.flow.result = ErrUI
	}
	w.close()
}

func (w *wizard) minimumTrackingSize(pointer uintptr) {
	if pointer == 0 {
		return
	}
	frameWidth, frameHeight, ok := nonclientFrame(w.dpi)
	if !ok {
		return
	}
	m := nativeMessagePointer[minMaxInfo](&pointer)
	m.MinTrackSize = point{int32(scaleUp(minimumClientWidth, w.dpi) + frameWidth), int32(scaleUp(minimumClientHeight, w.dpi) + frameHeight)}
}
