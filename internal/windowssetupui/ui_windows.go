//go:build windows

package windowssetupui

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32                = windows.NewLazySystemDLL("user32.dll")
	gdi32                 = windows.NewLazySystemDLL("gdi32.dll")
	comdlg32              = windows.NewLazySystemDLL("comdlg32.dll")
	kernel32              = windows.NewLazySystemDLL("kernel32.dll")
	registerClass         = user32.NewProc("RegisterClassExW")
	unregisterClass       = user32.NewProc("UnregisterClassW")
	createWindow          = user32.NewProc("CreateWindowExW")
	defWindowProc         = user32.NewProc("DefWindowProcW")
	destroyWindow         = user32.NewProc("DestroyWindow")
	getMessage            = user32.NewProc("GetMessageW")
	translateMessage      = user32.NewProc("TranslateMessage")
	dispatchMessage       = user32.NewProc("DispatchMessageW")
	isDialogMessage       = user32.NewProc("IsDialogMessageW")
	postMessage           = user32.NewProc("PostMessageW")
	postQuitMessage       = user32.NewProc("PostQuitMessage")
	sendMessage           = user32.NewProc("SendMessageW")
	setWindowText         = user32.NewProc("SetWindowTextW")
	showWindow            = user32.NewProc("ShowWindow")
	updateWindow          = user32.NewProc("UpdateWindow")
	enableWindow          = user32.NewProc("EnableWindow")
	setFocus              = user32.NewProc("SetFocus")
	setTimer              = user32.NewProc("SetTimer")
	killTimer             = user32.NewProc("KillTimer")
	messageBox            = user32.NewProc("MessageBoxW")
	loadCursor            = user32.NewProc("LoadCursorW")
	adjustWindowRect      = user32.NewProc("AdjustWindowRectExForDpi")
	getClientRect         = user32.NewProc("GetClientRect")
	getWindowRect         = user32.NewProc("GetWindowRect")
	moveWindow            = user32.NewProc("MoveWindow")
	setWindowPos          = user32.NewProc("SetWindowPos")
	monitorFromWindow     = user32.NewProc("MonitorFromWindow")
	monitorFromRect       = user32.NewProc("MonitorFromRect")
	getMonitorInfo        = user32.NewProc("GetMonitorInfoW")
	getDpiForWindow       = user32.NewProc("GetDpiForWindow")
	getDpiForSystem       = user32.NewProc("GetDpiForSystem")
	setThreadDpiAwareness = user32.NewProc("SetThreadDpiAwarenessContext")
	createFont            = gdi32.NewProc("CreateFontW")
	deleteObject          = gdi32.NewProc("DeleteObject")
	getOpenFileName       = comdlg32.NewProc("GetOpenFileNameW")
	commDlgExtendedError  = comdlg32.NewProc("CommDlgExtendedError")
	getModuleHandle       = kernel32.NewProc("GetModuleHandleW")
	getDriveType          = kernel32.NewProc("GetDriveTypeW")
	activeWizard          atomic.Pointer[wizard]
	windowCallback        = syscall.NewCallback(windowProcedure)
)

const (
	wmDestroy         = 0x0002
	wmSize            = 0x0005
	wmGetMinMaxInfo   = 0x0024
	wmDPIChanged      = 0x02e0
	wmDisplayChange   = 0x007e
	wmSettingChange   = 0x001a
	wmClose           = 0x0010
	wmQueryEndSession = 0x0011
	wmCommand         = 0x0111
	wmTimer           = 0x0113
	wmSetFont         = 0x0030
	wmUpdate          = 0x8001
	bmGetCheck        = 0x00f0
	bmSetCheck        = 0x00f1
	wsChild           = 0x40000000
	wsVisible         = 0x10000000
	wsTabStop         = 0x00010000
	wsVScroll         = 0x00200000
	wsBorder          = 0x00800000
	esMultiline       = 0x0004
	esAutoVScroll     = 0x0040
	esReadOnly        = 0x0800
	bsAutoCheckbox    = 0x0003
	bsMultiline       = 0x2000
	operationTimer    = 301
)

type winClass struct {
	Size, Style                        uint32
	WndProc                            uintptr
	ClsExtra, WndExtra                 int32
	Instance, Icon, Cursor, Background uintptr
	MenuName, ClassName                *uint16
	IconSmall                          uintptr
}

type point struct{ X, Y int32 }
type winMessage struct {
	Window         uintptr
	Message        uint32
	WParam, LParam uintptr
	Time           uint32
	Point          point
	Private        uint32
}
type rect struct{ Left, Top, Right, Bottom int32 }

// This is the Windows SDK layout, excluding its legacy _MAC-only fields.
// On both supported 64-bit targets OPENFILENAMEW is exactly 152 bytes.
type openFileName struct {
	Size                         uint32
	Owner, Instance              uintptr
	Filter, CustomFilter         *uint16
	MaxCustomFilter, FilterIndex uint32
	File                         *uint16
	MaxFile                      uint32
	FileTitle                    *uint16
	MaxFileTitle                 uint32
	InitialDir, Title            *uint16
	Flags                        uint32
	FileOffset, FileExtension    uint16
	DefaultExtension             *uint16
	CustomData, Hook             uintptr
	TemplateName                 *uint16
	Reserved                     uintptr
	ReservedWord, FlagsEx        uint32
}

type wizard struct {
	config                           Config
	hooks                            Hooks
	flow                             flow
	window, instance, font           uintptr
	dpi                              int
	layoutOK                         bool
	controls                         map[int]uintptr
	content, heading, note, selected uintptr
	pageControls                     []uintptr
	fileName                         string
	cancel                           context.CancelFunc
	done                             chan error
	progressMu                       sync.Mutex
	latestProgress                   string
	progress                         string
}

// Run starts a single native UI on a locked OS thread. It returns only after a
// running hook has returned, even when Close/Cancel is requested. The caller
// must build with -H windowsgui; the hooks own any separately allocated console.
func Run(c Config, h Hooks) error {
	if !validConfig(c, h) {
		return ErrConfiguration
	}
	if runtime.GOARCH != c.Architecture {
		return ErrConfiguration
	}
	w := &wizard{config: c, hooks: h, controls: make(map[int]uintptr)}
	if !activeWizard.CompareAndSwap(nil, w) {
		return ErrUI
	}
	defer activeWizard.Store(nil)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for _, p := range []*windows.LazyProc{registerClass, unregisterClass, createWindow, defWindowProc,
		destroyWindow, getMessage, translateMessage, dispatchMessage, isDialogMessage, postMessage,
		postQuitMessage, sendMessage, setWindowText, showWindow, updateWindow, enableWindow, setFocus,
		messageBox, loadCursor, adjustWindowRect, getOpenFileName, commDlgExtendedError, setTimer, killTimer,
		getModuleHandle, getDriveType, getClientRect, getWindowRect, moveWindow, setWindowPos, monitorFromWindow, monitorFromRect, getMonitorInfo, getDpiForWindow, getDpiForSystem, setThreadDpiAwareness, createFont, deleteObject} {
		if p.Find() != nil {
			return ErrUI
		}
	}
	previousDPI, _, _ := setThreadDpiAwareness.Call(^uintptr(3)) // PER_MONITOR_AWARE_V2 (-4)
	if previousDPI == 0 {
		return ErrUI
	}
	defer setThreadDpiAwareness.Call(previousDPI)
	dpi, _, _ := getDpiForSystem.Call()
	w.dpi = int(dpi)
	w.instance, _, _ = getModuleHandle.Call(0)
	if w.instance == 0 {
		return ErrUI
	}
	cursor, _, _ := loadCursor.Call(0, 32512) // IDC_ARROW
	className := utf16("TraceboltFreshSetupWizard")
	class := winClass{WndProc: windowCallback, Instance: w.instance, Cursor: cursor,
		Background: 16, ClassName: className} // COLOR_BTNFACE + 1
	class.Size = uint32(unsafe.Sizeof(class))
	if atom, _, _ := registerClass.Call(uintptr(unsafe.Pointer(&class))); atom == 0 {
		return ErrUI
	}
	defer unregisterClass.Call(uintptr(unsafe.Pointer(className)), w.instance)
	work, ok := windowWorkArea(0)
	if !ok {
		return ErrUI
	}
	frameWidth, frameHeight, ok := nonclientFrame(w.dpi)
	if !ok {
		return ErrUI
	}
	initial, ok := fitWindow(work, w.dpi, frameWidth, frameHeight)
	if !ok {
		return ErrUI
	}
	w.window, _, _ = createWindow.Call(windowExtendedStyle, uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(utf16("Tracebolt Setup"))), windowStyle, uintptr(initial.X), uintptr(initial.Y),
		uintptr(initial.Width), uintptr(initial.Height), 0, 0, w.instance, 0)
	if w.window == 0 {
		return ErrUI
	}
	defer func() {
		// A message-pump failure cannot strand an active console-owning hook.
		if w.flow.busy {
			w.cancel()
			w.flow.complete(<-w.done)
		}
		destroyWindow.Call(w.window)
		if w.font != 0 {
			deleteObject.Call(w.font)
		}
	}()
	dpi, _, _ = getDpiForWindow.Call(w.window)
	w.dpi = int(dpi)
	if !w.updateFont() || !w.fitToWorkArea(nil) {
		return ErrUI
	}
	if !w.makeCommonControls() || !w.render() {
		return ErrUI
	}
	showWindow.Call(w.window, 1)
	updateWindow.Call(w.window)
	setFocus.Call(w.controls[idChoose])
	var message winMessage
	for {
		ok, _, _ := getMessage.Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0)
		if int32(ok) == -1 {
			return ErrUI
		}
		if ok == 0 {
			break
		}
		if handled, _, _ := isDialogMessage.Call(w.window, uintptr(unsafe.Pointer(&message))); handled != 0 {
			continue
		}
		translateMessage.Call(uintptr(unsafe.Pointer(&message)))
		dispatchMessage.Call(uintptr(unsafe.Pointer(&message)))
	}
	if w.flow.busy {
		w.cancel()
		w.flow.complete(<-w.done)
	}
	return w.flow.result
}

func utf16(s string) *uint16 {
	// Callers only pass fixed or validated public text. Replacing NUL also makes
	// an accidental malformed progress update harmless to Win32 string parsing.
	p, _ := windows.UTF16PtrFromString(strings.ReplaceAll(s, "\x00", ""))
	return p
}

func windowProcedure(hwnd uintptr, message uint32, wp, lp uintptr) uintptr {
	w := activeWizard.Load()
	if w != nil && w.window == hwnd {
		switch message {
		case wmSize:
			// SIZE_MINIMIZED has a zero client area and is not a failure.
			if wp != 1 && !w.applyLayout() {
				w.layoutUnavailable()
			}
			return 0
		case wmGetMinMaxInfo:
			w.minimumTrackingSize(lp)
			return 0
		case wmDPIChanged:
			changeLayout(w.setLayoutReady, func() bool {
				if lp == 0 {
					return false
				}
				w.dpi = int(wp & 0xffff)
				suggested := *nativeMessagePointer[rect](&lp)
				return w.updateFont() && w.fitToWorkArea(&suggested)
			}, w.applyLayout, w.layoutUnavailable)
			return 0
		case wmDisplayChange, wmSettingChange:
			changeLayout(w.setLayoutReady, func() bool {
				return w.fitToWorkArea(nil)
			}, w.applyLayout, w.layoutUnavailable)
			return 0
		case wmCommand:
			if (wp >> 16) == 0 {
				w.command(int(wp & 0xffff))
			}
			return 0
		case wmClose:
			w.close()
			return 0
		case wmQueryEndSession:
			if w.flow.busy {
				w.close()
				return 0
			}
			return 1
		case wmUpdate:
			w.receiveUpdates()
			return 0
		case wmTimer:
			if wp == operationTimer {
				w.receiveUpdates()
			}
			return 0
		case wmDestroy:
			postQuitMessage.Call(0)
			return 0
		}
	}
	r, _, _ := defWindowProc.Call(hwnd, uintptr(message), wp, lp)
	return r
}

func (w *wizard) control(class, title string, style uintptr, id int, perPage bool) uintptr {
	h, _, _ := createWindow.Call(0, uintptr(unsafe.Pointer(utf16(class))), uintptr(unsafe.Pointer(utf16(title))),
		style|wsChild|wsVisible, 0, 0, 1, 1,
		w.window, uintptr(id), w.instance, 0)
	if h != 0 {
		sendMessage.Call(h, wmSetFont, w.font, 1)
		if id != 0 {
			w.controls[id] = h
		}
		if perPage {
			w.pageControls = append(w.pageControls, h)
		}
	}
	return h
}

func (w *wizard) makeCommonControls() bool {
	w.heading = w.control("STATIC", "", 0, idHeading, false)
	provenanceControl := w.control("EDIT", provenance(w.config), esMultiline|esReadOnly|esAutoVScroll|wsVScroll|wsTabStop, idProvenance, false)
	w.note = w.control("STATIC", "", 0, idNote, false)
	back := w.control("BUTTON", "< &Back", wsTabStop, idBack, false)
	next := w.control("BUTTON", "&Next >", wsTabStop|1, idNext, false)
	cancel := w.control("BUTTON", "&Cancel", wsTabStop, idCancel, false)
	return w.heading != 0 && provenanceControl != 0 && w.note != 0 && back != 0 && next != 0 && cancel != 0
}

func (w *wizard) render() bool {
	for _, h := range w.pageControls {
		destroyWindow.Call(h)
	}
	w.pageControls = nil
	for _, id := range []int{idChoose, idUninstall, idScope, idService, idIdentity, idCompared, idHTTPRisk, idSelectedFile, idReviewText, idOperationText, idInputText} {
		delete(w.controls, id)
	}
	enable(w.controls[idBack], w.flow.page == pageReview)
	enable(w.controls[idNext], false)
	enable(w.controls[idCancel], true)
	setText(w.controls[idCancel], "&Cancel")
	switch w.flow.page {
	case pageInput:
		setText(w.heading, "Step 1 of 3: Choose the public bootstrap")
		setText(w.controls[idNext], "&Next >")
		intro := "Choose the public bootstrap JSON supplied by your manager operator. The file must be a regular local file, no larger than 64 KiB.\r\n\r\nThis is public manager identity and trust material only. Do not choose a file containing an invitation, password, private key or other secret. The invitation is entered later in a separate console with input hidden.\r\n\r\nThis setup is for a fresh endpoint only. Existing service, enrollment, grants or setup state are never adopted or reset. HTTPS is the default. Explicit isolated HTTP-test bootstraps require a separate plaintext-risk approval.\r\n\r\nAfter choosing a valid bootstrap, review the full data scope and compare all public trust values independently. Installation only begins after you explicitly approve the read scopes, service, persistent identity and trust comparison.\r\n\r\nNo browser is opened and nothing is downloaded by this wizard."
		if w.control("EDIT", intro, esMultiline|esReadOnly|esAutoVScroll|wsVScroll|wsTabStop|wsBorder, idInputText, true) == 0 {
			return false
		}
		w.selected = w.control("EDIT", w.fileName, esReadOnly|wsTabStop|wsBorder, idSelectedFile, true)
		choose := w.control("BUTTON", "Choose &file...", wsTabStop, idChoose, true)
		uninstall := w.control("BUTTON", "&Uninstall service...", wsTabStop, idUninstall, true)
		if w.selected == 0 || choose == 0 || uninstall == 0 {
			return false
		}
		enable(w.controls[idNext], len(w.flow.bootstrap) != 0)
		setText(w.note, "Cancel now leaves installation state unchanged. Uninstall is a separate, explicitly confirmed service-only action.")
	case pageReview:
		setText(w.heading, "Step 2 of 3: Review scope, service, identity and trust")
		setText(w.controls[idNext], "&Install")
		w.content = w.control("EDIT", reviewText(w.config, w.flow.trust), esMultiline|esReadOnly|esAutoVScroll|wsVScroll|wsTabStop|wsBorder, idReviewText, true)
		checks := []struct {
			id   int
			text string
		}{
			{idScope, "I approve the exact five READ scopes and the full privacy disclosure above."},
			{idService, "I approve a LocalService Windows service and automatic startup after verified activation and grants."},
			{idIdentity, "I approve creation and protected storage of a persistent device identity on this computer."},
			{idCompared, "I independently compared the manager ID, both origins and every full trust fingerprint above."},
		}
		if w.flow.trust.HTTPTest {
			checks = append(checks, struct {
				id   int
				text string
			}{idHTTPRisk, "I accept plaintext invitation and five-scope telemetry, and forged manager-response risks for this HTTP test."})
		}
		for _, c := range checks {
			h := w.control("BUTTON", c.text, bsAutoCheckbox|bsMultiline|wsTabStop, c.id, true)
			if h == 0 {
				return false
			}
			sendMessage.Call(h, bmSetCheck, 0, 0)
		}
		if w.content == 0 {
			return false
		}
		setText(w.note, "Install opens a separate hidden-input console. Manager device-fingerprint approval is still required. Back clears all checkboxes.")
	case pageOperation:
		setText(w.heading, "Step 3 of 3: Installation status")
		if w.flow.operation == opUninstall {
			setText(w.heading, "Service-only uninstall status")
		}
		w.content = w.control("EDIT", w.progress, esMultiline|esReadOnly|esAutoVScroll|wsVScroll|wsTabStop|wsBorder, idOperationText, true)
		if w.content == 0 {
			return false
		}
		setText(w.note, "Keep the wizard and its invitation console open. Cancel requests a safe stop and waits for console cleanup; retained state is not rolled back.")
	}
	return w.applyLayout()
}

func (w *wizard) command(id int) {
	// Also reject synthetic/queued WM_COMMAND messages for disabled controls.
	// A geometry failure must not permit a hook or consent change through them.
	if !w.layoutOK && id != idCancel {
		return
	}
	switch id {
	case idCancel:
		w.close()
	case idBack:
		if w.flow.back() {
			w.renderOrClose()
			setFocus.Call(w.controls[idChoose])
		}
	case idChoose:
		if !w.flow.clearSelection() {
			return
		}
		w.fileName = ""
		setText(w.selected, "")
		enable(w.controls[idNext], false)
		path, canceled, err := chooseFile(w.window)
		if canceled {
			return
		}
		if err != nil {
			w.alert("The file chooser could not open. No installation was started.")
			return
		}
		data, err := readPublicBootstrap(path)
		if err != nil {
			w.alert("Choose a regular local public bootstrap file between 1 byte and 64 KiB. Links, network paths, devices and directories are not accepted.")
			return
		}
		preview, err := w.hooks.Preview(append([]byte(nil), data...))
		if err != nil || !previewAllowed(w.config, preview) || w.flow.selectBootstrap(data, preview) != nil {
			w.alert("The public bootstrap is invalid or unsupported. Use the manager's validated public bootstrap, without invitation or private material. HTTPS is the default; HTTP-test requires its full separate risk disclosure. Nothing was installed.")
			return
		}
		w.fileName = filepath.Base(path)
		setText(w.selected, w.fileName+" (public bootstrap validated)")
		w.updateActions()
		setFocus.Call(w.controls[idNext])
	case idScope, idService, idIdentity, idCompared, idHTTPRisk:
		if w.flow.page != pageReview || w.flow.busy || w.flow.attempted {
			return
		}
		w.flow.scope = checked(w.controls[idScope])
		w.flow.service = checked(w.controls[idService])
		w.flow.identity = checked(w.controls[idIdentity])
		w.flow.compared = checked(w.controls[idCompared])
		w.flow.httpAcknowledged = w.flow.trust.HTTPTest && checked(w.controls[idHTTPRisk])
		w.updateActions()
	case idNext:
		if !w.layoutOK {
			return
		}
		if w.flow.page == pageInput {
			if w.flow.next() {
				w.renderOrClose()
				setFocus.Call(w.content)
			}
		} else if w.flow.canInstall() {
			w.start(opInstall, false)
		}
	case idUninstall:
		if w.flow.busy || w.flow.attempted || w.flow.page != pageInput {
			return
		}
		body := "Remove the owned Tracebolt Windows service?\r\n\r\nThis may stop the service and removes its service registration. Installed files, persistent device identity, grants and setup state are retained. It does not revoke the identity in the manager.\r\n\r\nNo files or identity are deleted. A later fresh installation may still be blocked by the retained state. This action is separate from installation consent."
		answer, _, _ := messageBox.Call(w.window, uintptr(unsafe.Pointer(utf16(body))), uintptr(unsafe.Pointer(utf16("Confirm service-only uninstall"))), 0x00000004|0x00000030|0x00000100) // YESNO, warning, default No
		if answer == 6 {
			w.start(opUninstall, true)
		}
	}
}

func (w *wizard) renderOrClose() {
	if !w.render() {
		w.flow.result = ErrUI
		w.close()
	}
}

func (w *wizard) start(kind operation, confirmed bool) {
	if !w.layoutOK {
		return
	}
	httpApproved := w.flow.httpApproved()
	if !w.flow.begin(kind, confirmed) {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel, w.done = cancel, make(chan error, 1)
	w.progress = "Starting the confirmed operation..."
	// Render before starting a privileged operation. UI creation failure is
	// inert, with no hook invocation and no claim that setup was attempted.
	if !w.render() {
		cancel()
		w.flow.complete(ErrUI)
		w.flow.result = ErrUI
		w.close()
		return
	}
	// Timer polling is a completion safety net if PostMessage cannot enqueue an
	// update. Starting it before the hook makes a timer failure nonmutating.
	if timer, _, _ := setTimer.Call(w.window, operationTimer, 250, 0); timer == 0 {
		cancel()
		w.flow.complete(ErrUI)
		w.flow.result = ErrUI
		w.close()
		return
	}
	setFocus.Call(w.controls[idCancel])
	data := append([]byte(nil), w.flow.bootstrap...)
	go func() {
		var err error
		if kind == opInstall {
			err = w.hooks.Install(ctx, data, httpApproved, w.reportProgress)
		} else {
			err = w.hooks.Uninstall(ctx, w.reportProgress)
		}
		cancel()
		w.done <- err
		postMessage.Call(w.window, wmUpdate, 0, 0)
	}()
}

func (w *wizard) reportProgress(status string) {
	if !publicLine(status, 512) {
		return
	}
	w.progressMu.Lock()
	w.latestProgress = status
	w.progressMu.Unlock()
	postMessage.Call(w.window, wmUpdate, 0, 0)
}

func (w *wizard) receiveUpdates() {
	if !w.flow.busy {
		return
	}
	w.progressMu.Lock()
	latest := w.latestProgress
	w.progressMu.Unlock()
	if latest != "" {
		w.progress = latest
	}
	select {
	case err := <-w.done:
		killTimer.Call(w.window, operationTimer)
		// Receiving completion synchronizes with every earlier progress write.
		// Refresh after that receive so a final diagnostic cannot be lost.
		w.progressMu.Lock()
		latest = w.latestProgress
		w.progressMu.Unlock()
		if latest != "" {
			w.progress = latest
		}
		w.flow.complete(err)
		if err != nil {
			w.progress += "\r\n\r\n" + interruptedMessage
		} else if w.flow.operation == opInstall {
			w.progress += "\r\n\r\n" + installCompleted
		} else {
			w.progress += "\r\n\r\n" + uninstallCompleted
		}
		setText(w.controls[idCancel], "&Close")
		enable(w.controls[idCancel], true)
		setText(w.note, "The operation has returned. No retry or automatic recovery will run from this wizard.")
		setFocus.Call(w.controls[idCancel])
	default:
	}
	setText(w.content, w.progress)
}

func (w *wizard) close() {
	if w.flow.requestClose() {
		destroyWindow.Call(w.window)
		return
	}
	w.cancel()
	setText(w.note, "Cancellation requested. Waiting for the active operation to return and release its console. Files, identity and state will be retained.")
	setText(w.controls[idCancel], "Stopping...")
	enable(w.controls[idCancel], false)
}

func (w *wizard) alert(s string) {
	messageBox.Call(w.window, uintptr(unsafe.Pointer(utf16(s))), uintptr(unsafe.Pointer(utf16("Tracebolt Setup"))), 0x30)
}

func setText(h uintptr, s string) {
	if h != 0 {
		setWindowText.Call(h, uintptr(unsafe.Pointer(utf16(s))))
	}
}
func enable(h uintptr, on bool) {
	var v uintptr
	if on {
		v = 1
	}
	if h != 0 {
		enableWindow.Call(h, v)
	}
}
func checked(h uintptr) bool { n, _, _ := sendMessage.Call(h, bmGetCheck, 0, 0); return n == 1 }

func chooseFile(owner uintptr) (path string, canceled bool, err error) {
	buf := make([]uint16, 32768)
	// StringToUTF16 rejects embedded NUL; a common-dialog filter deliberately
	// uses them, so construct its UTF-16 sequence directly from fixed ASCII.
	filter := make([]uint16, 0, 80)
	for _, r := range "Public bootstrap JSON (*.json)\x00*.json\x00All files (*.*)\x00*.*\x00\x00" {
		filter = append(filter, uint16(r))
	}
	of := openFileName{Owner: owner, Filter: &filter[0], FilterIndex: 1, File: &buf[0], MaxFile: uint32(len(buf)),
		Title: utf16("Choose public bootstrap only (never the invitation)"),
		Flags: 0x00080000 | 0x00001000 | 0x00000800 | 0x00000004 | 0x00000008 | 0x02000000 | 0x00100000 | 0x00020000}
	of.Size = uint32(unsafe.Sizeof(of))
	ok, _, _ := getOpenFileName.Call(uintptr(unsafe.Pointer(&of)))
	runtime.KeepAlive(filter)
	runtime.KeepAlive(buf)
	if ok == 0 {
		code, _, _ := commDlgExtendedError.Call()
		if code == 0 {
			return "", true, nil
		}
		return "", false, ErrUI
	}
	return windows.UTF16ToString(buf), false, nil
}

func validPublicPath(path string) bool {
	// Drive-qualified local paths only: no UNC, device names, relative paths,
	// alternate streams, or namespace prefixes. Do this before os.Lstat.
	if len(path) < 4 || !((path[0] >= 'a' && path[0] <= 'z') || (path[0] >= 'A' && path[0] <= 'Z')) ||
		path[1] != ':' || path[2] != '\\' || strings.ContainsAny(path[2:], ":/\x00") || filepath.Clean(path) != path {
		return false
	}
	root := utf16(path[:3])
	drive, _, _ := getDriveType.Call(uintptr(unsafe.Pointer(root)))
	return drive == 2 || drive == 3 // removable or fixed local disk, never mapped network
}

func openPublicFile(path string) (*os.File, error) {
	if !validPublicPath(path) {
		return nil, ErrConfiguration
	}
	// Hold every ancestor against rename while opening the final file and
	// reject reparse points at every level, before traversing them. This avoids
	// following a local junction into a network share or a replaced directory.
	var ancestors []windows.Handle
	defer func() {
		for _, h := range ancestors {
			windows.CloseHandle(h)
		}
	}()
	parts := strings.Split(path[3:], "\\")
	current := path[:3]
	for i, part := range parts {
		if i > 0 {
			current += "\\"
		}
		current += part
		access := uint32(windows.FILE_READ_ATTRIBUTES)
		share := uint32(windows.FILE_SHARE_READ)
		flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT | windows.FILE_FLAG_BACKUP_SEMANTICS)
		if i == len(parts)-1 {
			access = windows.GENERIC_READ
			share = windows.FILE_SHARE_READ
		}
		h, e := windows.CreateFile(utf16(current), access, share, nil, windows.OPEN_EXISTING, flags, 0)
		if e != nil {
			return nil, ErrConfiguration
		}
		var info windows.ByHandleFileInformation
		e = windows.GetFileInformationByHandle(h, &info)
		if e != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			windows.CloseHandle(h)
			return nil, ErrConfiguration
		}
		if i == len(parts)-1 {
			kind, e := windows.GetFileType(h)
			if e != nil || kind != windows.FILE_TYPE_DISK || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
				windows.CloseHandle(h)
				return nil, ErrConfiguration
			}
			return os.NewFile(uintptr(h), path), nil
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			windows.CloseHandle(h)
			return nil, ErrConfiguration
		}
		ancestors = append(ancestors, h)
	}
	return nil, ErrConfiguration
}
