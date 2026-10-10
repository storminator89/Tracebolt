//go:build windows && tracebolt_setup_native

package main

// Real HWND/console driver for the packaged, unmodified zero-argument Setup.exe.
// It has no coordinator hook, test-only installer flag, or silent install path.
import (
	"bytes"
	"context"
	"golang.org/x/sys/windows"
	"localrmm/internal/windowsacceptance/setupgate"
	"localrmm/internal/windowsservice"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var setupUser32 = windows.NewLazySystemDLL("user32.dll")
var setupKernel32 = windows.NewLazySystemDLL("kernel32.dll")

// Preserve pointer lifetime through this wrapper, not just LazyProc.Call.
//
//go:uintptrescapes
func setupCall(name string, args ...uintptr) uintptr {
	r, _, _ := setupUser32.NewProc(name).Call(args...)
	return r
}

//go:uintptrescapes
func setupKernel(name string, args ...uintptr) uintptr {
	r, _, _ := setupKernel32.NewProc(name).Call(args...)
	return r
}
func setupUTF(s string) *uint16 { return windows.StringToUTF16Ptr(s) }
func setupText(hwnd uintptr) string {
	if hwnd == 0 {
		return ""
	}
	buf := make([]uint16, 32<<10)
	n, e := setupSend(hwnd, 0x000d, uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])))
	if e != nil || n >= uintptr(len(buf)-1) {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}
func setupControl(hwnd uintptr, id int) uintptr { return setupCall("GetDlgItem", hwnd, uintptr(id)) }
func setupEnabled(hwnd uintptr) bool            { return hwnd != 0 && setupCall("IsWindowEnabled", hwnd) != 0 }

// WM_GETTEXT/WM_SETTEXT carry pointers through this additional wrapper.
//
//go:uintptrescapes
func setupSend(hwnd uintptr, msg uint32, wparam, lparam uintptr) (uintptr, error) {
	var result uintptr
	r := setupCall("SendMessageTimeoutW", hwnd, uintptr(msg), wparam, lparam, 2, 2000, uintptr(unsafe.Pointer(&result)))
	if r == 0 {
		return 0, setupgate.ErrGuard
	}
	return result, nil
}

type setupRect struct{ Left, Top, Right, Bottom int32 }

func setupContains(outer, inner setupRect) bool {
	return inner.Right > inner.Left && inner.Bottom > inner.Top && outer.Left <= inner.Left && outer.Top <= inner.Top && outer.Right >= inner.Right && outer.Bottom >= inner.Bottom
}
func setupVisibleControl(hwnd uintptr) (visible bool) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// Match the real wizard's per-monitor-V2 coordinate space for all calls.
	previous := setupCall("SetThreadDpiAwarenessContext", ^uintptr(3))
	if previous == 0 {
		return false
	}
	defer func() {
		if setupCall("SetThreadDpiAwarenessContext", previous) == 0 {
			visible = false
		}
	}()

	if hwnd == 0 || setupCall("IsWindowVisible", hwnd) == 0 {
		return false
	}
	root := setupCall("GetAncestor", hwnd, 2)
	if root == 0 || setupCall("IsIconic", root) != 0 {
		return false
	}
	var control, client setupRect
	if setupCall("GetWindowRect", hwnd, uintptr(unsafe.Pointer(&control))) == 0 || setupCall("GetClientRect", root, uintptr(unsafe.Pointer(&client))) == 0 {
		return false
	}
	// Explicit BOOL-returning corner conversions avoid confusing a valid zero
	// displacement with a failed MapWindowPoints call.
	if setupCall("ClientToScreen", root, uintptr(unsafe.Pointer(&client.Left))) == 0 || setupCall("ClientToScreen", root, uintptr(unsafe.Pointer(&client.Right))) == 0 {
		return false
	}

	monitor := setupCall("MonitorFromWindow", root, 2)
	info := struct {
		Size          uint32
		Monitor, Work setupRect
		Flags         uint32
	}{}
	info.Size = uint32(unsafe.Sizeof(info))
	if monitor == 0 || setupCall("GetMonitorInfoW", monitor, uintptr(unsafe.Pointer(&info))) == 0 {
		return false
	}
	return setupContains(client, control) && setupContains(info.Work, control)
}

func setupClick(hwnd uintptr, id int) error {
	h := setupControl(hwnd, id)
	if !setupEnabled(h) || !setupVisibleControl(h) {
		return setupgate.ErrGuard
	}
	if setupCall("PostMessageW", h, 0x00f5, 0, 0) == 0 {
		return setupgate.ErrGuard
	}
	return nil
}
func setupAwait(ctx context.Context, timeout time.Duration, predicate func() bool) error {
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		if c.Err() != nil {
			return setupgate.ErrGuard
		}
		if predicate() {
			return nil
		}
		select {
		case <-c.Done():
			return setupgate.ErrGuard
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func setupWindow(pid uint32, class string) uintptr {
	var found uintptr
	callback := syscall.NewCallback(func(h, _ uintptr) uintptr {
		var p uint32
		setupCall("GetWindowThreadProcessId", h, uintptr(unsafe.Pointer(&p)))
		if p != pid {
			return 1
		}
		var b [128]uint16
		setupCall("GetClassNameW", h, uintptr(unsafe.Pointer(&b[0])), 128)
		if windows.UTF16ToString(b[:]) == class && setupCall("IsWindowVisible", h) != 0 {
			if found != 0 {
				found = 0
				return 0
			}
			found = h
		}
		return 1
	})
	setupCall("EnumWindows", callback, 0)
	return found
}
func setupInteractiveDesktop() bool {
	var session uint32
	if setupKernel("ProcessIdToSessionId", uintptr(os.Getpid()), uintptr(unsafe.Pointer(&session))) == 0 || session == 0 {
		return false
	}
	desktop := setupCall("OpenInputDesktop", 0, 0, 0x0001)
	if desktop == 0 {
		return false
	}
	defer setupCall("CloseDesktop", desktop)
	var flags struct{ Inherit, Reserved, Flags uint32 }
	var needed uint32
	station := setupCall("GetProcessWindowStation")
	return station != 0 && setupCall("GetUserObjectInformationW", station, 1, uintptr(unsafe.Pointer(&flags)), unsafe.Sizeof(flags), uintptr(unsafe.Pointer(&needed))) != 0 && flags.Flags&1 != 0
}

type setupGUI struct {
	process, job windows.Handle
	pid          uint32
	window       uintptr
	closed       bool
}

func setupLaunch(ctx context.Context, path string) (*setupGUI, error) {
	if ctx.Err() != nil || !filepath.IsAbs(path) {
		return nil, setupgate.ErrGuard
	}
	job, e := windows.CreateJobObject(nil, nil)
	if e != nil {
		return nil, setupgate.ErrGuard
	}
	ok := false
	defer func() {
		if !ok {
			windows.CloseHandle(job)
		}
	}()
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, e = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); e != nil {
		return nil, setupgate.ErrGuard
	}
	// Only ordinary OS environment reaches Setup, never approval tokens, CI secrets,
	// invitation bytes or any alternate destination/path override.
	env := []string{}
	for _, key := range []string{"SystemRoot", "TEMP", "TMP"} {
		if value := os.Getenv(key); value != "" {
			env = append(env, key+"="+value)
		}
	}
	system, e := windows.GetSystemWindowsDirectory()
	if e != nil {
		return nil, setupgate.ErrGuard
	}
	drive, e := windowsservice.SystemDriveFromWindowsDirectory(system)
	if e != nil {
		return nil, e
	}
	env = append(env, "SystemDrive="+drive)
	sort.Strings(env)
	block := []uint16{}
	for _, value := range env {
		block = append(block, windows.StringToUTF16(value)...)
	}
	block = append(block, 0)
	si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Desktop: setupUTF(`winsta0\default`)}
	var pi windows.ProcessInformation
	command := windows.StringToUTF16(syscall.EscapeArg(path))
	if windows.CreateProcess(setupUTF(path), &command[0], nil, nil, false, windows.CREATE_SUSPENDED|windows.CREATE_UNICODE_ENVIRONMENT, &block[0], setupUTF(filepath.Dir(path)), &si, &pi) != nil {
		return nil, setupgate.ErrGuard
	}
	defer windows.CloseHandle(pi.Thread)
	if windows.AssignProcessToJobObject(job, pi.Process) != nil {
		windows.TerminateProcess(pi.Process, 1)
		windows.WaitForSingleObject(pi.Process, 5000)
		windows.CloseHandle(pi.Process)
		return nil, setupgate.ErrGuard
	}
	g := &setupGUI{process: pi.Process, job: job, pid: pi.ProcessId}
	ok = true
	if _, e = windows.ResumeThread(pi.Thread); e != nil {
		g.dispose()
		return nil, setupgate.ErrGuard
	}
	if setupAwait(ctx, 15*time.Second, func() bool { g.window = setupWindow(g.pid, "TraceboltFreshSetupWizard"); return g.window != 0 }) != nil {
		g.dispose()
		return nil, setupgate.ErrGuard
	}
	return g, nil
}
func (g *setupGUI) dispose() {
	if g == nil || g.closed {
		return
	}
	g.closed = true
	windows.TerminateJobObject(g.job, 1)
	windows.WaitForSingleObject(g.process, 5000)
	windows.CloseHandle(g.process)
	windows.CloseHandle(g.job)
}
func (g *setupGUI) exit(ctx context.Context, expected uint32) error {
	if setupClick(g.window, 2) != nil {
		return setupgate.ErrGuard
	}
	return g.waitExit(ctx, expected)
}
func (g *setupGUI) waitExit(ctx context.Context, expected uint32) error {
	if setupAwait(ctx, 10*time.Second, func() bool {
		s, e := windows.WaitForSingleObject(g.process, 0)
		return e == nil && s == windows.WAIT_OBJECT_0
	}) != nil {
		return setupgate.ErrGuard
	}
	var code uint32
	if windows.GetExitCodeProcess(g.process, &code) != nil || code != expected {
		return setupgate.ErrGuard
	}
	windows.CloseHandle(g.process)
	windows.CloseHandle(g.job)
	g.closed = true
	return nil
}
func (g *setupGUI) choose(ctx context.Context, path string) error {
	return g.chooseObserved(ctx, path, func(string) {})
}
func (g *setupGUI) chooseObserved(ctx context.Context, path string, stage func(string)) error {
	stage("chooser-click")
	if setupClick(g.window, 102) != nil {
		return setupgate.ErrGuard
	}
	var dialog uintptr
	stage("chooser-dialog")
	if setupAwait(ctx, 10*time.Second, func() bool { dialog = setupWindow(g.pid, "#32770"); return dialog != 0 }) != nil {
		return setupgate.ErrGuard
	}
	stage("chooser-title")
	if setupText(dialog) != "Choose public bootstrap only (never the invitation)" {
		return setupgate.ErrGuard
	}
	stage("chooser-edit")
	combo := setupControl(dialog, 1148)
	edit := setupControl(combo, 1001)
	if edit == 0 {
		edit = combo
	}
	if edit == 0 {
		return setupgate.ErrGuard
	}
	stage("chooser-set-text")
	if _, e := setupSend(edit, 0x000c, 0, uintptr(unsafe.Pointer(setupUTF(path)))); e != nil {
		return e
	}
	stage("chooser-open")
	if setupClick(dialog, 1) != nil {
		return setupgate.ErrGuard
	}
	stage("chooser-validated")
	return setupAwait(ctx, 10*time.Second, func() bool { return setupWindow(g.pid, "#32770") == 0 && setupEnabled(setupControl(g.window, 1)) })
}
func (g *setupGUI) consent(ctx context.Context, http bool) error {
	return g.consentObserved(ctx, http, func(string) {})
}
func (g *setupGUI) consentObserved(ctx context.Context, http bool, stage func(string)) error {
	reviewWait := 5 * time.Second
	return setupgate.CheckConsent(stage, http, setupgate.ConsentSteps{
		Next: func() error { return setupClick(g.window, 1) },
		WaitReview: func() error {
			timeout := reviewWait
			reviewWait = 3 * time.Second
			return setupAwait(ctx, timeout, func() bool { return setupControl(g.window, 104) != 0 })
		},
		NextEnabled: func() bool { return setupEnabled(setupControl(g.window, 1)) },
		Present:     func(id int) bool { return setupControl(g.window, id) != 0 },
		Unchecked: func(id int) error {
			v, e := setupSend(setupControl(g.window, id), 0x00f0, 0, 0)
			if e != nil || v != 0 {
				return setupgate.ErrGuard
			}
			return nil
		},
		ClickChecked: func(id int) error {
			if setupClick(g.window, id) != nil {
				return setupgate.ErrGuard
			}
			return setupAwait(ctx, 2*time.Second, func() bool { v, e := setupSend(setupControl(g.window, id), 0x00f0, 0, 0); return e == nil && v == 1 })
		},
		WaitEnabled: func() error {
			return setupAwait(ctx, 3*time.Second, func() bool { return setupEnabled(setupControl(g.window, 1)) })
		},
		Back: func() error { return setupClick(g.window, 101) },
		WaitInput: func() error {
			return setupAwait(ctx, 3*time.Second, func() bool { return setupControl(g.window, 203) != 0 && setupEnabled(setupControl(g.window, 1)) })
		},
	})
}
func (g *setupGUI) finished(ctx context.Context) error {
	return setupAwait(ctx, 45*time.Second, func() bool {
		return strings.ReplaceAll(setupText(setupControl(g.window, 2)), "&", "") == "Close" && setupEnabled(setupControl(g.window, 2))
	})
}
func (g *setupGUI) uninstall(ctx context.Context, accept bool) error {
	if setupClick(g.window, 103) != nil {
		return setupgate.ErrGuard
	}
	var d uintptr
	if setupAwait(ctx, 5*time.Second, func() bool { d = setupWindow(g.pid, "#32770"); return d != 0 }) != nil {
		return setupgate.ErrGuard
	}
	if setupText(d) != "Confirm service-only uninstall" {
		return setupgate.ErrGuard
	}
	def, e := setupSend(d, 0x0400, 0, 0)
	if e != nil || def != 0x534b0007 {
		return setupgate.ErrGuard
	}
	id := 7
	if accept {
		id = 6
	}
	return setupClick(d, id)
}
func (g *setupGUI) operationText() string { return setupText(setupControl(g.window, 205)) }

// Attach only while inspecting or supplying actual console events. In particular
// do not keep the console alive on behalf of the GUI when its worker frees it.
type setupConsoleInfo struct {
	Size, Cursor struct{ X, Y int16 }
	Attributes   uint16
	Window       struct{ Left, Top, Right, Bottom int16 }
	Maximum      struct{ X, Y int16 }
}
type setupInputRecord struct {
	Type, Padding uint16
	Data          [4]uint32
}

func setupConsole(pid uint32, secret []byte, input []byte, enter bool) (text string, hidden bool, err error) {
	setupKernel("FreeConsole")
	if setupKernel("AttachConsole", uintptr(pid)) == 0 {
		return "", false, setupgate.ErrGuard
	}
	defer setupKernel("FreeConsole")
	in, e := windows.CreateFile(setupUTF("CONIN$"), windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if e != nil {
		return "", false, setupgate.ErrGuard
	}
	defer windows.CloseHandle(in)
	out, e := windows.CreateFile(setupUTF("CONOUT$"), windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if e != nil {
		return "", false, setupgate.ErrGuard
	}
	defer windows.CloseHandle(out)
	var mode uint32
	if windows.GetConsoleMode(in, &mode) != nil {
		return "", false, setupgate.ErrGuard
	}
	hidden = mode&4 == 0
	var info setupConsoleInfo
	if setupKernel("GetConsoleScreenBufferInfo", uintptr(out), uintptr(unsafe.Pointer(&info))) == 0 || info.Size.X <= 0 || info.Cursor.Y < 0 {
		return "", false, setupgate.ErrGuard
	}
	n := int(info.Size.X) * (int(info.Cursor.Y) + 1)
	if n > 64<<10 {
		return "", false, setupgate.ErrGuard
	}
	buf := make([]uint16, n)
	defer clear(buf)
	var read uint32
	if setupKernel("ReadConsoleOutputCharacterW", uintptr(out), uintptr(unsafe.Pointer(&buf[0])), uintptr(n), 0, uintptr(unsafe.Pointer(&read))) == 0 || read != uint32(n) {
		return "", false, setupgate.ErrGuard
	}
	var b strings.Builder
	for i := 0; i < n; i += int(info.Size.X) {
		b.WriteString(strings.TrimRight(windows.UTF16ToString(buf[i:i+int(info.Size.X)]), " "))
		b.WriteByte('\n')
	}
	text = b.String()
	// Memory-only inspection of the full bounded screen; never print on failure.
	compact := []byte(strings.Join(strings.Fields(text), ""))
	defer clear(compact)
	if len(secret) > 0 && (bytes.Contains(compact, secret) || len(secret) >= 8 && bytes.Contains(compact, secret[:8])) {
		return "", false, setupgate.ErrGuard
	}
	if len(input) > 0 {
		if !hidden || len(input) > 43 {
			return "", false, setupgate.ErrGuard
		}
		events := make([]setupInputRecord, 0, len(input)+1)
		defer clear(events)
		for _, c := range input {
			events = append(events, setupInputRecord{Type: 1, Data: [4]uint32{1, 1, uint32(c) << 16, 0}})
		}
		if enter {
			events = append(events, setupInputRecord{Type: 1, Data: [4]uint32{1, 1 | 0x0d<<16, '\r' << 16, 0}})
		}
		var written uint32
		if setupKernel("WriteConsoleInputW", uintptr(in), uintptr(unsafe.Pointer(&events[0])), uintptr(len(events)), uintptr(unsafe.Pointer(&written))) == 0 || written != uint32(len(events)) {
			return "", false, setupgate.ErrGuard
		}
	}
	return text, hidden, nil
}
func setupConsoleGone(pid uint32) bool {
	setupKernel("FreeConsole")
	attached := setupKernel("AttachConsole", uintptr(pid))
	if attached != 0 {
		setupKernel("FreeConsole")
		return false
	}
	return true
}
