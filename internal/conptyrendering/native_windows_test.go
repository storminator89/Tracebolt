//go:build windows

package conptyrendering

import (
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const publicChild = "--conpty-public-lines-only"
const publicConsoleChild = "--conpty-public-conout-only"

// The only child entry exits before the test runner. It accepts no input and
// writes these fixed public trust lines and non-newline prompt. It does not run commands or spawn children.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && (os.Args[1] == publicChild || os.Args[1] == publicConsoleChild) {
		os.Exit(runPublicChild(os.Args[1] == publicConsoleChild))
	}
	os.Exit(m.Run())
}
func publicHandleType(handle windows.Handle) (character, pipe, console bool) {
	kind, err := windows.GetFileType(handle)
	var mode uint32
	return err == nil && kind == windows.FILE_TYPE_CHAR, err == nil && kind == windows.FILE_TYPE_PIPE, windows.GetConsoleMode(handle, &mode) == nil
}
func runPublicChild(explicit bool) (code int) {
	var facts publicHandleFacts
	facts.stdoutChar, facts.stdoutPipe, facts.stdoutConsole = publicHandleType(windows.Handle(os.Stdout.Fd()))
	facts.stderrChar, facts.stderrPipe, facts.stderrConsole = publicHandleType(windows.Handle(os.Stderr.Fd()))
	out, promptOut := os.Stdout, os.Stderr
	if explicit {
		name, err := windows.UTF16PtrFromString("CONOUT$")
		if err != nil {
			return 2
		}
		handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
		if err != nil {
			return 2
		}
		character, pipe, console := publicHandleType(handle)
		if !character || pipe || !console {
			windows.CloseHandle(handle)
			return 2
		}
		file := os.NewFile(uintptr(handle), "<public console output>")
		if file == nil {
			windows.CloseHandle(handle)
			return 2
		}
		defer func() {
			if file.Close() != nil {
				code = 2
			}
		}()
		out, promptOut = file, file
	}
	n, err := out.Write([]byte(publicTrustLines))
	if err != nil || n != len(publicTrustLines) {
		return 2
	}
	n, err = promptOut.Write([]byte(publicPrompt))
	if err != nil || n != len(publicPrompt) {
		return 2
	}
	// No input is read or sent. Keep the same prompt live in each owned child.
	time.Sleep(2 * time.Second)
	return facts.code()
}

func TestNativePublicRendering(t *testing.T) {
	deadline := time.Now().Add(20 * time.Second)
	result, reason := observeNative(false, deadline)
	if reason != "none" {
		t.Fatal(reason)
	}
	// Only finite classifications reach test output. No bytes or parameters do.
	t.Logf("cursor_position=%t clear=%t cursor_visibility=%t presentation=%t title=%t unknown=%t overflow=%t incomplete=%t win32_input_enable=%t win32_input_disable=%t focus_reporting_enable=%t focus_reporting_disable=%t residual_unknown=%t first_residual_kind=%s live_output=%t public_trust=%t exact_prompt=%t prompt_without_final_space=%t", result.CursorPosition, result.Clear, result.CursorVisibility, result.Presentation, result.Title, result.Unknown, result.Overflow, result.Incomplete, result.Win32InputEnable, result.Win32InputDisable, result.FocusReportingEnable, result.FocusReportingDisable, result.ResidualUnknown, result.FirstResidualKind, result.LiveOutput, result.PublicTrust, result.ExactPrompt, result.PromptWithoutFinalSpace)
	if result.Overflow || result.Incomplete {
		t.Fatal("rendering_bound_or_incomplete")
	}
	explicit, reason := observeNative(true, deadline)
	if reason != "none" {
		t.Fatal(reason)
	}
	if explicit.Overflow || explicit.Incomplete {
		t.Fatal("rendering_bound_or_incomplete")
	}
	f := result.handles
	t.Logf("stdout_char=%t stdout_pipe=%t stdout_console=%t stderr_char=%t stderr_pipe=%t stderr_console=%t conout_console=true conout_live_output=%t conout_public_trust=%t conout_exact_prompt=%t conout_prompt_without_final_space=%t conout_overflow=%t conout_incomplete=%t conout_residual_unknown=%t conout_first_residual_kind=%s", f.stdoutChar, f.stdoutPipe, f.stdoutConsole, f.stderrChar, f.stderrPipe, f.stderrConsole, explicit.LiveOutput, explicit.PublicTrust, explicit.ExactPrompt, explicit.PromptWithoutFinalSpace, explicit.Overflow, explicit.Incomplete, explicit.ResidualUnknown, explicit.FirstResidualKind)
	// Unknown is a useful observation, not acceptance or permission to relax any
	// production guard. The probe deliberately does not apply that guard.
}

func observeNative(explicit bool, deadline time.Time) (result Summary, reason string) {
	var empty Summary
	if !time.Now().Before(deadline) {
		return empty, "deadline"
	}
	var inputR, inputW, outputR, outputW windows.Handle
	if windows.CreatePipe(&inputR, &inputW, nil, 0) != nil {
		return empty, "input_pipe"
	}
	defer func() {
		if inputR != 0 {
			windows.CloseHandle(inputR)
		}
	}()
	defer windows.CloseHandle(inputW)
	if windows.CreatePipe(&outputR, &outputW, nil, 0) != nil {
		return empty, "output_pipe"
	}
	defer func() {
		if outputR != 0 {
			windows.CloseHandle(outputR)
		}
	}()
	defer func() {
		if outputW != 0 {
			windows.CloseHandle(outputW)
		}
	}()
	var pc windows.Handle
	if windows.CreatePseudoConsole(windows.Coord{X: 120, Y: 30}, inputR, outputW, 0, &pc) != nil {
		return empty, "conpty_create"
	}
	// Closing after output is closed is safe on early setup errors, including
	// older Windows where ClosePseudoConsole waits for the final frame drain.
	closeStarted := false
	defer func() {
		if !closeStarted {
			windows.CloseHandle(outputR)
			outputR = 0
			closed := make(chan struct{})
			go func() { windows.ClosePseudoConsole(pc); close(closed) }()
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				reason = "conpty_close_deadline"
			}
		}
	}()
	attrs, e := windows.NewProcThreadAttributeList(1)
	if e != nil {
		return empty, "attributes_create"
	}
	defer attrs.Delete()
	// This attribute takes HPCON by value, unlike pointer-valued attributes.
	// Use the documented syscall shape rather than converting a handle into a Go pointer.
	update := windows.NewLazySystemDLL("kernel32.dll").NewProc("UpdateProcThreadAttribute")
	ok, _, _ := update.Call(uintptr(unsafe.Pointer(attrs.List())), 0, windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, uintptr(pc), unsafe.Sizeof(pc), 0, 0)
	if ok == 0 {
		return empty, "attributes_update"
	}
	exe, e := os.Executable()
	if e != nil {
		return empty, "executable"
	}
	app, e := windows.UTF16PtrFromString(exe)
	if e != nil {
		return empty, "executable"
	}
	childArg := publicChild
	if explicit {
		childArg = publicConsoleChild
	}
	command, e := windows.UTF16PtrFromString(syscall.EscapeArg(exe) + " " + childArg)
	if e != nil {
		return empty, "command"
	}
	si := windows.StartupInfoEx{StartupInfo: windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{}))}, ProcThreadAttributeList: attrs.List()}
	var pi windows.ProcessInformation
	if windows.CreateProcess(app, command, nil, nil, false, windows.EXTENDED_STARTUPINFO_PRESENT, nil, nil, &si.StartupInfo, &pi) != nil {
		return empty, "child_create"
	}
	runtime.KeepAlive(attrs)
	windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)
	windows.CloseHandle(outputW)
	outputW = 0
	// ConPTY owns duplicates; release these promptly to allow EOF detection.
	windows.CloseHandle(inputR)
	inputR = 0

	closeDone := make(chan struct{})
	startClose := func() {
		if !closeStarted {
			closeStarted = true
			go func() { windows.ClosePseudoConsole(pc); close(closeDone) }()
		}
	}
	reaped := false
	defer func() {
		if !reaped {
			if windows.TerminateProcess(pi.Process, 3) != nil {
				reason = "child_terminate"
			}
			status, err := windows.WaitForSingleObject(pi.Process, 5000)
			if err != nil || status != windows.WAIT_OBJECT_0 {
				reason = "child_reap"
			}
		}
		// Broken output releases a potential close wait on older Windows.
		if outputR != 0 {
			windows.CloseHandle(outputR)
			outputR = 0
		}
		startClose()
		select {
		case <-closeDone:
		case <-time.After(5 * time.Second):
			reason = "conpty_close_deadline"
		}
	}()
	peek := windows.NewLazySystemDLL("kernel32.dll").NewProc("PeekNamedPipe")
	var observer Observer
	var liveOutput, publicTrust, exactPrompt, omittedSpace bool
	defer func() { observer.reset(); clear(observer.public.line[:]) }()
	var buffer [1024]byte
	defer clear(buffer[:])
	var handles publicHandleFacts
	sawOutput := false
	eof := false
	for time.Now().Before(deadline) {
		if !reaped {
			status, err := windows.WaitForSingleObject(pi.Process, 0)
			if err != nil {
				return empty, "child_wait"
			}
			if status == windows.WAIT_OBJECT_0 {
				reaped = true
				var code uint32
				if windows.GetExitCodeProcess(pi.Process, &code) != nil {
					return empty, "child_exit"
				}
				var valid bool
				handles, valid = decodePublicHandleFacts(code)
				if !valid {
					return empty, "child_exit"
				}
				startClose()
			}
		}
		if !eof {
			var available uint32
			ok, _, err := peek.Call(uintptr(outputR), 0, 0, 0, uintptr(unsafe.Pointer(&available)), 0)
			if ok == 0 {
				if err != windows.ERROR_BROKEN_PIPE {
					return empty, "output_peek"
				}
				eof = true
			} else if available > 0 {
				n := min(available, uint32(len(buffer)))
				var read uint32
				if windows.ReadFile(outputR, buffer[:n], &read, nil) != nil {
					return empty, "output_read"
				}
				if read == 0 {
					return empty, "output_empty_read"
				}
				sawOutput = true
				observer.Feed(buffer[:read])
				// Freeze the last pipe-read snapshot observed while the child
				// was still running. Shutdown-only rendering cannot satisfy it.
				status, waitErr := windows.WaitForSingleObject(pi.Process, 0)
				if waitErr != nil {
					return empty, "child_wait"
				}
				if status == uint32(windows.WAIT_TIMEOUT) {
					liveOutput = true
					publicTrust, exactPrompt, omittedSpace = observer.liveTextSummary()
				}
				clear(buffer[:])
			}
		}
		if reaped && eof {
			select {
			case <-closeDone:
				if !sawOutput {
					return empty, "output_missing"
				}
				result = observer.Finish()
				result.handles = handles
				result.LiveOutput, result.PublicTrust = liveOutput, publicTrust
				result.ExactPrompt, result.PromptWithoutFinalSpace = exactPrompt, omittedSpace
				return result, "none"
			default:
			}
		}
		time.Sleep(time.Millisecond)
	}
	return empty, "deadline"
}
