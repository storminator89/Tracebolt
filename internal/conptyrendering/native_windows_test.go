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

// The only child entry exits before the test runner. It accepts no input and
// writes these fixed public lines. It does not run commands or spawn children.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == publicChild {
		const lines = "TRACEBOLT PUBLIC RENDER ONE\r\nTRACEBOLT PUBLIC RENDER TWO\r\n"
		n, e := os.Stdout.Write([]byte(lines))
		if e != nil || n != len(lines) {
			os.Exit(2)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestNativePublicRendering(t *testing.T) {
	result, reason := observeNative()
	if reason != "none" {
		t.Fatal(reason)
	}
	// Only finite classifications reach test output. No bytes or parameters do.
	t.Logf("cursor_position=%t clear=%t cursor_visibility=%t presentation=%t title=%t unknown=%t overflow=%t incomplete=%t", result.CursorPosition, result.Clear, result.CursorVisibility, result.Presentation, result.Title, result.Unknown, result.Overflow, result.Incomplete)
	if result.Overflow || result.Incomplete {
		t.Fatal("rendering_bound_or_incomplete")
	}
	// Unknown is a useful observation, not acceptance or permission to relax any
	// production guard. The probe deliberately does not apply that guard.
}

func observeNative() (result Summary, reason string) {
	var empty Summary
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
	command, e := windows.UTF16PtrFromString(syscall.EscapeArg(exe) + " " + publicChild)
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
	defer observer.reset()
	var buffer [1024]byte
	defer clear(buffer[:])
	deadline := time.Now().Add(20 * time.Second)
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
				if windows.GetExitCodeProcess(pi.Process, &code) != nil || code != 0 {
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
				clear(buffer[:])
			}
		}
		if reaped && eof {
			select {
			case <-closeDone:
				if !sawOutput {
					return empty, "output_missing"
				}
				return observer.Finish(), "none"
			default:
			}
		}
		time.Sleep(time.Millisecond)
	}
	return empty, "deadline"
}
