//go:build windows

package windowsconsole

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const consoleReadNowait = 0x0002

var readConsoleInputExW = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReadConsoleInputExW")

type nativeConsole struct{ handle windows.Handle }

func openConsole() (console, error) {
	// Resolve the fixed system API before opening or changing console modes.
	// NOWAIT avoids the readiness-probe/read race of ReadConsoleInputW, which
	// can otherwise block indefinitely when another reader consumes the event.
	// https://learn.microsoft.com/en-us/windows/console/readconsoleinputex
	if readConsoleInputExW.Find() != nil {
		return nil, ErrInput
	}
	name, err := windows.UTF16PtrFromString("CONIN$")
	if err != nil {
		return nil, ErrInput
	}
	// NULL security attributes make the handle noninheritable. No caller path,
	// standard handle, remote device, process or command is accepted.
	// https://learn.microsoft.com/en-us/windows/console/console-handles
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, ErrInput
	}
	kind, err := windows.GetFileType(handle)
	if err != nil || kind != windows.FILE_TYPE_CHAR {
		_ = windows.CloseHandle(handle)
		return nil, ErrInput
	}
	// A successful GetConsoleMode in readWithConsole is additionally required;
	// FILE_TYPE_CHAR alone would not establish a real console input handle.
	return &nativeConsole{handle: handle}, nil
}

func (c *nativeConsole) mode() (uint32, error) {
	var mode uint32
	if windows.GetConsoleMode(c.handle, &mode) != nil {
		return 0, ErrInput
	}
	return mode, nil
}

func (c *nativeConsole) setMode(mode uint32) error {
	if windows.SetConsoleMode(c.handle, mode) != nil {
		return ErrInput
	}
	return nil
}

func (c *nativeConsole) readRecord() (inputRecord, bool, error) {
	var record inputRecord
	defer record.clear()
	var read uint32
	ok, _, _ := readConsoleInputExW.Call(uintptr(c.handle), uintptr(unsafe.Pointer(&record)),
		1, uintptr(unsafe.Pointer(&read)), consoleReadNowait)
	runtime.KeepAlive(&record)
	runtime.KeepAlive(&read)
	if ok == 0 || read > 1 {
		record.clear()
		return inputRecord{}, false, ErrInput
	}
	return record, read == 1, nil
}

func (c *nativeConsole) discard() error {
	if windows.FlushConsoleInputBuffer(c.handle) != nil {
		return ErrInput
	}
	return nil
}

func (c *nativeConsole) close() error {
	if windows.CloseHandle(c.handle) != nil {
		return ErrInput
	}
	c.handle = windows.InvalidHandle
	return nil
}
