//go:build windows && tracebolt_fresh_native

package main

import (
	"io"
	"os"

	"golang.org/x/sys/windows"
)

// Called only inside the separately authorized child. This creates one owned
// output handle; no inherited handle, stdin, process table or Go global changes.
func openFreshConsoleOutput() (io.WriteCloser, error) {
	name, err := windows.UTF16PtrFromString("CONOUT$")
	if err != nil {
		return nil, errFreshConsoleOutput
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, errFreshConsoleOutput
	}
	file := os.NewFile(uintptr(handle), "<fresh console output>")
	if file == nil {
		windows.CloseHandle(handle)
		return nil, errFreshConsoleOutput
	}
	return file, nil
}
func freshConsoleOutputCharacter(output io.WriteCloser) error {
	file, ok := output.(*os.File)
	if !ok {
		return errFreshConsoleOutput
	}
	kind, err := windows.GetFileType(windows.Handle(file.Fd()))
	if err != nil || kind != windows.FILE_TYPE_CHAR {
		return errFreshConsoleOutput
	}
	return nil
}
func freshConsoleOutputMode(output io.WriteCloser) error {
	file, ok := output.(*os.File)
	if !ok {
		return errFreshConsoleOutput
	}
	var mode uint32
	if windows.GetConsoleMode(windows.Handle(file.Fd()), &mode) != nil {
		return errFreshConsoleOutput
	}
	return nil
}
