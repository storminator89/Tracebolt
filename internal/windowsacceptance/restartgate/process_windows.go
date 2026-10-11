//go:build windows

package restartgate

import (
	"golang.org/x/sys/windows"
	"os/exec"
	"syscall"
)

func isolateCommand(cmd *exec.Cmd) error {
	systemRoot, err := windows.GetWindowsDirectory()
	if err != nil || systemRoot == "" {
		return ErrRejected
	}
	// No inherited credentials, runtime overrides, injected DLL paths or controller
	// authority/pipe metadata. The installed command needs only this OS binding.
	cmd.Env = []string{"SystemRoot=" + systemRoot}
	// Console Ctrl+C cancellation of the observer must not also terminate its CLI.
	// No job object and no terminate/debug/write capability are acquired.
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
	return nil
}
