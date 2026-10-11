//go:build windows

package windowshistoryworker

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func workerEnvironment() ([]string, error) {
	// os/exec otherwise inherits SystemRoot on Windows even with an empty Env.
	// Obtain this one necessary value from the OS, never ambient environment.
	root, err := windows.GetWindowsDirectory()
	if err != nil || len(root) == 0 || len(root) > 32767 || !filepath.IsAbs(root) || strings.ContainsAny(root, "\x00\r\n=") {
		return nil, ErrUnavailable
	}
	return []string{"SystemRoot=" + root}, nil
}
