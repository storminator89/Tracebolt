//go:build windows

package windowsresourceworker

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"localrmm/internal/windowsresourcecontext"
)

func workerEnvironment() ([]string, error) {
	// os/exec otherwise silently inherits SystemRoot on Windows even with an
	// empty Env. Obtain the one required value from the OS, never os.Getenv,
	// and set it explicitly so no ambient credential or runtime setting passes.
	root, err := windows.GetWindowsDirectory()
	if err != nil || len(root) == 0 || len(root) > 32767 || !filepath.IsAbs(root) || strings.ContainsAny(root, "\x00\r\n=") {
		return nil, windowsresourcecontext.ErrUnavailable
	}
	return []string{"SystemRoot=" + root}, nil
}
