package windowsservice

import (
	"errors"
	"strings"
)

// SystemDriveFromWindowsDirectory validates an OS-supplied Windows directory and
// derives only its drive. The acceptance child uses it to support KnownFolder
// expansion; it never replaces a KnownFolder result or bypasses layout checks.
func SystemDriveFromWindowsDirectory(systemWindows string) (string, error) {
	if _, err := layoutFromRoots(systemWindows, systemWindows); err != nil || strings.ContainsAny(systemWindows, "%*") {
		return "", errors.New("invalid system directory")
	}
	return systemWindows[:2], nil
}
