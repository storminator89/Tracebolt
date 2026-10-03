//go:build darwin

package collector

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

// Cross-compilation does not execute this target-OS errno mapping check.
func TestDarwinNativePermissionQuality(t *testing.T) {
	for _, err := range []error{unix.EACCES, unix.EPERM, fmt.Errorf("native failure: %w", unix.EACCES)} {
		if quality := errorQuality(err); quality != "denied" {
			t.Errorf("native permission failure was labeled %s", quality)
		}
	}
	if quality := errorQuality(unix.EIO); quality != "unknown" {
		t.Errorf("native I/O failure was labeled %s", quality)
	}
}
