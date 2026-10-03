//go:build windows

package collector

import (
	"fmt"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// This ABI test is cross-compiled here; it has NOT run on Windows. The compile-
// time size assertions additionally guard both supported Windows architectures.
func TestWindowsMemoryStatusABI(t *testing.T) {
	var status memoryStatusEx
	if unsafe.Sizeof(status) != 64 || unsafe.Offsetof(status.TotalPhys) != 8 || unsafe.Offsetof(status.AvailPhys) != 16 || unsafe.Offsetof(status.AvailExtendedVirtual) != 56 {
		t.Fatalf("MEMORYSTATUSEX does not match native ABI: %+v", status)
	}
}

func TestWindowsNativePermissionQuality(t *testing.T) {
	if quality := errorQuality(fmt.Errorf("native failure: %w", windows.ERROR_ACCESS_DENIED)); quality != "denied" {
		t.Errorf("native access denied was labeled %s", quality)
	}
	if quality := errorQuality(windows.ERROR_INVALID_DATA); quality != "unknown" {
		t.Errorf("native invalid data was labeled %s", quality)
	}
}
