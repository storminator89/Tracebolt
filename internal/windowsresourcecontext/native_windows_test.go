//go:build windows

package windowsresourcecontext

import (
	"context"
	"testing"
	"unsafe"
)

// Synthetic layout/callback tests only. These tests do not invoke any native
// collector or API. Windows test binaries are compile-only in Linux validation.
func TestNativePointerWidthLayouts(t *testing.T) {
	var p performanceInformation
	var f enumPageFileInformation
	if unsafe.Sizeof(uintptr(0)) == 8 {
		if unsafe.Sizeof(p) != 104 || unsafe.Offsetof(p.CommitTotal) != 8 || unsafe.Offsetof(p.CommitLimit) != 16 || unsafe.Offsetof(p.PhysicalTotal) != 32 || unsafe.Offsetof(p.PhysicalAvailable) != 40 || unsafe.Offsetof(p.PageSize) != 80 {
			t.Fatal("PERFORMANCE_INFORMATION x64/arm64 ABI")
		}
		if unsafe.Sizeof(f) != 32 || unsafe.Offsetof(f.TotalSize) != 8 || unsafe.Offsetof(f.TotalInUse) != 16 {
			t.Fatal("ENUM_PAGE_FILE_INFORMATION x64/arm64 ABI")
		}
	} else if unsafe.Sizeof(p) != 56 || unsafe.Sizeof(f) != 20 {
		t.Fatal("32-bit ABI")
	}
}
func TestCallbackIgnoresFilenameAndReturnsBOOL(t *testing.T) {
	state := pagefileRead{ctx: context.Background()}
	row := enumPageFileInformation{Size: uint32(unsafe.Sizeof(enumPageFileInformation{})), TotalSize: 10, TotalInUse: 2}
	// The poison filename address must never be dereferenced. No native source.
	if r := pagefileCallback(uintptr(unsafe.Pointer(&state)), &row, ^uintptr(0)); r != 1 {
		t.Fatal("continue BOOL")
	}
	if state.aggregate.count != 1 || state.aggregate.total != 10 || state.aggregate.used != 2 {
		t.Fatal("wrong scalars")
	}
	row.Size = 1
	if r := pagefileCallback(uintptr(unsafe.Pointer(&state)), &row, ^uintptr(0)); r != 0 || state.aggregate.err != ErrMetadata {
		t.Fatal("stop BOOL")
	}
}
