//go:build windows

package windowsstate

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Native Windows tests are ABI and in-memory descriptor conversion ONLY.
// They must never call Open, ReadProtected, write files/ACLs, create keys, create
// services, or grant host permissions without separate action-time approval.
func TestWindowsRenameABI(t *testing.T) {
	var r renameHeader
	switch unsafe.Sizeof(uintptr(0)) {
	case 8:
		if unsafe.Offsetof(r.Root) != 8 || unsafe.Offsetof(r.NameBytes) != 16 || unsafe.Offsetof(r.Name) != 20 || unsafe.Sizeof(r) != 24 {
			t.Fatal("64-bit FILE_RENAME_INFORMATION ABI mismatch")
		}
	case 4:
		if unsafe.Offsetof(r.Root) != 4 || unsafe.Offsetof(r.NameBytes) != 8 || unsafe.Offsetof(r.Name) != 12 || unsafe.Sizeof(r) != 16 {
			t.Fatal("32-bit FILE_RENAME_INFORMATION ABI mismatch")
		}
	default:
		t.Fatal("unsupported pointer size")
	}
}
func TestWindowsDescriptorConversionInMemory(t *testing.T) {
	for _, owner := range []string{"SY", "BA", testSID} {
		sd, e := windows.SecurityDescriptorFromString("O:" + owner + "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + testSID + ")")
		if e != nil {
			t.Fatal("in-memory SDDL conversion failed")
		}
		p, e := parseDescriptor(unsafe.Slice((*byte)(unsafe.Pointer(sd)), int(sd.Length())))
		if e != nil || validateSecurity(p, testSID, false) != nil {
			t.Fatal("native descriptor rejected")
		}
	}
	sd, e := windows.SecurityDescriptorFromString("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if e != nil {
		t.Fatal(e)
	}
	p, e := parseDescriptor(unsafe.Slice((*byte)(unsafe.Pointer(sd)), int(sd.Length())))
	if e != nil || validateSecurity(p, "", true) != nil {
		t.Fatal("installer descriptor rejected")
	}
}

func TestWindowsOutputBufferAlignment(t *testing.T) {
	for _, n := range []int{4, 24, 4096, 16384} {
		b := alignedBytes(n)
		if len(b) != n || uintptr(unsafe.Pointer(&b[0]))%8 != 0 {
			t.Fatal("native output buffer is not aligned")
		}
	}
}
