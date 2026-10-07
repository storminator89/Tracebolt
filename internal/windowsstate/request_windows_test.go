//go:build windows

package windowsstate

import (
	"errors"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The syscall is intercepted before execution. Only memory-backed SDDL and
// request structures are used; no state, directory, file or ACL is created.
func TestStateNativeDirectoryOptionsPreserveBinding(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		t.Fatal("descriptor fixture rejected")
	}
	for _, directory := range []bool{false, true} {
		for _, disposition := range []uint32{windows.FILE_OPEN, windows.FILE_CREATE} {
			access, share := uint32(writeAccess), uint32(0)
			if directory {
				access, share = directoryAccess, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE
			}
			calls := 0
			h, err := ntOpenWith(17, "entry", access, share, disposition, directory, sd, func(h *windows.Handle, a uint32, oa *windows.OBJECT_ATTRIBUTES, iosb *windows.IO_STATUS_BLOCK, allocation *int64, attributes, sharing, disp, options uint32, ea uintptr, eaLength uint32) error {
				calls++
				wantOptions, wantAttributes := uint32(0x00600062), uint32(windows.FILE_ATTRIBUTE_NORMAL)
				if directory {
					wantOptions, wantAttributes = 0x00200021, windows.FILE_ATTRIBUTE_DIRECTORY
				}
				wantSD := (*windows.SECURITY_DESCRIPTOR)(nil)
				if disposition == windows.FILE_CREATE {
					wantSD = sd
				}
				if a != access || sharing != share || sharing&windows.FILE_SHARE_DELETE != 0 || disp != disposition || options != wantOptions || attributes != wantAttributes || oa.Length != uint32(unsafe.Sizeof(*oa)) || oa.RootDirectory != 17 || oa.ObjectName.String() != "entry" || oa.Attributes != windows.OBJ_CASE_INSENSITIVE|windows.OBJ_DONT_REPARSE || oa.SecurityDescriptor != wantSD || oa.SecurityQoS != nil || allocation != nil || ea != 0 || eaLength != 0 {
					t.Fatal("state request changed a binding or protection")
				}
				*h = 23
				return nil
			})
			if err != nil || h != 23 || calls != 1 {
				t.Fatal("state request retried or rebound")
			}
		}
	}
}
func TestStateNativeReparseFailureHasNoFallback(t *testing.T) {
	for _, failure := range []error{windows.STATUS_REPARSE_POINT_ENCOUNTERED, windows.STATUS_ACCESS_DENIED, windows.STATUS_SHARING_VIOLATION} {
		calls := 0
		h, err := ntOpenWith(17, "entry", directoryAccess, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.FILE_OPEN, true, nil, func(*windows.Handle, uint32, *windows.OBJECT_ATTRIBUTES, *windows.IO_STATUS_BLOCK, *int64, uint32, uint32, uint32, uint32, uintptr, uint32) error {
			calls++
			return failure
		})
		if h != 0 || !errors.Is(err, failure) || calls != 1 {
			t.Fatal("state failure retried or weakened")
		}
	}
}
