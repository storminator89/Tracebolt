//go:build windows

package windowspath

import (
	"errors"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// No file, directory, ACL, token, or service operation is performed. The request
// is intercepted before NtCreateFile; descriptors exist only in process memory.
func TestRelativeNativeRequestsAreBoundAndCreateOnly(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		t.Fatal("descriptor fixture rejected")
	}
	for _, dir := range []bool{false, true} {
		for _, create := range []bool{false, true} {
			disposition, descriptor := uint32(windows.FILE_OPEN), (*windows.SECURITY_DESCRIPTOR)(nil)
			if create {
				disposition, descriptor = windows.FILE_CREATE, sd
			}
			calls := 0
			call := func(h *windows.Handle, access uint32, oa *windows.OBJECT_ATTRIBUTES, iosb *windows.IO_STATUS_BLOCK, allocation *int64, attributes, share, gotDisposition, options uint32, ea uintptr, eaLength uint32) error {
				calls++
				wantAccess, wantShare := uint32(DirectoryAccess), uint32(DirectoryShare)
				if create && !dir {
					wantAccess, wantShare = windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.SYNCHRONIZE, 0
				}
				if access != wantAccess || share != wantShare {
					t.Fatal("wrong binding access or share mode")
				}
				if oa.RootDirectory != 17 || oa.ObjectName.String() != "child" || oa.Attributes != windows.OBJ_CASE_INSENSITIVE|windows.OBJ_DONT_REPARSE || oa.SecurityDescriptor != descriptor || oa.Length != uint32(unsafe.Sizeof(*oa)) || share&windows.FILE_SHARE_DELETE != 0 || gotDisposition != disposition || allocation != nil || ea != 0 || eaLength != 0 {
					t.Fatal("relative request contract changed")
				}
				required := uint32(windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_OPEN_REPARSE_POINT | windows.FILE_OPEN_NO_RECALL)
				if dir {
					required |= windows.FILE_DIRECTORY_FILE
					if attributes != windows.FILE_ATTRIBUTE_DIRECTORY {
						t.Fatal("wrong directory attributes")
					}
				} else {
					required |= windows.FILE_NON_DIRECTORY_FILE | windows.FILE_WRITE_THROUGH
				}
				if options != required {
					t.Fatal("relative request options changed")
				}
				*h = 23
				return nil
			}
			var h windows.Handle
			var err error
			if create {
				h, err = createChildWith(17, "child", dir, descriptor, call)
			} else {
				h, err = openChildWith(17, "child", dir, DirectoryAccess, DirectoryShare, call)
			}

			if err != nil || h != 23 || calls != 1 {
				t.Fatal("create/open retried or returned a different object")
			}
		}
	}
}
func TestRelativeNativeFailureHasNoAdoptionOrRetry(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		t.Fatal("descriptor fixture rejected")
	}
	for _, failure := range []error{windows.STATUS_OBJECT_NAME_COLLISION, windows.STATUS_REPARSE_POINT_ENCOUNTERED, windows.STATUS_ACCESS_DENIED} {
		calls := 0
		h, err := createChildWith(17, "child", true, sd, func(*windows.Handle, uint32, *windows.OBJECT_ATTRIBUTES, *windows.IO_STATUS_BLOCK, *int64, uint32, uint32, uint32, uint32, uintptr, uint32) error {
			calls++
			return failure
		})
		if h != 0 || !errors.Is(err, failure) || calls != 1 {
			t.Fatal("failed create adopted or retried")
		}
	}
}

func TestRelativeNativeInvalidInputNeverReachesSyscall(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		t.Fatal("descriptor fixture rejected")
	}
	calls := 0
	call := func(*windows.Handle, uint32, *windows.OBJECT_ATTRIBUTES, *windows.IO_STATUS_BLOCK, *int64, uint32, uint32, uint32, uint32, uintptr, uint32) error {
		calls++
		return nil
	}
	for _, name := range []string{"", ".", "..", `a\b`, `C:\absolute`, `a:stream`} {
		if _, err := createChildWith(17, name, true, sd, call); err == nil {
			t.Fatal("unsafe create name accepted")
		}
		if _, err := openChildWith(17, name, true, DirectoryAccess, DirectoryShare, call); err == nil {
			t.Fatal("unsafe open name accepted")
		}
	}
	if _, err := createChildWith(0, "child", true, sd, call); err == nil {
		t.Fatal("missing parent accepted")
	}
	if _, err := createChildWith(17, "child", true, nil, call); err == nil {
		t.Fatal("missing creation descriptor accepted")
	}
	if _, err := openChildWith(17, "child", true, DirectoryAccess, windows.FILE_SHARE_DELETE, call); err == nil {
		t.Fatal("delete sharing accepted")
	}
	if calls != 0 {
		t.Fatal("invalid request reached native syscall")
	}
}
