//go:build windows

package windowspath

import (
	"errors"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Every Windows call is intercepted. These tests perform no drive query, file
// open, ACL operation, listener action or token inspection on the host.
func rootFixture(t *testing.T, create createCall) rootCalls {
	t.Helper()
	return rootCalls{
		driveType: func(root *uint16) uint32 {
			if windows.UTF16PtrToString(root) != `C:\` {
				t.Fatal("wrong drive query")
			}
			return windows.DRIVE_FIXED
		},
		queryDevice: func(name *uint16, target *uint16, capacity uint32) (uint32, error) {
			if windows.UTF16PtrToString(name) != `C:` {
				t.Fatal("wrong DOS mapping query")
			}
			// Only the current (first) mapping is used; old mappings are not retries.
			values := append(windows.StringToUTF16(`\Device\HarddiskVolume12`), windows.StringToUTF16(`\Device\HarddiskVolume99`)...)
			values = append(values, 0)
			copy(unsafe.Slice(target, int(capacity)), values)
			return uint32(len(values)), nil
		}, create: create,
	}
}
func TestRootRequestUsesResolvedDeviceWithoutFallback(t *testing.T) {
	calls := 0
	h, err := openRootWith(`C:\`, rootFixture(t, func(h *windows.Handle, access uint32, oa *windows.OBJECT_ATTRIBUTES, iosb *windows.IO_STATUS_BLOCK, allocation *int64, attributes, share, disposition, options uint32, ea uintptr, eaLength uint32) error {
		calls++
		if oa.RootDirectory != 0 || oa.ObjectName.String() != `\Device\HarddiskVolume12\` || oa.Attributes != windows.OBJ_CASE_INSENSITIVE|windows.OBJ_DONT_REPARSE || oa.SecurityDescriptor != nil || oa.SecurityQoS != nil || access != 0x1200a1 || share != 3 || disposition != windows.FILE_OPEN || attributes != windows.FILE_ATTRIBUTE_DIRECTORY || options != windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_DIRECTORY_FILE || allocation != nil || ea != 0 || eaLength != 0 {
			t.Fatal("native root request changed")
		}
		*h = 17
		return nil
	}))
	if err != nil || h != 17 || calls != 1 {
		t.Fatal("root open retried or rebound")
	}
}
func TestRootAcquisitionStagesFailBeforeNativeOpen(t *testing.T) {
	for _, stage := range []string{"root-path-syntax", "root-drive-type", "root-device-query-failed", "root-device-buffer-invalid", "root-device-target-rejected"} {
		t.Run(stage, func(t *testing.T) {
			opens := 0
			calls := rootFixture(t, func(*windows.Handle, uint32, *windows.OBJECT_ATTRIBUTES, *windows.IO_STATUS_BLOCK, *int64, uint32, uint32, uint32, uint32, uintptr, uint32) error {
				opens++
				return nil
			})
			root := `C:\`
			switch stage {
			case "root-path-syntax":
				root = `C:\child`
			case "root-drive-type":
				calls.driveType = func(*uint16) uint32 { return windows.DRIVE_REMOTE }
			case "root-device-query-failed":
				calls.queryDevice = func(*uint16, *uint16, uint32) (uint32, error) { return 0, windows.ERROR_ACCESS_DENIED }
			case "root-device-buffer-invalid":
				calls.queryDevice = func(*uint16, *uint16, uint32) (uint32, error) { return 1024, nil }
			case "root-device-target-rejected":
				calls.queryDevice = func(_ *uint16, b *uint16, n uint32) (uint32, error) {
					v := windows.StringToUTF16(`\??\C:`)
					copy(unsafe.Slice(b, int(n)), v)
					return uint32(len(v)), nil
				}
			}
			h, err := openRootWith(root, calls)
			if h != 0 || !errors.Is(err, ErrPath) || RootDiagnostic(err) != stage || opens != 0 {
				t.Fatal("wrong root acquisition stage or native call reached")
			}
		})
	}
}
func TestRootNativeStatusesAreFiniteAndNeverRetried(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{windows.STATUS_ACCESS_DENIED, "root-open-access-denied"}, {windows.STATUS_SHARING_VIOLATION, "root-open-sharing-violation"}, {windows.STATUS_REPARSE_POINT_ENCOUNTERED, "root-open-reparse"},
		{windows.STATUS_INVALID_PARAMETER, "root-open-invalid-request"}, {windows.STATUS_INVALID_PARAMETER_11, "root-open-invalid-request"},
		{windows.STATUS_OBJECT_NAME_NOT_FOUND, "root-open-name-not-found"}, {windows.STATUS_OBJECT_PATH_NOT_FOUND, "root-open-path-not-found"},
		{windows.STATUS_OBJECT_NAME_INVALID, "root-open-name-invalid"}, {windows.STATUS_OBJECT_PATH_SYNTAX_BAD, "root-open-path-invalid"},
		{windows.STATUS_OBJECT_TYPE_MISMATCH, "root-open-type-mismatch"}, {windows.STATUS_FILE_IS_A_DIRECTORY, "root-open-type-mismatch"}, {windows.STATUS_NOT_A_DIRECTORY, "root-open-not-directory"},
		{windows.STATUS_INVALID_DEVICE_REQUEST, "root-open-unsupported"}, {windows.STATUS_PRIVILEGE_NOT_HELD, "root-open-privilege"},
		{windows.STATUS_STOPPED_ON_SYMLINK, "root-open-reparse-unresolved"}, {windows.STATUS_DEVICE_NOT_READY, "root-open-device-unavailable"},
		{windows.STATUS_IO_DEVICE_ERROR, "root-open-io-failed"}, {windows.NTStatus(0xdeadbeef), "root-open-other"}, {errors.New("private native error"), "root-open-other"},
	}
	for _, test := range tests {
		calls := 0
		h, err := openRootWith(`C:\`, rootFixture(t, func(*windows.Handle, uint32, *windows.OBJECT_ATTRIBUTES, *windows.IO_STATUS_BLOCK, *int64, uint32, uint32, uint32, uint32, uintptr, uint32) error {
			calls++
			return test.err
		}))
		if h != 0 || !errors.Is(err, test.err) || RootDiagnostic(err) != test.want || calls != 1 {
			t.Fatal("root status lost, leaked or retried")
		}
	}
	if rootOpenFailure(ErrPath) != "root-name-encoding" {
		t.Fatal("name construction failure misattributed")
	}
}
