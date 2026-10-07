//go:build windows

package windowspath

import (
	"errors"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// OpenRoot resolves a fixed local volume once, then opens its native device
// directly. Later requests use this handle, never a mutable DOS drive mapping.
func OpenRoot(root string) (windows.Handle, error) {
	return openRootWith(root, rootCalls{windows.GetDriveType, windows.QueryDosDevice, windows.NtCreateFile})
}

type rootCalls struct {
	driveType   func(*uint16) uint32
	queryDevice func(*uint16, *uint16, uint32) (uint32, error)
	create      createCall
}

// Injection is used only by in-memory request/diagnostic tests. Production uses
// the same three Windows calls, in the same order, without retries or fallback.
func openRootWith(root string, calls rootCalls) (windows.Handle, error) {
	if !Canonical(root) || len(root) != 3 {
		return 0, rootRejected("root-path-syntax", ErrPath)
	}
	if calls.driveType(windows.StringToUTF16Ptr(root)) != windows.DRIVE_FIXED {
		return 0, rootRejected("root-drive-type", ErrPath)
	}
	var target [1024]uint16
	n, err := calls.queryDevice(windows.StringToUTF16Ptr(root[:2]), &target[0], uint32(len(target)))
	if err != nil {
		return 0, rootRejected("root-device-query-failed", ErrPath)
	}
	if n == 0 || n >= uint32(len(target)) {
		return 0, rootRejected("root-device-buffer-invalid", ErrPath)
	}
	device := windows.UTF16ToString(target[:])
	const prefix = `\Device\HarddiskVolume`
	if !strings.HasPrefix(device, prefix) || len(device) == len(prefix) {
		return 0, rootRejected("root-device-target-rejected", ErrPath)
	}
	for _, c := range device[len(prefix):] {
		if c < '0' || c > '9' {
			return 0, rootRejected("root-device-target-rejected", ErrPath)
		}
	}
	h, err := ntOpenWith(0, device+`\`, DirectoryAccess, DirectoryShare, windows.FILE_OPEN, true, nil, calls.create)
	if err != nil {
		return 0, rootRejected(rootOpenFailure(err), err)
	}
	return h, nil
}
func rootOpenFailure(err error) string {
	if errors.Is(err, ErrPath) {
		return "root-name-encoding"
	}
	var status windows.NTStatus
	if !errors.As(err, &status) {
		return "root-open-other"
	}
	switch status {
	case windows.STATUS_ACCESS_DENIED:
		return "root-open-access-denied"
	case windows.STATUS_SHARING_VIOLATION:
		return "root-open-sharing-violation"
	case windows.STATUS_REPARSE_POINT_ENCOUNTERED:
		return "root-open-reparse"
	case windows.STATUS_INVALID_PARAMETER, windows.STATUS_INVALID_PARAMETER_MIX,
		windows.STATUS_INVALID_PARAMETER_1, windows.STATUS_INVALID_PARAMETER_2, windows.STATUS_INVALID_PARAMETER_3, windows.STATUS_INVALID_PARAMETER_4,
		windows.STATUS_INVALID_PARAMETER_5, windows.STATUS_INVALID_PARAMETER_6, windows.STATUS_INVALID_PARAMETER_7, windows.STATUS_INVALID_PARAMETER_8,
		windows.STATUS_INVALID_PARAMETER_9, windows.STATUS_INVALID_PARAMETER_10, windows.STATUS_INVALID_PARAMETER_11, windows.STATUS_INVALID_PARAMETER_12:
		return "root-open-invalid-request"
	case windows.STATUS_OBJECT_NAME_NOT_FOUND, windows.STATUS_NO_SUCH_FILE:
		return "root-open-name-not-found"
	case windows.STATUS_OBJECT_PATH_NOT_FOUND:
		return "root-open-path-not-found"
	case windows.STATUS_OBJECT_NAME_INVALID:
		return "root-open-name-invalid"
	case windows.STATUS_OBJECT_PATH_SYNTAX_BAD:
		return "root-open-path-invalid"
	case windows.STATUS_OBJECT_TYPE_MISMATCH, windows.STATUS_FILE_IS_A_DIRECTORY:
		return "root-open-type-mismatch"
	case windows.STATUS_NOT_A_DIRECTORY:
		return "root-open-not-directory"
	case windows.STATUS_NOT_SUPPORTED, windows.STATUS_INVALID_DEVICE_REQUEST, windows.STATUS_NOT_IMPLEMENTED:
		return "root-open-unsupported"
	case windows.STATUS_PRIVILEGE_NOT_HELD:
		return "root-open-privilege"
	case windows.STATUS_IO_REPARSE_TAG_NOT_HANDLED, windows.STATUS_REPARSE, windows.STATUS_REPARSE_OBJECT, windows.STATUS_STOPPED_ON_SYMLINK, windows.STATUS_REPARSE_POINT_NOT_RESOLVED, windows.STATUS_IO_REPARSE_TAG_INVALID, windows.STATUS_IO_REPARSE_TAG_MISMATCH, windows.STATUS_REPARSE_ATTRIBUTE_CONFLICT:
		return "root-open-reparse-unresolved"
	case windows.STATUS_NO_SUCH_DEVICE, windows.STATUS_DEVICE_NOT_READY, windows.STATUS_VOLUME_DISMOUNTED, windows.STATUS_FILE_IS_OFFLINE:
		return "root-open-device-unavailable"
	case windows.STATUS_IO_DEVICE_ERROR, windows.STATUS_DISK_CORRUPT_ERROR, windows.STATUS_FILE_CORRUPT_ERROR:
		return "root-open-io-failed"
	}
	return "root-open-other"
}

// OpenChild accepts only one component. Attributes/EA writes are not frozen by
// sharing flags: OBJ_DONT_REPARSE and post-open validation remain mandatory.
func OpenChild(parent windows.Handle, name string, directory bool, access, share uint32) (windows.Handle, error) {
	return openChildWith(parent, name, directory, access, share, windows.NtCreateFile)
}
func openChildWith(parent windows.Handle, name string, directory bool, access, share uint32, call createCall) (windows.Handle, error) {
	if parent == 0 || parent == windows.InvalidHandle || !Component(name) || share&windows.FILE_SHARE_DELETE != 0 {
		return 0, ErrPath
	}
	if directory {
		access |= DirectoryAccess
	}
	return ntOpenWith(parent, name, access|windows.SYNCHRONIZE, share, windows.FILE_OPEN, directory, nil, call)
}

// CreateChild is create-only. The protected descriptor is attached atomically
// to the returned object, with no absolute create/reopen or ACL-repair phase.
func CreateChild(parent windows.Handle, name string, directory bool, sd *windows.SECURITY_DESCRIPTOR) (windows.Handle, error) {
	return createChildWith(parent, name, directory, sd, windows.NtCreateFile)
}
func createChildWith(parent windows.Handle, name string, directory bool, sd *windows.SECURITY_DESCRIPTOR, call createCall) (windows.Handle, error) {
	if parent == 0 || parent == windows.InvalidHandle || !Component(name) || sd == nil || !sd.IsValid() {
		return 0, ErrPath
	}
	access, share := uint32(windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.SYNCHRONIZE), uint32(0)
	if directory {
		access, share = DirectoryAccess, DirectoryShare
	}
	return ntOpenWith(parent, name, access, share, windows.FILE_CREATE, directory, sd, call)
}

type createCall func(*windows.Handle, uint32, *windows.OBJECT_ATTRIBUTES, *windows.IO_STATUS_BLOCK, *int64, uint32, uint32, uint32, uint32, uintptr, uint32) error

func ntOpen(parent windows.Handle, name string, access, share, disposition uint32, directory bool, sd *windows.SECURITY_DESCRIPTOR) (windows.Handle, error) {
	return ntOpenWith(parent, name, access, share, disposition, directory, sd, windows.NtCreateFile)
}

// The syscall is injected only by inert request fixtures; production always uses
// the ordinary access-checked NtCreateFile API, without token changes.
func ntOpenWith(parent windows.Handle, name string, access, share, disposition uint32, directory bool, sd *windows.SECURITY_DESCRIPTOR, call createCall) (windows.Handle, error) {
	unicode, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, ErrPath
	}
	oa := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: parent, ObjectName: unicode, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE, SecurityDescriptor: sd}
	// Keep both reparse protections. NO_RECALL is not part of MS-FSA's
	// directory option set; request it only for non-directory content opens.
	// This does not assert that directory acquisition cannot invoke providers.
	flags := uint32(windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_OPEN_REPARSE_POINT)
	attributes := uint32(windows.FILE_ATTRIBUTE_NORMAL)
	if directory {
		flags |= windows.FILE_DIRECTORY_FILE
		attributes = windows.FILE_ATTRIBUTE_DIRECTORY
	} else {
		flags |= windows.FILE_NON_DIRECTORY_FILE | windows.FILE_WRITE_THROUGH | windows.FILE_OPEN_NO_RECALL
	}
	var h windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	err = call(&h, access, &oa, &iosb, nil, attributes, share, disposition, flags, 0, 0)
	runtime.KeepAlive(unicode)
	runtime.KeepAlive(sd)
	if err != nil {
		return 0, err
	}
	return h, nil
}
