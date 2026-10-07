//go:build windows

package windowspath

import (
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// OpenRoot resolves a fixed local volume once, then opens its native device
// directly. Later requests use this handle, never a mutable DOS drive mapping.
func OpenRoot(root string) (windows.Handle, error) {
	if !Canonical(root) || len(root) != 3 || windows.GetDriveType(windows.StringToUTF16Ptr(root)) != windows.DRIVE_FIXED {
		return 0, ErrPath
	}
	var target [1024]uint16
	n, err := windows.QueryDosDevice(windows.StringToUTF16Ptr(root[:2]), &target[0], uint32(len(target)))
	if err != nil || n == 0 || n >= uint32(len(target)) {
		return 0, ErrPath
	}
	device := windows.UTF16ToString(target[:])
	const prefix = `\Device\HarddiskVolume`
	if !strings.HasPrefix(device, prefix) || len(device) == len(prefix) {
		return 0, ErrPath
	}
	for _, c := range device[len(prefix):] {
		if c < '0' || c > '9' {
			return 0, ErrPath
		}
	}
	return ntOpen(0, device+`\`, DirectoryAccess, DirectoryShare, windows.FILE_OPEN, true, nil)
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
	flags := uint32(windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_OPEN_REPARSE_POINT | windows.FILE_OPEN_NO_RECALL)
	attributes := uint32(windows.FILE_ATTRIBUTE_NORMAL)
	if directory {
		flags |= windows.FILE_DIRECTORY_FILE
		attributes = windows.FILE_ATTRIBUTE_DIRECTORY
	} else {
		flags |= windows.FILE_NON_DIRECTORY_FILE | windows.FILE_WRITE_THROUGH
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
