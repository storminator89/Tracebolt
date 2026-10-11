//go:build windows

package windowsstorage

import (
	"context"
	"golang.org/x/sys/windows"
	"runtime"
	"unsafe"
)

var volumeDLL = windows.NewLazySystemDLL("kernel32.dll")
var logicalDrives = volumeDLL.NewProc("GetLogicalDrives")
var driveType = volumeDLL.NewProc("GetDriveTypeW")
var volumeName = volumeDLL.NewProc("GetVolumeNameForVolumeMountPointW")

type nativeDriveAPI struct{}

func driveError(e error) error {
	if e == windows.ERROR_ACCESS_DENIED {
		return ErrDenied
	}
	return ErrUnavailable
}
func (nativeDriveAPI) mask() (uint32, error) {
	if logicalDrives.Find() != nil {
		return 0, ErrUnsupported
	}
	r, _, e := logicalDrives.Call()
	if r == 0 {
		return 0, driveError(e)
	}
	return uint32(r), nil
}
func driveRoot(letter byte) ([4]uint16, error) {
	if letter < 'A' || letter > 'Z' {
		return [4]uint16{}, ErrInvalid
	}
	return [4]uint16{uint16(letter), ':', '\\', 0}, nil
}
func (nativeDriveAPI) driveType(letter byte) (uint32, error) {
	root, e := driveRoot(letter)
	if e != nil {
		return 0, e
	}
	if driveType.Find() != nil {
		return 0, ErrUnsupported
	}
	r, _, _ := driveType.Call(uintptr(unsafe.Pointer(&root[0])))
	runtime.KeepAlive(root)
	return uint32(r), nil
}
func (nativeDriveAPI) volume(letter byte) (string, error) {
	root, e := driveRoot(letter)
	if e != nil {
		return "", e
	}
	if volumeName.Find() != nil {
		return "", ErrUnsupported
	}
	var out [50]uint16
	r, _, e := volumeName.Call(uintptr(unsafe.Pointer(&root[0])), uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)))
	runtime.KeepAlive(root)
	runtime.KeepAlive(out)
	if r == 0 {
		return "", driveError(e)
	}
	n := 0
	for n < len(out) && out[n] != 0 {
		n++
	}
	if n == len(out) {
		return "", ErrBounds
	}
	for _, c := range out[:n] {
		if c > 127 {
			return "", ErrMetadata
		}
	}
	return windows.UTF16ToString(out[:n]), nil
}
func nativeDrives(ctx context.Context) (Drives, error) { return collectDrives(ctx, nativeDriveAPI{}) }
