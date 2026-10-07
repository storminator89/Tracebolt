//go:build windows

package windowsvolumes

import (
	"context"
	"errors"
	"io"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var kernel = windows.NewLazySystemDLL("kernel32.dll")
var findFirstVolume = kernel.NewProc("FindFirstVolumeW")
var findNextVolume = kernel.NewProc("FindNextVolumeW")
var findVolumeClose = kernel.NewProc("FindVolumeClose")
var getDriveType = kernel.NewProc("GetDriveTypeW")
var getDiskFreeSpaceEx = kernel.NewProc("GetDiskFreeSpaceExW")

// Typed injectable wrappers keep pointers intact until the concrete syscall;
// tests replace these functions without loading or invoking Windows procedures.
type nativeAPI struct {
	ready    func() error
	first    func([]uint16) (uintptr, error)
	next     func(uintptr, []uint16) error
	close    func(uintptr) error
	drive    func(*uint16) uint32
	capacity func(*uint16) (uint64, uint64, uint64, error)
}

var systemAPI = nativeAPI{
	ready: func() error {
		for _, p := range []*windows.LazyProc{findFirstVolume, findNextVolume, findVolumeClose, getDriveType, getDiskFreeSpaceEx} {
			if p.Find() != nil {
				return ErrUnavailable
			}
		}
		return nil
	},
	first: func(buf []uint16) (uintptr, error) {
		h, _, e := findFirstVolume.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		runtime.KeepAlive(buf)
		if h == ^uintptr(0) {
			return h, e
		}
		return h, nil
	},
	next: func(h uintptr, buf []uint16) error {
		ok, _, e := findNextVolume.Call(h, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		runtime.KeepAlive(buf)
		if ok == 0 {
			return e
		}
		return nil
	},
	close: func(h uintptr) error {
		ok, _, e := findVolumeClose.Call(h)
		if ok == 0 {
			return e
		}
		return nil
	},
	drive: func(p *uint16) uint32 {
		n, _, _ := getDriveType.Call(uintptr(unsafe.Pointer(p)))
		runtime.KeepAlive(p)
		return uint32(n)
	},
	capacity: func(p *uint16) (uint64, uint64, uint64, error) {
		var available, total, free uint64
		ok, _, e := getDiskFreeSpaceEx.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&available)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&free)))
		runtime.KeepAlive(p)
		if ok == 0 {
			return 0, 0, 0, e
		}
		return total, free, available, nil
	},
}

type nativeCursor struct {
	api    nativeAPI
	handle uintptr
	first  string
}

func nativeError(e error) error {
	if errors.Is(e, windows.ERROR_ACCESS_DENIED) {
		return ErrDenied
	}
	if errors.Is(e, windows.ERROR_NO_MORE_FILES) {
		return io.EOF
	}
	return ErrUnavailable
}
func volumeName(buf []uint16) (string, error) {
	end := -1
	for i, v := range buf {
		if v == 0 {
			end = i
			break
		}
	}
	if end < 0 {
		return "", ErrMetadata
	}
	s := windows.UTF16ToString(buf[:end])
	if len(s) != 49 {
		return "", ErrMetadata
	}
	s = s[:11] + strings.ToLower(s[11:47]) + s[47:]
	if !validVolumeID(s) {
		return "", ErrMetadata
	}
	return s, nil
}
func openNative(ctx context.Context) (cursor, error) { return openNativeUsing(ctx, systemAPI) }
func openNativeUsing(ctx context.Context, api nativeAPI) (cursor, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := api.ready(); e != nil {
		return nil, e
	}
	// Fixed GUID-root buffer; no paths, labels or mount point APIs are queried.
	var buf [64]uint16
	h, e := api.first(buf[:])
	if e != nil {
		if errors.Is(e, windows.ERROR_NO_MORE_FILES) {
			return &nativeCursor{}, nil
		}
		return nil, nativeError(e)
	}
	n, err := volumeName(buf[:])
	if err != nil {
		api.close(h)
		return nil, err
	}
	return &nativeCursor{api: api, handle: h, first: n}, nil
}
func (r *nativeCursor) Next(ctx context.Context) (string, error) {
	if e := ctx.Err(); e != nil {
		return "", e
	}
	if r.first != "" {
		s := r.first
		r.first = ""
		return s, nil
	}
	if r.handle == 0 {
		return "", io.EOF
	}
	var buf [64]uint16
	e := r.api.next(r.handle, buf[:])
	if e != nil {
		return "", nativeError(e)
	}
	return volumeName(buf[:])
}
func (r *nativeCursor) Close() error {
	if r.handle == 0 {
		return nil
	}
	h := r.handle
	r.handle = 0
	e := r.api.close(h)
	if e != nil {
		return nativeError(e)
	}
	return nil
}
func (r *nativeCursor) DriveType(ctx context.Context, id string) (string, error) {
	if e := ctx.Err(); e != nil {
		return "unknown", e
	}
	if !validVolumeID(id) {
		return "unknown", ErrMetadata
	}
	p, e := windows.UTF16PtrFromString(id)
	if e != nil {
		return "unknown", ErrMetadata
	}
	n := r.api.drive(p)
	switch n {
	case 2:
		return "removable", nil
	case 3:
		return "fixed", nil
	case 5:
		return "cdrom", nil
	case 6:
		return "ramdisk", nil
	default:
		return "unknown", ErrDriveType
	}
}
func (r *nativeCursor) Capacity(ctx context.Context, id string) (uint64, uint64, uint64, error) {
	if e := ctx.Err(); e != nil {
		return 0, 0, 0, e
	}
	if !validVolumeID(id) {
		return 0, 0, 0, ErrMetadata
	}
	p, e := windows.UTF16PtrFromString(id)
	if e != nil {
		return 0, 0, 0, ErrMetadata
	}
	total, free, available, e := r.api.capacity(p)
	if e != nil {
		return 0, 0, 0, nativeError(e)
	}
	return total, free, available, nil
}
