//go:build windows

package collector

import (
	"errors"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"localrmm/internal/model"
)

type windowsNativeProvider struct{}

// Only the system DLL search path is permitted; never resolve an arbitrary DLL
// from a working directory. x/sys does not expose GlobalMemoryStatusEx directly.
var globalMemoryStatusEx = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")

// memoryStatusEx matches Microsoft's MEMORYSTATUSEX ABI on amd64 and arm64:
// https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-memorystatusex
// Only TotalPhys and AvailPhys leave the native adapter.
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// Compile-time ABI size checks; both arrays must have non-negative lengths.
var _ [64 - unsafe.Sizeof(memoryStatusEx{})]byte
var _ [unsafe.Sizeof(memoryStatusEx{}) - 64]byte

// Snapshot calls fixed local native APIs. It never consults environment paths,
// enumerates other volumes, runs commands, or contacts a manager.
func Snapshot() model.Device {
	d := snapshotWindows(windowsNativeProvider{}, time.Now().UTC())
	d.LastSeen = time.Now().UTC()
	return d
}

func (windowsNativeProvider) version() (*windowsVersion, error) {
	version := windows.RtlGetVersion()
	if version == nil {
		return nil, errors.New("operating system version unavailable")
	}
	return &windowsVersion{major: version.MajorVersion, minor: version.MinorVersion, build: version.BuildNumber}, nil
}

func (windowsNativeProvider) uptime() (*time.Duration, error) {
	// x/sys DurationSinceBoot wraps GetTickCount64, not the wrapping 32-bit API.
	uptime := windows.DurationSinceBoot()
	return &uptime, nil
}

func (windowsNativeProvider) memory() (*physicalMemory, error) {
	if err := globalMemoryStatusEx.Find(); err != nil {
		return nil, err
	}
	status := memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	result, _, err := globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&status)))
	if result == 0 {
		if err == nil || errors.Is(err, windows.ERROR_SUCCESS) {
			return nil, errors.New("physical memory query failed")
		}
		return nil, err
	}
	return &physicalMemory{total: status.TotalPhys, available: status.AvailPhys}, nil
}

func (windowsNativeProvider) systemVolume() (*volumeCapacity, error) {
	return queryWindowsSystemVolume(windowsNativeVolumeProvider{})
}

type windowsNativeVolumeProvider struct{}

func (windowsNativeVolumeProvider) systemDirectory() (string, error) {
	return windows.GetSystemDirectory()
}

func (windowsNativeVolumeProvider) fixedDrive(root string) bool {
	path, err := windows.UTF16PtrFromString(root)
	return err == nil && windows.GetDriveType(path) == windows.DRIVE_FIXED
}

func (windowsNativeVolumeProvider) capacity(root string) (*volumeCapacity, error) {
	path, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return nil, err
	}
	var available, total uint64
	// Do not mix caller-quota total with whole-volume free bytes. The matching
	// caller-available value keeps the denominator and numerator in one scope.
	if err := windows.GetDiskFreeSpaceEx(path, &available, &total, nil); err != nil {
		return nil, err
	}
	return &volumeCapacity{total: total, available: available}, nil
}
