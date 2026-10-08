//go:build windows

package windowsprocessmetrics

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"runtime"
	"unsafe"
)

// PROCESS_MEMORY_COUNTERS uses SIZE_T, hence uintptr, for both 32/64-bit ABIs.
type memoryCounters struct {
	Size, PageFaultCount                                                                                                                                                   uint32
	PeakWorkingSetSize, WorkingSetSize, QuotaPeakPagedPoolUsage, QuotaPagedPoolUsage, QuotaPeakNonPagedPoolUsage, QuotaNonPagedPoolUsage, PagefileUsage, PeakPagefileUsage uintptr
}

var memoryInfo = windows.NewLazySystemDLL("psapi.dll").NewProc("GetProcessMemoryInfo")

type nativeAPI struct {
	open   func(uint32, bool, uint32) (windows.Handle, error)
	close  func(windows.Handle) error
	times  func(windows.Handle) (uint64, uint64, uint64, error)
	memory func(windows.Handle) (uint64, error)
}

func ticks(t windows.Filetime) uint64 { return uint64(t.HighDateTime)<<32 | uint64(t.LowDateTime) }

var systemAPI = nativeAPI{
	open: windows.OpenProcess, close: windows.CloseHandle,
	times: func(h windows.Handle) (uint64, uint64, uint64, error) {
		var creation, exit, kernel, user windows.Filetime
		e := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user)
		return ticks(creation), ticks(kernel), ticks(user), e
	},
	memory: func(h windows.Handle) (uint64, error) {
		if e := memoryInfo.Find(); e != nil {
			return 0, ErrUnavailable
		}
		var m memoryCounters
		m.Size = uint32(unsafe.Sizeof(m))
		ok, _, e := memoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&m)), uintptr(m.Size))
		runtime.KeepAlive(&m)
		if ok == 0 {
			if e == nil {
				return 0, ErrUnavailable
			}
			return 0, e
		}
		return uint64(m.WorkingSetSize), nil
	},
}

func nativeError(e error) error {
	if e == nil {
		return nil
	}
	if errors.Is(e, windows.ERROR_ACCESS_DENIED) {
		return ErrDenied
	}
	return ErrUnavailable
}
func readNative(ctx context.Context, pid uint32) reading { return readNativeUsing(ctx, pid, systemAPI) }
func readNativeUsing(ctx context.Context, pid uint32, api nativeAPI) (r reading) {
	if e := ctx.Err(); e != nil {
		return reading{CPUErr: e, MemoryErr: e}
	}
	// Limited query only; never PROCESS_VM_READ, debug privilege or fallback rights.
	h, e := api.open(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if e != nil {
		return reading{CPUErr: nativeError(e), MemoryErr: nativeError(e)}
	}
	defer api.close(h)
	if e = ctx.Err(); e != nil {
		return reading{CPUErr: e, MemoryErr: e}
	}
	r.Creation, r.Kernel, r.User, e = api.times(h)
	r.CPUErr = nativeError(e)
	if e = ctx.Err(); e != nil {
		r.MemoryErr = e
		return r
	}
	r.Memory, e = api.memory(h)
	r.MemoryErr = nativeError(e)
	return r
}
