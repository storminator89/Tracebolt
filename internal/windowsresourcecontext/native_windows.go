//go:build windows

package windowsresourcecontext

import (
	"context"
	"golang.org/x/sys/windows"
	"runtime"
	"syscall"
	"unsafe"
)

var locatorID = windows.GUID{Data1: 0x76a64158, Data2: 0xcb41, Data3: 0x11d1, Data4: [8]byte{0x8b, 0x02, 0x00, 0x60, 0x08, 0x06, 0xd9, 0xb6}}
var enumID = windows.GUID{Data1: 0x00020404, Data4: [8]byte{0xc0, 0, 0, 0, 0, 0, 0, 0x46}}

const processorNamespace = `Root\CIMV2`
const processorQuery = "SELECT Name, Architecture, NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor"

// Only one fixed local namespace, class and explicit property projection. Five
// bounded Next calls distinguish a complete <=4-row set from a forbidden prefix.
// https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-processor
func nativeProcessors(ctx context.Context) (Processors, error) {
	locator, close, e := openAutomation(ctx, &locatorID)
	if e != nil {
		return Processors{}, e
	}
	defer close()
	server, e := bstrArgument(".")
	if e != nil {
		return Processors{}, e
	}
	defer server.clear()
	namespace, e := bstrArgument(processorNamespace)
	if e != nil {
		return Processors{}, e
	}
	defer namespace.clear()
	service, e := locator.objectValue(ctx, "ConnectServer", dispatchMethod, namespace, server)
	if e != nil {
		return Processors{}, e
	}
	defer service.close()
	query, e := bstrArgument(processorQuery)
	if e != nil {
		return Processors{}, e
	}
	defer query.clear()
	language, e := bstrArgument("WQL")
	if e != nil {
		return Processors{}, e
	}
	defer language.clear()
	rows, e := service.objectValue(ctx, "ExecQuery", dispatchMethod, intArgument(0x30), language, query)
	if e != nil {
		return Processors{}, e
	}
	defer rows.close()
	enumeration, e := rows.invoke(ctx, "_NewEnum", dispatchGet)
	if e != nil {
		return Processors{}, e
	}
	defer enumeration.clear()
	if (enumeration.kind != 13 && enumeration.kind != vtDispatch) || enumeration.data[0] == 0 {
		return Processors{}, ErrMetadata
	}
	unknown := (*dispatchObject)(enumeration.pointer())
	var enumerator *dispatchObject
	hr, _, _ := syscall.SyscallN(unknown.table[0], uintptr(unsafe.Pointer(unknown)), uintptr(unsafe.Pointer(&enumID)), uintptr(unsafe.Pointer(&enumerator)))
	if e = hrError(hr); e != nil {
		return Processors{}, e
	}
	if enumerator == nil {
		return Processors{}, ErrMetadata
	}
	defer syscall.SyscallN(enumerator.table[2], uintptr(unsafe.Pointer(enumerator)))
	result := make([]Processor, 0, MaxProcessors)
	for i := 0; i <= MaxProcessors; i++ {
		if e = ctx.Err(); e != nil {
			return Processors{}, e
		}
		var value variant
		var fetched uint32
		hr, _, _ = syscall.SyscallN(enumerator.table[3], uintptr(unsafe.Pointer(enumerator)), 1, uintptr(unsafe.Pointer(&value)), uintptr(unsafe.Pointer(&fetched)))
		runtime.KeepAlive(enumerator)
		if e = hrError(hr); e != nil {
			value.clear()
			return Processors{}, e
		}
		// IEnumVARIANT::Next returns S_FALSE only when fewer than one was fetched.
		if fetched > 1 || uint32(hr) > 1 || ((uint32(hr) == 1) != (fetched == 0)) {
			value.clear()
			return Processors{}, ErrMetadata
		}
		if fetched == 0 {
			value.clear()
			return finishProcessors(result)
		}
		if i == MaxProcessors {
			value.clear()
			return Processors{}, ErrBounds
		}
		if value.kind != vtDispatch || value.data[0] == 0 {
			value.clear()
			return Processors{}, ErrMetadata
		}
		object := &automation{(*dispatchObject)(value.pointer())}
		name, ne := object.text(ctx, "Name", MaxStringUnits)
		arch, ae := object.unsigned(ctx, "Architecture")
		cores, ce := object.unsigned(ctx, "NumberOfCores")
		logical, le := object.unsigned(ctx, "NumberOfLogicalProcessors")
		result = append(result, Processor{observedField(name, ne), architectureField(arch, ae), countField(cores, ce), countField(logical, le)})
		value.clear()
	}
	return Processors{}, ErrBounds
}

// WMI scripting uint16 is returned as VT_I4; permit the equivalent scalar
// unsigned representations while rejecting coercions, arrays and signed negatives.
func (a *automation) unsigned(ctx context.Context, name string) (uint32, error) {
	v, e := a.invoke(ctx, name, dispatchGet)
	if e != nil {
		return 0, e
	}
	defer v.clear()
	switch v.kind {
	case vtI4:
		n := int32(uint32(v.data[0]))
		if n < 0 {
			return 0, ErrMetadata
		}
		return uint32(n), nil
	case 18:
		return uint32(uint16(v.data[0])), nil
	case 19:
		return uint32(v.data[0]), nil
	default:
		return 0, ErrMetadata
	}
}

var memoryDLL = windows.NewLazySystemDLL("kernel32.dll")
var getInstalledMemory = memoryDLL.NewProc("GetPhysicallyInstalledSystemMemory")
var getPerformanceInfo = memoryDLL.NewProc("K32GetPerformanceInfo")
var pagefilesDLL = windows.NewLazySystemDLL("psapi.dll")
var enumPageFiles = pagefilesDLL.NewProc("EnumPageFilesW")

// SIZE_T is pointer-width. Anonymous fields reserve excluded members without
// making their values available to source logic. On x64/arm64 the size is104.
// https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-performance_information
// https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getperformanceinfo
type performanceInformation struct {
	Size                             uint32
	CommitTotal, CommitLimit         uintptr
	_                                uintptr // CommitPeak
	PhysicalTotal, PhysicalAvailable uintptr
	_                                [4]uintptr // SystemCache, KernelTotal, KernelPaged, KernelNonpaged
	PageSize                         uintptr
	_                                [3]uint32 // HandleCount, ProcessCount, ThreadCount
}

// SIZE_T is pointer-width. Size32 on x64/arm64,20 on386. PeakUsage is never read.
// https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-enum_page_file_information
type enumPageFileInformation struct {
	Size                  uint32
	_                     uint32 // Reserved
	TotalSize, TotalInUse uintptr
	_                     uintptr // PeakUsage
}

func nativeCallError(e error) error {
	if e == windows.ERROR_ACCESS_DENIED {
		return ErrDenied
	}
	if e == windows.ERROR_INVALID_DATA {
		return ErrMetadata
	}
	return ErrUnavailable
}

// https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getphysicallyinstalledsystemmemory
func nativeInstalledMemory(ctx context.Context) (InstalledMemory, error) {
	if e := ctx.Err(); e != nil {
		return InstalledMemory{}, e
	}
	if getInstalledMemory.Find() != nil {
		return InstalledMemory{}, ErrUnsupported
	}
	var kb uint64
	r, _, e := getInstalledMemory.Call(uintptr(unsafe.Pointer(&kb)))
	runtime.KeepAlive(&kb)
	if r == 0 {
		return InstalledMemory{}, nativeCallError(e)
	}
	if e := ctx.Err(); e != nil {
		return InstalledMemory{}, e
	}
	return installedMemoryFromKB(kb)
}

// Only allowlisted scalars leave the native buffer. The pagefile worker reads
// PageSize only; no excluded structure member is copied into its source model.
type performanceValues struct{ CommitTotal, CommitLimit, PhysicalTotal, PhysicalAvailable, PageSize uint64 }

func readPerformanceInformation(ctx context.Context, pageSizeOnly bool) (performanceValues, error) {
	if e := ctx.Err(); e != nil {
		return performanceValues{}, e
	}
	if getPerformanceInfo.Find() != nil {
		return performanceValues{}, ErrUnsupported
	}
	var p performanceInformation
	p.Size = uint32(unsafe.Sizeof(p))
	r, _, e := getPerformanceInfo.Call(uintptr(unsafe.Pointer(&p)), uintptr(p.Size))
	runtime.KeepAlive(&p)
	if r == 0 {
		return performanceValues{}, nativeCallError(e)
	}
	if e := ctx.Err(); e != nil {
		return performanceValues{}, e
	}
	if p.Size != uint32(unsafe.Sizeof(p)) || !validPageSize(uint64(p.PageSize)) {
		return performanceValues{}, ErrMetadata
	}
	v := performanceValues{PageSize: uint64(p.PageSize)}
	if !pageSizeOnly {
		v.CommitTotal = uint64(p.CommitTotal)
		v.CommitLimit = uint64(p.CommitLimit)
		v.PhysicalTotal = uint64(p.PhysicalTotal)
		v.PhysicalAvailable = uint64(p.PhysicalAvailable)
	}
	return v, nil
}
func nativeMemory(ctx context.Context) (Memory, error) {
	p, e := readPerformanceInformation(ctx, false)
	if e != nil {
		return Memory{}, e
	}
	return memoryFromPages(uint64(p.CommitTotal), uint64(p.CommitLimit), uint64(p.PhysicalTotal), uint64(p.PhysicalAvailable), uint64(p.PageSize))
}

type pagefileRead struct {
	ctx       context.Context
	aggregate pagefileAccumulator
}

// PENUM_PAGE_FILE_CALLBACKW returns BOOL (0/1), not a Win32 status code.
// The unnamed filename argument is never dereferenced, copied or retained.
// https://learn.microsoft.com/en-us/windows/win32/api/psapi/nc-psapi-penum_page_file_callbackw
func pagefileCallback(contextPointer uintptr, info *enumPageFileInformation, _ uintptr) uintptr {
	if contextPointer == 0 {
		return 0
	}
	state := (*pagefileRead)(unsafe.Pointer(contextPointer))
	if e := state.ctx.Err(); e != nil {
		state.aggregate.err = e
		return 0
	}
	if state.aggregate.count >= MaxPagefiles {
		state.aggregate.err = ErrBounds
		return 0
	}
	if info == nil || info.Size != uint32(unsafe.Sizeof(enumPageFileInformation{})) {
		state.aggregate.err = ErrMetadata
		return 0
	}
	if !state.aggregate.add(uint64(info.TotalSize), uint64(info.TotalInUse)) {
		return 0
	}
	return 1
}

var pagefileCallbackPointer = syscall.NewCallback(pagefileCallback)

// https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumpagefilesw
func nativePagefiles(ctx context.Context) (Pagefiles, error) {
	if e := ctx.Err(); e != nil {
		return Pagefiles{}, e
	}
	if enumPageFiles.Find() != nil {
		return Pagefiles{}, ErrUnsupported
	}
	// This independent worker obtains only PageSize from its own fixed API read;
	// it does not depend on or copy the separately captured memory source.
	p, e := readPerformanceInformation(ctx, true)
	if e != nil {
		return Pagefiles{}, e
	}
	state := pagefileRead{ctx: ctx}
	r, _, e := enumPageFiles.Call(pagefileCallbackPointer, uintptr(unsafe.Pointer(&state)))
	runtime.KeepAlive(&state)
	if e := ctx.Err(); e != nil {
		return Pagefiles{}, e
	}
	if state.aggregate.err != nil {
		return Pagefiles{}, state.aggregate.err
	}
	if r == 0 {
		return Pagefiles{}, nativeCallError(e)
	}
	return state.aggregate.finish(true, uint64(p.PageSize))
}
