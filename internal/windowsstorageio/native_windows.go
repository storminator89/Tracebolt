//go:build windows

package windowsstorageio

import (
	"context"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var pdhDLL = windows.NewLazySystemDLL("pdh.dll")
var pdhOpenQuery = pdhDLL.NewProc("PdhOpenQueryW")
var pdhAddEnglishCounter = pdhDLL.NewProc("PdhAddEnglishCounterW")
var pdhCollectQueryData = pdhDLL.NewProc("PdhCollectQueryData")
var pdhGetFormattedCounterValue = pdhDLL.NewProc("PdhGetFormattedCounterValue")
var pdhCloseQuery = pdhDLL.NewProc("PdhCloseQuery")

type nativeQuery struct {
	handle   uintptr
	counters [8]uintptr
}

// Null data source means live local counters, never a log file. Handles and
// DWORD_PTR are pointer-sized, while PDH_STATUS is a 32-bit LONG status code.
// https://learn.microsoft.com/en-us/windows/win32/api/pdh/nf-pdh-pdhopenqueryw
func nativePerfDisk(ctx context.Context) (PerfDisk, error) {
	if e := ctx.Err(); e != nil {
		return PerfDisk{}, e
	}
	for _, p := range []*windows.LazyProc{pdhOpenQuery, pdhAddEnglishCounter, pdhCollectQueryData, pdhGetFormattedCounterValue, pdhCloseQuery} {
		if p.Find() != nil {
			return PerfDisk{}, ErrUnsupported
		}
	}
	q := &nativeQuery{}
	status, _, _ := pdhOpenQuery.Call(0, 0, uintptr(unsafe.Pointer(&q.handle)))
	runtime.KeepAlive(q)
	if e := pdhError(uint32(status)); e != nil {
		return PerfDisk{}, e
	}
	if q.handle == 0 {
		return PerfDisk{}, ErrMetadata
	}
	return collectPDH(ctx, q, realClock{})
}

// PdhAddEnglishCounterW supplies language-neutral fixed paths. It may succeed
// for a missing instance; later formatted CStatus validation remains required.
// https://learn.microsoft.com/en-us/windows/win32/api/pdh/nf-pdh-pdhaddenglishcounterw
func (q *nativeQuery) add(index int) uint32 {
	if index < 0 || index >= len(counterPaths) {
		return 0xC0000BBD
	}
	path, e := windows.UTF16PtrFromString(counterPaths[index])
	if e != nil {
		return 0xC0000BBD
	}
	status, _, _ := pdhAddEnglishCounter.Call(q.handle, uintptr(unsafe.Pointer(path)), 0, uintptr(unsafe.Pointer(&q.counters[index])))
	runtime.KeepAlive(path)
	runtime.KeepAlive(q)
	if uint32(status) == 0 && q.counters[index] == 0 {
		return pdhInvalidData
	}
	return uint32(status)
}
func (q *nativeQuery) collect() uint32 {
	status, _, _ := pdhCollectQueryData.Call(q.handle)
	runtime.KeepAlive(q)
	return uint32(status)
}

// Explicit DOUBLE|NOSCALE|NOCAP100, no formatted array or raw counter export.
// The optional counter-type output is not requested.
// https://learn.microsoft.com/en-us/windows/win32/api/pdh/nf-pdh-pdhgetformattedcountervalue
func (q *nativeQuery) formatted(index int) (uint32, formattedValue) {
	v := formattedValue{CStatus: pdhCounterInvalidData}
	status, _, _ := pdhGetFormattedCounterValue.Call(q.counters[index], uintptr(pdhFormat), 0, uintptr(unsafe.Pointer(&v)))
	runtime.KeepAlive(q)
	runtime.KeepAlive(&v)
	return uint32(status), v
}

// PdhCloseQuery also releases all counters owned by this query.
// https://learn.microsoft.com/en-us/windows/win32/api/pdh/nf-pdh-pdhclosequery
func (q *nativeQuery) close() {
	if q.handle != 0 {
		pdhCloseQuery.Call(q.handle)
		q.handle = 0
		q.counters = [8]uintptr{}
	}
}

// Compile-time ABI assertions, including when Windows tests are cross-compiled.
var _ [16 - unsafe.Sizeof(formattedValue{})]byte
var _ [unsafe.Sizeof(formattedValue{}) - 16]byte
var _ [8 - unsafe.Offsetof(formattedValue{}.DoubleValue)]byte
var _ [unsafe.Offsetof(formattedValue{}.DoubleValue) - 8]byte
