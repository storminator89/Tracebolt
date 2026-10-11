//go:build windows

package windowssessions

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

var wtsDLL = windows.NewLazySystemDLL("wtsapi32.dll")
var wtsEnumerate = wtsDLL.NewProc("WTSEnumerateSessionsW")
var wtsQuery = wtsDLL.NewProc("WTSQuerySessionInformationW")
var wtsFree = wtsDLL.NewProc("WTSFreeMemory")
var netDLL = windows.NewLazySystemDLL("netapi32.dll")
var netJoin = netDLL.NewProc("NetGetJoinInformation")
var netSize = netDLL.NewProc("NetApiBufferSize")
var netFree = netDLL.NewProc("NetApiBufferFree")

type wtsSessionInfo struct {
	ID      uint32
	Station *uint16
	State   uint32
}

func nativeError(e error) error {
	if errors.Is(e, windows.ERROR_ACCESS_DENIED) {
		return ErrDenied
	}
	return ErrUnavailable
}

// Fixed WTS_CURRENT_SERVER_HANDLE, Reserved=0, Version=1. The OS owns the
// allocation before returning; there is no API input for a pre-allocation cap.
// Reject over-cap counts before traversal, never read station-name pointers,
// and always free the native allocation inside the owned bounded worker.
func nativeSessions(ctx context.Context) (Sessions, error) {
	for _, p := range []*windows.LazyProc{wtsEnumerate, wtsQuery, wtsFree} {
		if p.Find() != nil {
			return Sessions{}, ErrUnavailable
		}
	}
	if e := ctx.Err(); e != nil {
		return Sessions{}, e
	}
	var ptr *wtsSessionInfo
	var count uint32
	ok, _, callErr := wtsEnumerate.Call(0, 0, 1, uintptr(unsafe.Pointer(&ptr)), uintptr(unsafe.Pointer(&count)))
	if ptr != nil {
		defer wtsFree.Call(uintptr(unsafe.Pointer(ptr)))
	}
	if ok == 0 {
		return Sessions{}, nativeError(callErr)
	}
	if count > MaxNativeSessions {
		return Sessions{}, ErrBounds
	}
	if count > 0 && ptr == nil {
		return Sessions{}, ErrMetadata
	}
	rows := make([]nativeSession, 0, count)
	if count > 0 {
		for _, r := range unsafe.Slice(ptr, int(count)) {
			rows = append(rows, nativeSession{r.ID, r.State})
		}
	}
	selected, e := selectSessions(rows)
	if e != nil {
		return Sessions{}, e
	}
	result := Sessions{ObservedCount: &count, Rows: []Session{}}
	for _, r := range selected {
		if e := ctx.Err(); e != nil {
			return Sessions{}, e
		}
		user, uq := queryLabel(r.ID, 5)
		domain, dq := queryLabel(r.ID, 7)
		protocol := "unknown"
		raw, e := querySession(r.ID, 16, 2)
		if e == nil {
			protocol = sessionProtocol(raw)
		}
		result.Rows = append(result.Rows, Session{r.ID, user, uq, domain, dq, sessionState(r.State), protocol})
	}
	return finishSessions(result), nil
}
func queryLabel(id, class uint32) (*string, string) {
	raw, e := querySession(id, class, 2*(MaxLabelUnits+1))
	if errors.Is(e, ErrDenied) {
		return nil, "denied"
	}
	if e != nil {
		return nil, "unavailable"
	}
	v, e := decodeLabel(raw, MaxLabelUnits)
	if e != nil {
		return nil, "unavailable"
	}
	if v == nil {
		return nil, "empty"
	}
	return v, "observed"
}
func querySession(id, class uint32, maxBytes uint32) ([]byte, error) {
	// Deliberately closed allowlist, even for private callers.
	if class != 5 && class != 7 && class != 16 {
		return nil, ErrInvalid
	}
	var ptr *byte
	var size uint32
	ok, _, callErr := wtsQuery.Call(0, uintptr(id), uintptr(class), uintptr(unsafe.Pointer(&ptr)), uintptr(unsafe.Pointer(&size)))
	if ptr != nil {
		defer wtsFree.Call(uintptr(unsafe.Pointer(ptr)))
	}
	if ok == 0 {
		return nil, nativeError(callErr)
	}
	if size > maxBytes {
		return nil, ErrBounds
	}
	if ptr == nil || size == 0 {
		return nil, ErrMetadata
	}
	return append([]byte{}, unsafe.Slice(ptr, int(size))...), nil
}
func nativeJoin(ctx context.Context) (Join, error) {
	for _, p := range []*windows.LazyProc{netJoin, netSize, netFree} {
		if p.Find() != nil {
			return Join{}, ErrUnavailable
		}
	}
	if e := ctx.Err(); e != nil {
		return Join{}, e
	}
	var ptr *byte
	var status uint32
	code, _, _ := netJoin.Call(0, uintptr(unsafe.Pointer(&ptr)), uintptr(unsafe.Pointer(&status)))
	if ptr != nil {
		defer netFree.Call(uintptr(unsafe.Pointer(ptr)))
	}
	if code != 0 {
		return Join{}, nativeError(syscall.Errno(code))
	}
	j := Join{Quality: "observed"}
	switch status {
	case 1:
		j.Status = "unjoined"
		return j, nil
	case 2:
		j.Status = "workgroup"
	case 3:
		j.Status = "domain"
	default:
		return Join{}, ErrUnavailable
	}
	j.Quality = "partial"
	j.Reason = ErrMetadata.Error()
	if ptr == nil {
		return j, nil
	}
	var size uint32
	code, _, _ = netSize.Call(uintptr(unsafe.Pointer(ptr)), uintptr(unsafe.Pointer(&size)))
	if code != 0 {
		return j, nil
	}
	if size > 2*(MaxJoinUnits+1) {
		j.Reason = ErrBounds.Error()
		return j, nil
	}
	if size < 2 {
		return j, nil
	}
	name, e := decodeLabel(unsafe.Slice(ptr, int(size)), MaxJoinUnits)
	if e != nil || name == nil {
		return j, nil
	}
	j.Name = name
	j.Quality = "observed"
	j.Reason = ""
	return j, nil
}
