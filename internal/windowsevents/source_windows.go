//go:build windows

package windowsevents

import (
	"context"
	"errors"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	evtQueryChannelPath      = 0x1
	evtQueryReverseDirection = 0x200
	evtRenderContextValues   = 0
	evtRenderEventValues     = 0
	nextTimeoutMillis        = 250
)

var (
	evtDLL                 = windows.NewLazySystemDLL("wevtapi.dll")
	evtQuery               = evtDLL.NewProc("EvtQuery")
	evtNext                = evtDLL.NewProc("EvtNext")
	evtCreateRenderContext = evtDLL.NewProc("EvtCreateRenderContext")
	evtRender              = evtDLL.NewProc("EvtRender")
	evtClose               = evtDLL.NewProc("EvtClose")
)

// Collect reads only explicitly requested Application/System metadata on the
// local machine. The query is fixed, newest first. No native read occurs at init.
// Cancellation is cooperative between synchronous native calls; EvtNext has a
// finite timeout. EvtQuery/EvtRender have no native timeout, so the five-second
// collection budget cannot preempt an in-flight OS call. No worker is abandoned.
func Collect(ctx context.Context, channels []string, limit int) (Report, error) {
	if err := validateInput(ctx, channels, limit); err != nil {
		return Report{}, err
	}
	// Microsoft requires EvtQuery handles to stay on their creating OS thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return collectWith(ctx, channels, limit, openNativeChannel)
}

type nativeCursor struct {
	query         uintptr
	renderContext uintptr
	event         uintptr
	channel       string
}

func openNativeChannel(ctx context.Context, channel string) (cursor, error) {
	if !allowedChannel(channel) {
		return nil, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, proc := range []*windows.LazyProc{evtQuery, evtNext, evtCreateRenderContext, evtRender, evtClose} {
		if err := proc.Find(); err != nil {
			return nil, ErrUnavailable
		}
	}
	path, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return nil, ErrInvalidInput
	}
	// NULL Session is local, NULL Query selects all events; no caller query,
	// exported log file, remote session, bookmarks, subscriptions or tolerance.
	query, _, callErr := evtQuery.Call(0, uintptr(unsafe.Pointer(path)), 0, evtQueryChannelPath|evtQueryReverseDirection)
	runtime.KeepAlive(path)
	if query == 0 {
		return nil, nativeError(callErr)
	}
	reader := &nativeCursor{query: query, channel: channel}
	paths := metadataPaths()
	var valuePaths [metadataPropertyCount]*uint16
	for i, path := range paths {
		valuePaths[i], err = windows.UTF16PtrFromString(path)
		if err != nil {
			_ = reader.Close()
			return nil, ErrReadFailed
		}
	}
	renderContext, _, callErr := evtCreateRenderContext.Call(metadataPropertyCount, uintptr(unsafe.Pointer(&valuePaths[0])), evtRenderContextValues)
	runtime.KeepAlive(valuePaths)
	if renderContext == 0 {
		_ = reader.Close()
		return nil, nativeError(callErr)
	}
	reader.renderContext = renderContext
	return reader, nil
}

func (r *nativeCursor) Next(ctx context.Context) (bool, error) {
	if err := closeHandle(&r.event); err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	timeout := uint32(nextTimeoutMillis)
	if deadline, ok := ctx.Deadline(); ok {
		left := time.Until(deadline)
		if left <= 0 {
			return false, context.DeadlineExceeded
		}
		if left < time.Duration(timeout)*time.Millisecond {
			timeout = uint32((left + time.Millisecond - 1) / time.Millisecond)
		}
	}
	var returned uint32
	ok, _, callErr := evtNext.Call(r.query, 1, uintptr(unsafe.Pointer(&r.event)), uintptr(timeout), 0, uintptr(unsafe.Pointer(&returned)))
	if ok == 0 {
		// Be defensive if an API failure still populated an event handle.
		if err := closeHandle(&r.event); err != nil {
			return false, err
		}
		if errors.Is(callErr, windows.ERROR_NO_MORE_ITEMS) {
			return false, nil
		}
		return false, nativeError(callErr)
	}
	if returned != 1 || r.event == 0 {
		return false, ErrInvalidData
	}
	return true, nil
}

func (r *nativeCursor) Metadata() (Event, error) {
	if r.event == 0 || r.renderContext == 0 {
		return Event{}, ErrReadFailed
	}
	var used, count uint32
	ok, _, callErr := evtRender.Call(r.renderContext, r.event, evtRenderEventValues, 0, 0,
		uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&count)))
	if ok != 0 || !errors.Is(callErr, windows.ERROR_INSUFFICIENT_BUFFER) {
		return Event{}, nativeError(callErr)
	}
	if used > maxRenderBytes {
		return Event{}, ErrBufferLimit
	}
	if used < metadataPropertyCount*variantSize {
		return Event{}, ErrInvalidData
	}
	// uint64 storage supplies EVT_VARIANT alignment on supported Windows arches.
	storage := make([]uint64, (int(used)+7)/8)
	capacity := len(storage) * 8
	buffer := unsafe.Slice((*byte)(unsafe.Pointer(&storage[0])), capacity)
	ok, _, callErr = evtRender.Call(r.renderContext, r.event, evtRenderEventValues, uintptr(capacity), uintptr(unsafe.Pointer(&storage[0])),
		uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&count)))
	if ok == 0 {
		return Event{}, nativeError(callErr)
	}
	if used > uint32(capacity) {
		return Event{}, ErrInvalidData
	}
	event, err := parseMetadataValues(buffer[:used], uint64(uintptr(unsafe.Pointer(&storage[0]))), count, r.channel)
	runtime.KeepAlive(storage)
	return event, err
}

func (r *nativeCursor) Close() error {
	return errors.Join(closeHandle(&r.event), closeHandle(&r.renderContext), closeHandle(&r.query))
}

func closeHandle(handle *uintptr) error {
	if *handle == 0 {
		return nil
	}
	ok, _, callErr := evtClose.Call(*handle)
	*handle = 0
	if ok == 0 {
		return nativeError(callErr)
	}
	return nil
}

func nativeError(err error) error {
	switch {
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return ErrAccessDenied
	case errors.Is(err, windows.ERROR_TIMEOUT):
		return context.DeadlineExceeded
	case errors.Is(err, windows.ERROR_CANCELLED):
		return context.Canceled
	case errors.Is(err, windows.ERROR_EVT_CHANNEL_NOT_FOUND), errors.Is(err, windows.ERROR_SERVICE_DISABLED),
		errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE):
		return ErrUnavailable
	default:
		return ErrReadFailed
	}
}
