//go:build windows

package windowseventcontent

import (
	"context"
	"errors"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	evtQueryChannelPath    = 0x1
	evtFormatMessageEvent  = 1
	evtRenderContextValues = 0
	evtRenderEventValues   = 0
	nextTimeoutMillis      = 250
)

var (
	evtDLL                   = windows.NewLazySystemDLL("wevtapi.dll")
	evtQuery                 = evtDLL.NewProc("EvtQuery")
	evtNext                  = evtDLL.NewProc("EvtNext")
	evtCreateRenderContext   = evtDLL.NewProc("EvtCreateRenderContext")
	evtRender                = evtDLL.NewProc("EvtRender")
	evtClose                 = evtDLL.NewProc("EvtClose")
	evtOpenPublisherMetadata = evtDLL.NewProc("EvtOpenPublisherMetadata")
	evtFormatMessage         = evtDLL.NewProc("EvtFormatMessage")
)

// Read formats only exact, explicitly selected local Application/System events.
// Query handles and all dependent operations stay on the creating OS thread.
// Cancellation is cooperative: EvtNext has a finite timeout, but EvtQuery,
// EvtRender, EvtOpenPublisherMetadata and EvtFormatMessage have no timeout
// argument. No abandoned goroutine pretends to preempt an in-flight native call.
func Read(ctx context.Context, request Request) (Report, error) {
	if err := ValidateRequest(request); err != nil {
		return Report{}, err
	}
	if ctx == nil {
		return Report{}, ErrInvalidInput
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return readWith(ctx, request, openNativeSelection)
}

type nativeCursor struct {
	query         uintptr
	renderContext uintptr
	event         uintptr
	channel       string
}

func openNativeSelection(ctx context.Context, selected Event) (cursor, error) {
	if !validEvent(selected, selected.Channel) {
		return nil, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, proc := range []*windows.LazyProc{evtQuery, evtNext, evtCreateRenderContext, evtRender, evtClose, evtOpenPublisherMetadata, evtFormatMessage} {
		if err := proc.Find(); err != nil {
			return nil, ErrUnavailable
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, err := windows.UTF16PtrFromString(selected.Channel)
	if err != nil {
		return nil, ErrInvalidInput
	}
	queryText, err := windows.UTF16PtrFromString(selectionQuery(selected.RecordID))
	if err != nil {
		return nil, ErrInvalidInput
	}
	// NULL Session is local. Query text contains only a validated uint64 record
	// ID, never a caller XPath, file path, remote session or subscription.
	query, _, callErr := evtQuery.Call(0, uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(queryText)), evtQueryChannelPath)
	runtime.KeepAlive(path)
	runtime.KeepAlive(queryText)
	if query == 0 {
		return nil, nativeError(callErr)
	}
	reader := &nativeCursor{query: query, channel: selected.Channel}
	if err := ctx.Err(); err != nil {
		_ = reader.Close()
		return nil, err
	}

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

func (r *nativeCursor) Metadata(ctx context.Context) (Event, error) {
	if err := ctx.Err(); err != nil {
		return Event{}, err
	}
	if r.event == 0 || r.renderContext == 0 {
		return Event{}, ErrReadFailed
	}
	var used, count uint32
	ok, _, callErr := evtRender.Call(r.renderContext, r.event, evtRenderEventValues, 0, 0,
		uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&count)))
	if err := ctx.Err(); err != nil {
		return Event{}, err
	}
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
	if err := ctx.Err(); err != nil {
		return Event{}, err
	}
	if used > uint32(capacity) {
		return Event{}, ErrInvalidData
	}
	event, err := parseMetadataValues(buffer[:used], uint64(uintptr(unsafe.Pointer(&storage[0]))), count, r.channel)
	runtime.KeepAlive(storage)
	return event, err
}

func (r *nativeCursor) Message(ctx context.Context, provider string) (message string, err error) {
	if r.event == 0 || !validProvider(provider) {
		return "", ErrInvalidData
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	name, conversionErr := windows.UTF16PtrFromString(provider)
	if conversionErr != nil {
		return "", ErrInvalidData
	}
	// Local registered publisher only, no archived file, caller locale or remote
	// session. The provider comes from the identity-checked selected event.
	publisher, _, callErr := evtOpenPublisherMetadata.Call(0, uintptr(unsafe.Pointer(name)), 0, 0, 0)
	runtime.KeepAlive(name)
	if publisher == 0 {
		return "", publisherError(callErr)
	}
	defer func() {
		if closeErr := closeHandle(&publisher); closeErr != nil && err == nil {
			message, err = "", closeErr
		}
	}()
	return formatMessage(ctx, func(buffer []uint16) (uint32, error) {
		var used uint32
		var pointer *uint16
		if len(buffer) != 0 {
			pointer = &buffer[0]
		}
		ok, _, callErr := evtFormatMessage.Call(publisher, r.event, 0, 0, 0, evtFormatMessageEvent,
			uintptr(len(buffer)), uintptr(unsafe.Pointer(pointer)), uintptr(unsafe.Pointer(&used)))
		runtime.KeepAlive(buffer)
		if ok != 0 {
			return used, nil
		}
		if errors.Is(callErr, windows.ERROR_INSUFFICIENT_BUFFER) {
			return used, errInsufficientBuffer
		}
		return used, messageError(callErr)
	})
}

func publisherError(err error) error {
	switch {
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND), errors.Is(err, windows.ERROR_PATH_NOT_FOUND),
		errors.Is(err, windows.ERROR_EVT_PUBLISHER_METADATA_NOT_FOUND), errors.Is(err, windows.ERROR_EVT_MESSAGE_LOCALE_NOT_FOUND):
		return ErrPublisherUnavailable
	default:
		return nativeError(err)
	}
}

func messageError(err error) error {
	switch {
	case errors.Is(err, windows.ERROR_EVT_MESSAGE_NOT_FOUND), errors.Is(err, windows.ERROR_EVT_MESSAGE_ID_NOT_FOUND),
		errors.Is(err, windows.ERROR_EVT_UNRESOLVED_VALUE_INSERT), errors.Is(err, windows.ERROR_EVT_UNRESOLVED_PARAMETER_INSERT),
		errors.Is(err, windows.ERROR_EVT_MAX_INSERTS_REACHED), errors.Is(err, windows.ERROR_EVT_EVENT_DEFINITION_NOT_FOUND),
		errors.Is(err, windows.ERROR_EVT_MESSAGE_LOCALE_NOT_FOUND), errors.Is(err, windows.ERROR_MUI_FILE_NOT_FOUND),
		errors.Is(err, windows.ERROR_RESOURCE_LANG_NOT_FOUND), errors.Is(err, windows.ERROR_RESOURCE_NAME_NOT_FOUND),
		errors.Is(err, windows.ERROR_RESOURCE_TYPE_NOT_FOUND), errors.Is(err, windows.ERROR_RESOURCE_DATA_NOT_FOUND):
		return ErrMessageUnavailable
	default:
		return nativeError(err)
	}
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
