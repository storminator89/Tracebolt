//go:build windows

package windowsfullservices

import (
	"context"
	"errors"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Collect reads only SERVICE_WIN32 status metadata with enumeration rights.
// No service handle, configuration, executable path, account or driver is read.
func Collect(ctx context.Context) (Capture, error) {
	if ctx == nil {
		return Capture{}, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return Capture{}, e
	}
	started := time.Now().UTC()
	captureContext, cancel := context.WithTimeout(ctx, CaptureTimeout)
	defer cancel()
	ctx = captureContext
	manager, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ENUMERATE_SERVICE)
	if e != nil {
		reason := "unavailable"
		if errors.Is(e, windows.ERROR_ACCESS_DENIED) {
			reason = "access_denied"
		}
		at := time.Now().UTC()
		return Capture{StartedAt: started, FinishedAt: at, Rows: []Row{}, Reason: reason}, ErrUnavailable
	}
	defer windows.CloseServiceHandle(manager)
	buf := make([]byte, NativePageBytes)
	captured, collectErr := collectPages(ctx, func(ctx context.Context, resume uint32) (enumerationPage, error) {
		if e := ctx.Err(); e != nil {
			return enumerationPage{}, e
		}
		clear(buf)
		var needed, count uint32
		e := windows.EnumServicesStatusEx(manager, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_WIN32, windows.SERVICE_STATE_ALL, &buf[0], uint32(len(buf)), &needed, &count, &resume, nil)
		if e != nil && !errors.Is(e, windows.ERROR_MORE_DATA) {
			if errors.Is(e, windows.ERROR_ACCESS_DENIED) {
				return enumerationPage{}, ErrDenied
			}
			return enumerationPage{}, ErrUnavailable
		}
		size := unsafe.Sizeof(windows.ENUM_SERVICE_STATUS_PROCESS{})
		if uint64(count) > uint64(len(buf))/uint64(size) {
			return enumerationPage{}, ErrInvalid
		}
		page := enumerationPage{rows: make([]Row, 0, count), next: resume, more: errors.Is(e, windows.ERROR_MORE_DATA), workBytes: len(buf)}
		for i := uint32(0); i < count; i++ {
			if e := ctx.Err(); e != nil {
				return enumerationPage{}, e
			}
			entry := (*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[uintptr(i)*size]))
			name, ok := nativeString(buf, entry.ServiceName)
			if !ok || name == "" {
				return enumerationPage{}, ErrInvalid
			}
			row := Row{Name: name, DisplayNameQuality: "unavailable", StateQuality: "unavailable", PIDQuality: "unavailable"}
			if display, ok := nativeString(buf, entry.DisplayName); ok {
				row.DisplayName = &display
				row.DisplayNameQuality = "observed"
			}
			if state, ok := nativeState(entry.ServiceStatusProcess.CurrentState); ok {
				row.State = &state
				row.StateQuality = "observed"
			}
			if StatePIDValid(row.State) {
				pid := entry.ServiceStatusProcess.ProcessId
				row.PID = &pid
				row.PIDQuality = "observed"
			}
			page.rows = append(page.rows, row)
		}
		runtime.KeepAlive(buf)
		return page, nil
	}, func() time.Time { return time.Now().UTC() })
	captured.StartedAt = started
	if captured.FinishedAt.Sub(started) > CaptureTimeout {
		captured.Complete = false
		captured.Rows = []Row{}
		captured.Reason = "deadline"
		return captured, ErrUnavailable
	}
	return captured, collectErr
}
