//go:build windows

package windowsfullprocesses

import (
	"context"
	"errors"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type toolhelpSnapshot struct {
	handle windows.Handle
	first  bool
	entry  windows.ProcessEntry32
}

// Collect requests only TH32CS_SNAPPROCESS, never modules, heaps, paths,
// process-owner tokens, process handles or additional token privileges.
func Collect(ctx context.Context) (Capture, error) {
	return collectSnapshot(ctx, func(ctx context.Context) (processSnapshot, error) {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		handle, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
		if e != nil {
			return nil, nativeError(e)
		}
		return &toolhelpSnapshot{handle: handle, first: true}, nil
	}, func() time.Time { return time.Now().UTC() })
}
func nativeError(e error) error {
	if errors.Is(e, windows.ERROR_NOT_ENOUGH_MEMORY) || errors.Is(e, windows.ERROR_OUTOFMEMORY) {
		return ErrBudget
	}
	if errors.Is(e, windows.ERROR_ACCESS_DENIED) {
		return ErrDenied
	}
	if errors.Is(e, windows.ERROR_CALL_NOT_IMPLEMENTED) || errors.Is(e, windows.ERROR_NOT_SUPPORTED) {
		return ErrUnsupported
	}
	return ErrUnavailable
}
func (s *toolhelpSnapshot) next(ctx context.Context) (nativeEntry, bool, error) {
	if e := ctx.Err(); e != nil {
		return nativeEntry{}, false, e
	}
	s.entry = windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(s.entry))}
	var e error
	if s.first {
		s.first = false
		e = windows.Process32First(s.handle, &s.entry)
	} else {
		e = windows.Process32Next(s.handle, &s.entry)
	}
	if errors.Is(e, windows.ERROR_NO_MORE_FILES) {
		return nativeEntry{}, true, nil
	}
	if e != nil {
		return nativeEntry{}, false, nativeError(e)
	}
	return nativeEntry{pid: s.entry.ProcessID, parentPID: s.entry.ParentProcessID, threads: s.entry.Threads, name: s.entry.ExeFile}, false, nil
}
func (s *toolhelpSnapshot) close() { windows.CloseHandle(s.handle) }
