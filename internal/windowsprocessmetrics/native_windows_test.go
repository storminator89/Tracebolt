//go:build windows

package windowsprocessmetrics

import (
	"context"
	"golang.org/x/sys/windows"
	"testing"
)

func TestNativeMinimalRightsCloseAndCancel(t *testing.T) {
	closed, times, memory := 0, 0, 0
	ctx, cancel := context.WithCancel(context.Background())
	api := nativeAPI{
		open: func(rights uint32, inherit bool, pid uint32) (windows.Handle, error) {
			if rights != windows.PROCESS_QUERY_LIMITED_INFORMATION || inherit || pid != 42 {
				t.Fatal(rights, inherit, pid)
			}
			return 7, nil
		},
		close: func(h windows.Handle) error {
			if h != 7 {
				t.Fatal(h)
			}
			closed++
			return nil
		},
		times:  func(windows.Handle) (uint64, uint64, uint64, error) { times++; cancel(); return 1, 2, 3, nil },
		memory: func(windows.Handle) (uint64, error) { memory++; return 4, nil },
	}
	r := readNativeUsing(ctx, 42, api)
	if closed != 1 || times != 1 || memory != 0 || r.MemoryErr == nil {
		t.Fatal(r, closed, times, memory)
	}
	api.open = func(uint32, bool, uint32) (windows.Handle, error) { return 0, windows.ERROR_ACCESS_DENIED }
	r = readNativeUsing(context.Background(), 42, api)
	if r.CPUErr != ErrDenied || r.MemoryErr != ErrDenied || closed != 1 {
		t.Fatal(r, closed)
	}
}
