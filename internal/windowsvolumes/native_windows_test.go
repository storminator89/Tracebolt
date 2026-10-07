//go:build windows

package windowsvolumes

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"io"
	"strings"
	"testing"
)

// All API functions are injected; these tests perform no native reads even
// when run on Windows. Cross-compilation is not execution evidence.
func TestNativeInjectedEnumeration(t *testing.T) {
	calls, closed := 0, 0
	api := nativeAPI{
		ready: func() error { return nil },
		first: func(buf []uint16) (uintptr, error) {
			calls++
			if len(buf) != 64 {
				t.Fatal(len(buf))
			}
			u, _ := windows.UTF16FromString(strings.Replace(guid(10), "00000000000a", "00000000000A", 1))
			copy(buf, u)
			return 99, nil
		},
		next: func(h uintptr, buf []uint16) error {
			calls++
			if h != 99 {
				t.Fatal(h)
			}
			return windows.ERROR_NO_MORE_FILES
		},
		close:    func(uintptr) error { closed++; return nil },
		drive:    func(*uint16) uint32 { return 3 },
		capacity: func(*uint16) (uint64, uint64, uint64, error) { return 100, 200, 50, nil },
	}
	r, e := openNativeUsing(context.Background(), api)
	if e != nil {
		t.Fatal(e)
	}
	id, e := r.Next(context.Background())
	if e != nil || id != guid(10) {
		t.Fatal(id, e)
	}
	if d, e := r.DriveType(context.Background(), id); e != nil || d != "fixed" {
		t.Fatal(d, e)
	}
	total, free, available, e := r.Capacity(context.Background(), id)
	if e != nil || total != 100 || free != 200 || available != 50 {
		t.Fatal(total, free, available, e)
	}
	if _, e = r.Next(context.Background()); !errors.Is(e, io.EOF) {
		t.Fatal(e)
	}
	r.Close()
	r.Close()
	if closed != 1 || calls != 2 {
		t.Fatal(closed, calls)
	}
	api.drive = func(*uint16) uint32 { return 4 }
	r, e = openNativeUsing(context.Background(), api)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if d, e := r.DriveType(context.Background(), guid(1)); d != "unknown" || e != ErrDriveType {
		t.Fatal("remote drive admitted")
	}
}
func TestNativeRejectMalformedRoots(t *testing.T) {
	for _, s := range []string{`C:\`, `\\server\share\`, guid(1) + "suffix", strings.Replace(guid(1), "Volume", "volume", 1)} {
		u, _ := windows.UTF16FromString(s)
		if _, e := volumeName(u); e == nil {
			t.Fatal(s)
		}
	}
	if _, e := volumeName(make([]uint16, 0)); e == nil {
		t.Fatal("unterminated")
	}
}
