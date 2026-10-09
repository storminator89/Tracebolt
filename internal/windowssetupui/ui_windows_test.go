//go:build windows

package windowssetupui

import (
	"runtime"
	"testing"
	"unsafe"
)

// These are inert ABI layout assertions, not Win32 window/native acceptance.
func TestWin32Supported64BitLayouts(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("installer supports amd64 and arm64 only")
	}
	if unsafe.Sizeof(winClass{}) != 80 {
		t.Fatal("WNDCLASSEXW layout")
	}
	if unsafe.Sizeof(winMessage{}) != 48 {
		t.Fatal("MSG layout")
	}
	if unsafe.Sizeof(openFileName{}) != 152 {
		t.Fatal("OPENFILENAMEW layout")
	}
	if unsafe.Offsetof(openFileName{}.File) != 48 || unsafe.Offsetof(openFileName{}.Flags) != 96 || unsafe.Offsetof(openFileName{}.Reserved) != 136 {
		t.Fatal("OPENFILENAMEW offsets")
	}
	if unsafe.Sizeof(rect{}) != 16 || unsafe.Sizeof(monitorInfo{}) != 40 || unsafe.Offsetof(monitorInfo{}.Work) != 20 {
		t.Fatal("RECT/MONITORINFO layout")
	}
	if unsafe.Sizeof(minMaxInfo{}) != 40 || unsafe.Offsetof(minMaxInfo{}.MinTrackSize) != 24 {
		t.Fatal("MINMAXINFO layout")
	}
}

func TestNativeLayoutMessagePointerDecoding(t *testing.T) {
	// Inert local structures only; no Windows API or HWND is touched.
	// Pin the Go fixtures while modeling native-owned, nonmoving memory.
	var pinned runtime.Pinner
	defer pinned.Unpin()
	r := &rect{-1920, -40, 0, 1040}
	pinned.Pin(r)
	parameter := uintptr(unsafe.Pointer(r))
	if got := *nativeMessagePointer[rect](&parameter); got != *r {
		t.Fatalf("WM_DPICHANGED rectangle changed: %+v", got)
	}
	m := &minMaxInfo{}
	pinned.Pin(m)
	parameter = uintptr(unsafe.Pointer(m))
	nativeMessagePointer[minMaxInfo](&parameter).MinTrackSize = point{770, 599}
	if m.MinTrackSize != (point{770, 599}) {
		t.Fatal("WM_GETMINMAXINFO output pointer lost")
	}
	parameter = 0
	if nativeMessagePointer[rect](&parameter) != nil {
		t.Fatal("null LPARAM became non-null")
	}
}
