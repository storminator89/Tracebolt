//go:build windows

package windowsupdates

import (
	"runtime"
	"testing"
	"unsafe"
)

// These tests inspect ABI and HRESULT mapping only. They do not initialize COM,
// load WUA, search the machine or create a local capability grant.
func TestNativeVariantAndDispatchABI(t *testing.T) {
	var v variant
	var p dispatchParams
	width := unsafe.Sizeof(uintptr(0))
	if unsafe.Offsetof(v.data) != 8 || unsafe.Sizeof(v) != 8+2*width || unsafe.Sizeof(p) != 2*width+8 || unsafe.Offsetof(p.count) != 2*width {
		t.Fatalf("invalid ABI for %s: variant=%d data=%d params=%d", runtime.GOARCH, unsafe.Sizeof(v), unsafe.Offsetof(v.data), unsafe.Sizeof(p))
	}
	var obj dispatchObject
	*(*unsafe.Pointer)(unsafe.Pointer(&v.data[0])) = unsafe.Pointer(&obj)
	if v.pointer() != unsafe.Pointer(&obj) {
		t.Fatal("pointer union lost native address")
	}
	runtime.KeepAlive(&obj)
	v = intArgument(-7)
	if v.kind != vtI4 || int32(uint32(v.data[0])) != -7 {
		t.Fatal("signed LONG lost")
	}
}
func TestNativeHRESULTUsesSignedLowWord(t *testing.T) {
	for _, hr := range []uintptr{0, 1, 0x7fffffff} {
		if hrError(hr) != nil {
			t.Fatal(hr)
		}
	}
	if hrError(0x80070005) != ErrDenied || hrError(0x80004005) != ErrUnavailable {
		t.Fatal("HRESULT mapped incorrectly")
	}
}
