//go:build windows && (amd64 || arm64)

package windowsadapters

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"testing"
	"unsafe"
)

// Every call below is injected; these tests never inspect host adapters.
func TestAdapterContextNativeCallFlagsBoundsAndClear(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		size     uint32
		complete bool
		want     error
	}{
		{"no-data", windows.ERROR_NO_DATA, 0, true, nil},
		{"denied", windows.ERROR_ACCESS_DENIED, 0, false, ErrDenied},
		{"unsupported", windows.ERROR_NOT_SUPPORTED, 0, false, ErrUnsupported},
		{"overflow", windows.ERROR_BUFFER_OVERFLOW, MaxNativeBytes + 8, false, ErrBounds},
		{"invalid-success", nil, MaxNativeBytes + 8, false, ErrUnavailable},
		{"zero-success", nil, 0, false, ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			var held []byte
			r := readNativeUsing(context.Background(), func(family, flags uint32, reserved uintptr, adapters *windows.IpAdapterAddresses, size *uint32) error {
				calls++
				if family != windows.AF_UNSPEC || flags != adapterFlags || reserved != 0 || *size != MaxNativeBytes {
					t.Fatal("unbounded/widened native query")
				}
				held = unsafe.Slice((*byte)(unsafe.Pointer(adapters)), MaxNativeBytes)
				held[32] = 99
				*size = tc.size
				return tc.err
			})
			if calls != 1 || r.Complete != tc.complete || !errors.Is(r.Err, tc.want) {
				t.Fatal(r)
			}
			for _, b := range held {
				if b != 0 {
					t.Fatal("aggregate bytes not cleared")
				}
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := readNativeUsing(ctx, func(uint32, uint32, uintptr, *windows.IpAdapterAddresses, *uint32) error {
		t.Fatal("cancelled collection reached API")
		return nil
	})
	if !errors.Is(r.Err, context.Canceled) {
		t.Fatal(r)
	}
}
