//go:build windows

package windowsstorage

import (
	"context"
	"testing"
	"unsafe"
)

func TestFixedStorageSourceAndAutomationABI(t *testing.T) {
	if storageNamespace != `Root\Microsoft\Windows\Storage` || disksQuery != "SELECT DeviceId, FriendlyName, HealthStatus, OperationalStatus, BusType, MediaType, Size FROM MSFT_PhysicalDisk" {
		t.Fatal("storage source widened")
	}
	if unsafe.Sizeof(variant{}) != 24 {
		t.Fatal("64-bit VARIANT layout")
	}
	if _, _, e := fixedDisks(context.Background(), nil); e != ErrInvalid {
		t.Fatal("nil callback opened provider")
	}
	for _, l := range []byte{0, '@', '[', 255} {
		if _, e := driveRoot(l); e != ErrInvalid {
			t.Fatal("arbitrary path accepted")
		}
	}
	r, e := driveRoot('C')
	if e != nil || r != [4]uint16{'C', ':', '\\', 0} {
		t.Fatal("drive root")
	}
}
func TestStorageProviderNumericTypesPreserveUnknown(t *testing.T) {
	for _, tc := range []struct {
		kind  uint16
		raw   uintptr
		want  uint16
		valid bool
	}{{3, 0, 0, true}, {3, 5, 5, true}, {3, 65535, 65535, true}, {3, 65536, 0, false}, {3, 0xffffffff, 0, false}, {18, 0, 0, true}, {19, 65535, 65535, true}, {19, 65536, 0, false}, {0, 0, 0, false}, {1, 0, 0, false}, {8, 0, 0, false}, {11, 0, 0, false}} {
		n, e := variantUint16(variant{kind: tc.kind, data: [2]uintptr{tc.raw}})
		if (e == nil) != tc.valid || tc.valid && n != tc.want {
			t.Fatal("invented or truncated provider value", tc, n, e)
		}
	}
}
