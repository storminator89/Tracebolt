//go:build windows

package windowsservice

import (
	"golang.org/x/sys/windows"
	"testing"
	"unsafe"
)

// Memory-only security descriptor fixtures; no host security setting is read or changed.
func TestObservationDescriptorMemoryFixtures(t *testing.T) {
	for _, tc := range []struct {
		sddl string
		ok   bool
	}{{`O:SYG:SYD:(A;;GA;;;BA)(A;;0x2018d;;;AU)`, true}, {`O:LSG:SYD:(A;;GA;;;BA)`, false}, {`O:SYG:SYD:(A;;GA;;;BA)(A;;DC;;;AU)`, false}, {`O:SYG:SYD:(A;;GA;;;BA)(A;;WD;;;AU)`, false}} {
		sd, e := windows.SecurityDescriptorFromString(tc.sddl)
		if e != nil {
			t.Fatal(e)
		}
		raw := unsafe.Slice((*byte)(unsafe.Pointer(sd)), int(sd.Length()))
		buffer := make([]byte, 8192)
		copy(buffer, raw)
		extent, err := observationDescriptorExtent(buffer)
		if err != nil || extent != len(raw) {
			t.Fatalf("extent=%d want=%d err=%v", extent, len(raw), err)
		}
		e = observationDescriptorBytes(buffer[:extent])
		if (e == nil) != tc.ok {
			t.Fatalf("%s: %v", tc.sddl, e)
		}
	}
}
