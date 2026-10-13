//go:build windows

package windowsupdateexecutor

import (
	"encoding/binary"
	"golang.org/x/sys/windows"
	"testing"
	"unsafe"
)

func testThreadID() uint64 { return uint64(windows.GetCurrentThreadId()) }

// ABI only: these tests never construct native COM or query a process token.
func TestNativeABI(t *testing.T) {
	var v variant
	var p dispatchParams
	w := unsafe.Sizeof(uintptr(0))
	if unsafe.Offsetof(v.data) != 8 || unsafe.Sizeof(v) != 8+2*w || unsafe.Sizeof(p) != 2*w+8 {
		t.Fatal("ABI mismatch")
	}
	var obj dispatchObject
	*(*unsafe.Pointer)(unsafe.Pointer(&v.data[0])) = unsafe.Pointer(&obj)
	if v.pointer() != unsafe.Pointer(&obj) {
		t.Fatal("pointer union")
	}
	if hrError(0) != nil || hrError(1) != nil || hrError(0x80004005) == nil {
		t.Fatal("HRESULT sign")
	}
	if installer2ID.Data1 != 0x3442d4fe || collectionID.Data1 != 0x13639463 || sessionID.Data1 != 0x4cb43d7f {
		t.Fatal("fixed identifiers")
	}
}

func TestNativeDownloadDecimalOverlayABI(t *testing.T) {
	var v variant
	v.kind = vtDecimal
	b := unsafe.Slice((*byte)(unsafe.Pointer(&v)), 16)
	binary.LittleEndian.PutUint32(b[8:], 0)
	binary.LittleEndian.PutUint32(b[12:], 4)
	if n, err := decodeDownloadDecimal(b); err != nil || n != 16<<30 {
		t.Fatal(n, err)
	}
	// The sign/scale and high coefficient overlay VARIANT's reserved words,
	// not its two-pointer data union. No native API is called by this test.
	v.reserved[0] = 0x8000
	if _, err := decodeDownloadDecimal(b); err == nil {
		t.Fatal("negative decimal accepted")
	}
}
