//go:build windows

package windowsnetwork

import (
	"context"
	"encoding/binary"
	"errors"
	"golang.org/x/sys/windows"
	"testing"
	"unsafe"
)

func TestNativeNetworkInjectedFourTables(t *testing.T) {
	calls, ready := 0, 0
	api := nativeAPI{
		ready: func(protocol string) error {
			if protocol != "tcp" && protocol != "udp" {
				t.Fatal(protocol)
			}
			ready++
			return nil
		},
		table: func(protocol string, b []byte, size *uint32, order bool, af, class, reserved uint32) uint32 {
			calls++
			if !order || reserved != 0 || *size != uint32(len(b)) {
				t.Fatal("bad native arguments")
			}
			index := -1
			for i, s := range tables {
				if s.protocol == protocol && s.af == af {
					index = i
					if s.class != class {
						t.Fatal("wrong class")
					}
				}
			}
			if index < 0 {
				t.Fatal("wrong family")
			}
			s := tables[index]
			fixture := rawTable(s, []Endpoint{endpoint(s.protocol, s.family, uint32(index+1))})
			*size = uint32(len(fixture))
			if len(b) < len(fixture) {
				return uint32(windows.ERROR_INSUFFICIENT_BUFFER)
			}
			copy(b, fixture)
			return 0
		},
	}
	v, e := collectUsing(context.Background(), generation, grant, epoch, func(s tableSpec, b []byte) (uint32, error) { return queryNativeUsing(s, b, api) })
	if e != nil || !v.CountExact || v.ObservedCount != 4 || calls != 8 || ready != 8 {
		t.Fatal(v, e, calls, ready)
	}
}
func TestNativeNetworkReturnCodesAndBounds(t *testing.T) {
	for code, want := range map[uint32]error{uint32(windows.ERROR_ACCESS_DENIED): ErrDenied, uint32(windows.ERROR_NOT_SUPPORTED): ErrUnsupported, uint32(windows.ERROR_INVALID_PARAMETER): ErrUnavailable, uint32(windows.ERROR_INSUFFICIENT_BUFFER): ErrInsufficientBuffer} {
		api := nativeAPI{ready: func(string) error { return nil }, table: func(_ string, _ []byte, size *uint32, _ bool, _, _, _ uint32) uint32 { *size = 64; return code }}
		_, e := queryNativeUsing(tables[0], nil, api)
		if !errors.Is(e, want) {
			t.Fatal(code, e)
		}
	}
	called := false
	api := nativeAPI{ready: func(string) error { called = true; return ErrUnavailable }, table: func(string, []byte, *uint32, bool, uint32, uint32, uint32) uint32 {
		t.Fatal("called after readiness failure")
		return 0
	}}
	if _, e := queryNativeUsing(tables[0], nil, api); !errors.Is(e, ErrUnavailable) || !called {
		t.Fatal(e)
	}
	called = false
	if _, e := queryNativeUsing(tableSpec{}, nil, api); !errors.Is(e, ErrInvalid) || called {
		t.Fatal("invalid spec reached native")
	}
	if _, e := queryNativeUsing(tables[0], make([]byte, MaxTableBytes+1), api); !errors.Is(e, ErrInvalid) || called {
		t.Fatal("oversized allocation reached native")
	}
}
func TestNativeNetworkDWORDLayouts(t *testing.T) {
	type tcp4 struct{ State, LocalAddress, LocalPort, RemoteAddress, RemotePort, PID uint32 }
	type tcp6 struct {
		LocalAddress                        [16]byte
		LocalScope, LocalPort               uint32
		RemoteAddress                       [16]byte
		RemoteScope, RemotePort, State, PID uint32
	}
	type udp4 struct{ LocalAddress, LocalPort, PID uint32 }
	type udp6 struct {
		LocalAddress               [16]byte
		LocalScope, LocalPort, PID uint32
	}
	type table6 struct {
		Count uint32
		Row   tcp6
	}
	var a tcp4
	var b tcp6
	var c udp4
	var d udp6
	var e table6
	if unsafe.Sizeof(a) != 24 || unsafe.Sizeof(b) != 56 || unsafe.Sizeof(c) != 12 || unsafe.Sizeof(d) != 28 || unsafe.Offsetof(e.Row) != 4 || unsafe.Offsetof(b.LocalScope) != 16 || unsafe.Offsetof(b.RemoteAddress) != 24 || unsafe.Offsetof(b.RemoteScope) != 40 || unsafe.Offsetof(b.State) != 48 || unsafe.Offsetof(b.PID) != 52 || unsafe.Offsetof(d.PID) != 24 {
		t.Fatal("unexpected OWNER_PID ABI")
	}
	// All supported Go Windows architectures are little endian; wire scopes and
	// ports still use network byte order, independent of these native DWORDs.
	n := uint32(0x01020304)
	bytes := *(*[4]byte)(unsafe.Pointer(&n))
	if binary.LittleEndian.Uint32(bytes[:]) != n {
		t.Fatal("unsupported native endian")
	}
}
