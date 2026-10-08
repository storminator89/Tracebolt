//go:build windows

package windowsnetwork

import (
	"golang.org/x/sys/windows"
	"runtime"
	"unsafe"
)

var ipHelper = windows.NewLazySystemDLL("iphlpapi.dll")
var extendedTCP = ipHelper.NewProc("GetExtendedTcpTable")
var extendedUDP = ipHelper.NewProc("GetExtendedUdpTable")

// Typed injected wrappers never load/call DLLs in tests. All OWNER_PID layouts
// are DWORD-aligned with no pointers or 64-bit members: header 4, row 24/56/12/28.
type nativeAPI struct {
	ready func(string) error
	table func(string, []byte, *uint32, bool, uint32, uint32, uint32) uint32
}

var systemAPI = nativeAPI{
	ready: func(protocol string) error {
		p := extendedTCP
		if protocol == "udp" {
			p = extendedUDP
		}
		if p.Find() != nil {
			return ErrUnavailable
		}
		return nil
	},
	table: func(protocol string, buf []byte, size *uint32, ordered bool, af, class, reserved uint32) uint32 {
		p := extendedTCP
		if protocol == "udp" {
			p = extendedUDP
		}
		var ptr *byte
		if len(buf) > 0 {
			ptr = &buf[0]
		}
		var order uintptr
		if ordered {
			order = 1
		}
		n, _, _ := p.Call(uintptr(unsafe.Pointer(ptr)), uintptr(unsafe.Pointer(size)), order, uintptr(af), uintptr(class), uintptr(reserved))
		runtime.KeepAlive(buf)
		runtime.KeepAlive(size)
		// DWORD return is authoritative; GetLastError is not this API's result.
		return uint32(n)
	},
}

func queryNative(spec tableSpec, buf []byte) (uint32, error) {
	return queryNativeUsing(spec, buf, systemAPI)
}
func queryNativeUsing(spec tableSpec, buf []byte, api nativeAPI) (uint32, error) {
	if len(buf) > MaxTableBytes || api.ready == nil || api.table == nil {
		return 0, ErrInvalid
	}
	valid := false
	for _, t := range tables {
		if spec == t {
			valid = true
			break
		}
	}
	if !valid {
		return 0, ErrInvalid
	}
	if e := api.ready(spec.protocol); e != nil {
		return 0, e
	}
	size := uint32(len(buf))
	// Ask Windows for address/scope/port order; portable sorting also adds state
	// and PID tie breakers. No DNS, sockets, process opens or privilege requests.
	code := api.table(spec.protocol, buf, &size, true, spec.af, spec.class, 0)
	switch code {
	case 0:
		return size, nil
	case uint32(windows.ERROR_INSUFFICIENT_BUFFER):
		return size, errBuffer
	case uint32(windows.ERROR_ACCESS_DENIED):
		return 0, ErrDenied
	case uint32(windows.ERROR_NOT_SUPPORTED):
		return 0, ErrUnsupported
	default:
		return 0, ErrUnavailable
	}
}
