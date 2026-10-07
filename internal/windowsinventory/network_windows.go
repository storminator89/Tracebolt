//go:build windows

package windowsinventory

import (
	"context"
	"errors"
	"net/netip"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const maxNetworkBuffer = 1 << 20
const networkFlags = windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER

func (nativeProvider) network(ctx context.Context) result[InterfaceAddress] {
	if ctx.Err() != nil {
		return result[InterfaceAddress]{err: ctx.Err()}
	}
	// A single fixed allocation/call: no OS-controlled unbounded resize loop.
	// Do not request gateway/WINS/prefix lists, all compartments or all interfaces.
	storage := make([]uint64, maxNetworkBuffer/8)
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&storage[0])), maxNetworkBuffer)
	size := uint32(len(buf))
	err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, networkFlags, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&storage[0])), &size)
	if errors.Is(err, windows.ERROR_NO_DATA) {
		return result[InterfaceAddress]{complete: true}
	}
	if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
		return result[InterfaceAddress]{truncated: true, err: errInvalid}
	}
	if err != nil {
		return result[InterfaceAddress]{err: err}
	}
	if size == 0 {
		return result[InterfaceAddress]{complete: true}
	}
	if size > uint32(len(buf)) {
		return result[InterfaceAddress]{err: errInvalid}
	}
	r := parseNetwork(ctx, buf[:size])
	runtime.KeepAlive(storage)
	return r
}

func inNativeBuffer(buf []byte, p unsafe.Pointer, size, alignment uintptr) bool {
	if len(buf) == 0 || p == nil || alignment == 0 {
		return false
	}
	base, addr := uintptr(unsafe.Pointer(&buf[0])), uintptr(p)
	if addr < base || addr%alignment != 0 {
		return false
	}
	offset := addr - base
	return offset < uintptr(len(buf)) && size <= uintptr(len(buf))-offset
}

func parseNetwork(ctx context.Context, buf []byte) result[InterfaceAddress] {
	r := result[InterfaceAddress]{complete: true}
	if len(buf) == 0 {
		return r
	}
	adapter := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
	const adapterMin = unsafe.Offsetof(windows.IpAdapterAddresses{}.Ipv6IfIndex) + 4
	const addressMin = unsafe.Offsetof(windows.IpAdapterUnicastAddress{}.OnLinkPrefixLength) + 1
	seenAdapters := map[*windows.IpAdapterAddresses]bool{}
	seenAddresses := map[*windows.IpAdapterUnicastAddress]bool{}
	for adapter != nil {
		if ctx.Err() != nil {
			r.complete = false
			r.err = ctx.Err()
			return r
		}
		if len(seenAdapters) >= MaxInterfaces {
			r.complete = false
			r.truncated = true
			return r
		}
		if !inNativeBuffer(buf, unsafe.Pointer(adapter), adapterMin, unsafe.Alignof(windows.IpAdapterAddresses{})) || seenAdapters[adapter] {
			r.complete = false
			r.err = errInvalid
			return r
		}
		seenAdapters[adapter] = true
		if uintptr(adapter.Length) < adapterMin {
			r.complete = false
			r.err = errInvalid
			return r
		}
		if adapter.OperStatus == windows.IfOperStatusUp && adapter.IfType != windows.IF_TYPE_SOFTWARE_LOOPBACK {
			name, ok := bufferString(buf, adapter.FriendlyName)
			if !ok {
				r.complete = false
				adapter = adapter.Next
				continue
			}
			for address := adapter.FirstUnicastAddress; address != nil; address = address.Next {
				if ctx.Err() != nil {
					r.complete = false
					r.err = ctx.Err()
					return r
				}
				if len(seenAddresses) >= MaxAddresses {
					r.complete = false
					r.truncated = true
					return r
				}
				if !inNativeBuffer(buf, unsafe.Pointer(address), addressMin, unsafe.Alignof(windows.IpAdapterUnicastAddress{})) || seenAddresses[address] {
					r.complete = false
					r.err = errInvalid
					return r
				}
				seenAddresses[address] = true
				if uintptr(address.Length) < addressMin {
					r.complete = false
					r.err = errInvalid
					return r
				}
				ip, ok := networkAddress(buf, address.Address)
				if !ok {
					r.complete = false
					continue
				}
				if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
					continue
				}
				index := adapter.IfIndex
				if ip.Is6() && adapter.Ipv6IfIndex != 0 {
					index = adapter.Ipv6IfIndex
				}
				if index == 0 {
					index = adapter.Ipv6IfIndex
				}
				r.rows = append(r.rows, InterfaceAddress{Index: int(index), Name: name, Address: ip.String(), PrefixLength: int(address.OnLinkPrefixLength)})
			}
		}
		adapter = adapter.Next
	}
	return r
}
func networkAddress(buf []byte, address windows.SocketAddress) (netip.Addr, bool) {
	p := unsafe.Pointer(address.Sockaddr)
	if address.SockaddrLength < 2 || !inNativeBuffer(buf, p, uintptr(address.SockaddrLength), 2) {
		return netip.Addr{}, false
	}
	family := *(*uint16)(p)
	switch family {
	case windows.AF_INET:
		if uintptr(address.SockaddrLength) < unsafe.Sizeof(windows.RawSockaddrInet4{}) {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4((*windows.RawSockaddrInet4)(p).Addr), true
	case windows.AF_INET6:
		if uintptr(address.SockaddrLength) < unsafe.Sizeof(windows.RawSockaddrInet6{}) || !inNativeBuffer(buf, p, unsafe.Sizeof(windows.RawSockaddrInet6{}), unsafe.Alignof(windows.RawSockaddrInet6{})) {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16((*windows.RawSockaddrInet6)(p).Addr), true
	}
	return netip.Addr{}, false
}
