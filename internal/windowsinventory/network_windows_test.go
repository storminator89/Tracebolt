//go:build windows

package windowsinventory

import (
	"context"
	"encoding/binary"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestNativeNetworkFixtureAndBounds(t *testing.T) {
	storage := make([]uint64, 1024)
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&storage[0])), len(storage)*8)
	adapter := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
	adapter.Length = uint32(unsafe.Sizeof(*adapter))
	adapter.IfIndex = 7
	adapter.OperStatus = windows.IfOperStatusUp
	adapter.IfType = windows.IF_TYPE_ETHERNET_CSMACD
	name := []uint16{'E', 't', 'h', 'e', 'r', 'n', 'e', 't', 0}
	for i, v := range name {
		*(*uint16)(unsafe.Pointer(&buf[1000+i*2])) = v
	}
	adapter.FriendlyName = (*uint16)(unsafe.Pointer(&buf[1000]))
	address := (*windows.IpAdapterUnicastAddress)(unsafe.Pointer(&buf[2000]))
	address.Length = uint32(unsafe.Sizeof(*address))
	adapter.FirstUnicastAddress = address
	address.OnLinkPrefixLength = 24
	raw := (*windows.RawSockaddrInet4)(unsafe.Pointer(&buf[3000]))
	raw.Family = windows.AF_INET
	raw.Addr = [4]byte{192, 0, 2, 7}
	address.Address = windows.SocketAddress{Sockaddr: (*syscall.RawSockaddrAny)(unsafe.Pointer(raw)), SockaddrLength: int32(unsafe.Sizeof(*raw))}
	r := parseNetwork(context.Background(), buf)
	if !r.complete || len(r.rows) != 1 || r.rows[0].Address != "192.0.2.7" || r.rows[0].Index != 7 {
		t.Fatal("valid synthetic native network rejected")
	}
	adapter.Next = adapter
	r = parseNetwork(context.Background(), buf)
	if r.complete || r.err == nil {
		t.Fatal("adapter cycle accepted")
	}
	adapter.Next = nil
	address.Next = address
	r = parseNetwork(context.Background(), buf)
	if r.complete || r.err == nil {
		t.Fatal("address cycle accepted")
	}
	address.Next = nil
	address.Address.SockaddrLength = 9000
	r = parseNetwork(context.Background(), buf)
	if r.complete || len(r.rows) != 0 {
		t.Fatal("out-of-buffer sockaddr accepted")
	}
	if inNativeBuffer(buf, nil, 1, 1) || inNativeBuffer(buf, unsafe.Pointer(&buf[1]), 4, 4) || inNativeBuffer(buf, unsafe.Pointer(&buf[len(buf)-1]), 2, 1) {
		t.Fatal("invalid native pointer accepted")
	}
}
func TestNativeNetworkReadFlags(t *testing.T) {
	if networkFlags&(windows.GAA_FLAG_INCLUDE_GATEWAYS|windows.GAA_FLAG_INCLUDE_WINS_INFO|windows.GAA_FLAG_INCLUDE_ALL_COMPARTMENTS|windows.GAA_FLAG_INCLUDE_ALL_INTERFACES) != 0 || networkFlags&windows.GAA_FLAG_SKIP_DNS_SERVER == 0 {
		t.Fatal("network collection scope expanded")
	}
}

func TestNativeNetworkIPv6AndInvalidPrefix(t *testing.T) {
	storage := make([]uint64, 1024)
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&storage[0])), len(storage)*8)
	adapter := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
	adapter.Length = uint32(unsafe.Sizeof(*adapter))
	adapter.IfIndex = 7
	adapter.Ipv6IfIndex = 9
	adapter.OperStatus = windows.IfOperStatusUp
	*(*uint16)(unsafe.Pointer(&buf[1000])) = 'E'
	adapter.FriendlyName = (*uint16)(unsafe.Pointer(&buf[1000]))
	address := (*windows.IpAdapterUnicastAddress)(unsafe.Pointer(&buf[2000]))
	address.Length = uint32(unsafe.Sizeof(*address))
	adapter.FirstUnicastAddress = address
	address.OnLinkPrefixLength = 64
	raw := (*windows.RawSockaddrInet6)(unsafe.Pointer(&buf[3000]))
	raw.Family = windows.AF_INET6
	raw.Addr = [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	address.Address = windows.SocketAddress{Sockaddr: (*syscall.RawSockaddrAny)(unsafe.Pointer(raw)), SockaddrLength: int32(unsafe.Sizeof(*raw))}
	r := parseNetwork(context.Background(), buf)
	if !r.complete || len(r.rows) != 1 || r.rows[0].Address != "2001:db8::1" || r.rows[0].Index != 9 || r.rows[0].PrefixLength != 64 {
		t.Fatal("native IPv6 fixture invalid")
	}
	address.OnLinkPrefixLength = 129
	s := section("fixed", "fixed", parseNetwork(context.Background(), buf), MaxAddresses, validAddress)
	if s.Complete || len(s.Rows) != 0 {
		t.Fatal("invalid IPv6 prefix accepted")
	}
}
func TestNativeNetworkRejectsMalformedPointersAndLengths(t *testing.T) {
	for _, kind := range []string{"adapter length", "adapter outside", "adapter unaligned", "address length", "address outside", "address unaligned"} {
		t.Run(kind, func(t *testing.T) {
			storage := make([]uint64, 1024)
			buf := unsafe.Slice((*byte)(unsafe.Pointer(&storage[0])), len(storage)*8)
			adapter := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
			adapter.Length = uint32(unsafe.Sizeof(*adapter))
			adapter.IfIndex = 1
			adapter.OperStatus = windows.IfOperStatusUp
			*(*uint16)(unsafe.Pointer(&buf[1000])) = 'E'
			adapter.FriendlyName = (*uint16)(unsafe.Pointer(&buf[1000]))
			address := (*windows.IpAdapterUnicastAddress)(unsafe.Pointer(&buf[2000]))
			address.Length = uint32(unsafe.Sizeof(*address))
			switch kind {
			case "adapter length":
				adapter.Length = 1
			case "adapter outside":
				adapter.Next = new(windows.IpAdapterAddresses)
			case "adapter unaligned":
				fixturePointer(buf, unsafe.Offsetof(adapter.Next), uintptr(unsafe.Pointer(&buf[1])))
			case "address length":
				adapter.FirstUnicastAddress = address
				address.Length = 1
			case "address outside":
				adapter.FirstUnicastAddress = new(windows.IpAdapterUnicastAddress)
			case "address unaligned":
				fixturePointer(buf, unsafe.Offsetof(adapter.FirstUnicastAddress), uintptr(unsafe.Pointer(&buf[2001])))
			}
			r := parseNetwork(context.Background(), buf)
			if r.complete || r.err == nil {
				t.Fatal("malformed native structure accepted")
			}
		})
	}
}
func TestNativeNetworkTraversalCaps(t *testing.T) {
	storage := make([]uint64, maxNetworkBuffer/8)
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&storage[0])), maxNetworkBuffer)
	for i := 0; i <= MaxInterfaces; i++ {
		a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[i*512]))
		a.Length = uint32(unsafe.Sizeof(*a))
		if i < MaxInterfaces {
			a.Next = (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[(i+1)*512]))
		}
	}
	r := parseNetwork(context.Background(), buf)
	if r.complete || !r.truncated || r.err != nil {
		t.Fatal("adapter traversal cap failed")
	}
	clear(buf)
	a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
	a.Length = uint32(unsafe.Sizeof(*a))
	a.IfIndex = 1
	a.OperStatus = windows.IfOperStatusUp
	*(*uint16)(unsafe.Pointer(&buf[1000])) = 'E'
	a.FriendlyName = (*uint16)(unsafe.Pointer(&buf[1000]))
	a.FirstUnicastAddress = (*windows.IpAdapterUnicastAddress)(unsafe.Pointer(&buf[2048]))
	raw := (*windows.RawSockaddrInet4)(unsafe.Pointer(&buf[100000]))
	raw.Family = windows.AF_INET
	raw.Addr = [4]byte{192, 0, 2, 1}
	for i := 0; i <= MaxAddresses; i++ {
		address := (*windows.IpAdapterUnicastAddress)(unsafe.Pointer(&buf[2048+i*64]))
		address.Length = uint32(unsafe.Sizeof(*address))
		address.OnLinkPrefixLength = 24
		address.Address = windows.SocketAddress{Sockaddr: (*syscall.RawSockaddrAny)(unsafe.Pointer(raw)), SockaddrLength: int32(unsafe.Sizeof(*raw))}
		if i < MaxAddresses {
			address.Next = (*windows.IpAdapterUnicastAddress)(unsafe.Pointer(&buf[2048+(i+1)*64]))
		}
	}
	r = parseNetwork(context.Background(), buf)
	if r.complete || !r.truncated || r.err != nil || len(r.rows) != MaxAddresses {
		t.Fatal("address traversal cap failed")
	}
}

// Write malformed native pointer bytes without making a misaligned Go typed
// pointer; future Windows race/checkptr runs must reach the bounds validator.
func fixturePointer(buf []byte, offset, address uintptr) {
	if unsafe.Sizeof(uintptr(0)) == 8 {
		binary.LittleEndian.PutUint64(buf[offset:], uint64(address))
	} else {
		binary.LittleEndian.PutUint32(buf[offset:], uint32(address))
	}
}
