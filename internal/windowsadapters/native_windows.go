//go:build windows && (amd64 || arm64)

package windowsadapters

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"runtime"
	"unsafe"
)

// Fail compilation rather than decode a changed native ABI with stale offsets.
var _ [unsafe.Offsetof(windows.IpAdapterAddresses{}.Ipv6IfIndex) - 108]byte
var _ [108 - unsafe.Offsetof(windows.IpAdapterAddresses{}.Ipv6IfIndex)]byte
var _ [unsafe.Offsetof(windows.IpAdapterAddresses{}.FirstDnsServerAddress) - 48]byte
var _ [48 - unsafe.Offsetof(windows.IpAdapterAddresses{}.FirstDnsServerAddress)]byte
var _ [unsafe.Offsetof(windows.IpAdapterAddresses{}.FriendlyName) - 72]byte
var _ [72 - unsafe.Offsetof(windows.IpAdapterAddresses{}.FriendlyName)]byte
var _ [unsafe.Offsetof(windows.IpAdapterAddresses{}.TransmitLinkSpeed) - 184]byte
var _ [184 - unsafe.Offsetof(windows.IpAdapterAddresses{}.TransmitLinkSpeed)]byte
var _ [unsafe.Offsetof(windows.IpAdapterAddresses{}.FirstGatewayAddress) - 208]byte
var _ [208 - unsafe.Offsetof(windows.IpAdapterAddresses{}.FirstGatewayAddress)]byte
var _ [unsafe.Sizeof(windows.IpAdapterDnsServerAdapter{}) - addressNodeSize]byte
var _ [addressNodeSize - unsafe.Sizeof(windows.IpAdapterDnsServerAdapter{})]byte
var _ [unsafe.Sizeof(windows.IpAdapterGatewayAddress{}) - addressNodeSize]byte
var _ [addressNodeSize - unsafe.Sizeof(windows.IpAdapterGatewayAddress{})]byte

var _ [unsafe.Offsetof(windows.IpAdapterAddresses{}.IfIndex) - 4]byte
var _ [4 - unsafe.Offsetof(windows.IpAdapterAddresses{}.IfIndex)]byte
var _ [unsafe.Offsetof(windows.IpAdapterAddresses{}.Next) - 8]byte
var _ [8 - unsafe.Offsetof(windows.IpAdapterAddresses{}.Next)]byte
var _ [unsafe.Offsetof(windows.IpAdapterAddresses{}.IfType) - 100]byte
var _ [100 - unsafe.Offsetof(windows.IpAdapterAddresses{}.IfType)]byte
var _ [unsafe.Offsetof(windows.IpAdapterAddresses{}.OperStatus) - 104]byte
var _ [104 - unsafe.Offsetof(windows.IpAdapterAddresses{}.OperStatus)]byte
var _ [unsafe.Offsetof(windows.IpAdapterAddresses{}.ReceiveLinkSpeed) - 192]byte
var _ [192 - unsafe.Offsetof(windows.IpAdapterAddresses{}.ReceiveLinkSpeed)]byte
var _ [unsafe.Offsetof(windows.IpAdapterDnsServerAdapter{}.Next) - 8]byte
var _ [8 - unsafe.Offsetof(windows.IpAdapterDnsServerAdapter{}.Next)]byte
var _ [unsafe.Offsetof(windows.IpAdapterDnsServerAdapter{}.Address) - 16]byte
var _ [16 - unsafe.Offsetof(windows.IpAdapterDnsServerAdapter{}.Address)]byte
var _ [unsafe.Offsetof(windows.IpAdapterGatewayAddress{}.Next) - 8]byte
var _ [8 - unsafe.Offsetof(windows.IpAdapterGatewayAddress{}.Next)]byte
var _ [unsafe.Offsetof(windows.IpAdapterGatewayAddress{}.Address) - 16]byte
var _ [16 - unsafe.Offsetof(windows.IpAdapterGatewayAddress{}.Address)]byte
var _ [unsafe.Offsetof(windows.SocketAddress{}.SockaddrLength) - 8]byte
var _ [8 - unsafe.Offsetof(windows.SocketAddress{}.SockaddrLength)]byte
var _ [unsafe.Offsetof(windows.RawSockaddrInet4{}.Addr) - 4]byte
var _ [4 - unsafe.Offsetof(windows.RawSockaddrInet4{}.Addr)]byte
var _ [unsafe.Offsetof(windows.RawSockaddrInet6{}.Addr) - 8]byte
var _ [8 - unsafe.Offsetof(windows.RawSockaddrInet6{}.Addr)]byte
var _ [unsafe.Offsetof(windows.RawSockaddrInet6{}.Scope_id) - 24]byte
var _ [24 - unsafe.Offsetof(windows.RawSockaddrInet6{}.Scope_id)]byte

const adapterFlags = windows.GAA_FLAG_SKIP_UNICAST | windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_INCLUDE_GATEWAYS | windows.GAA_FLAG_INCLUDE_ALL_INTERFACES

type nativeQuery func(uint32, uint32, uintptr, *windows.IpAdapterAddresses, *uint32) error

func readNative(ctx context.Context) Result {
	return readNativeUsing(ctx, windows.GetAdaptersAddresses)
}
func readNativeUsing(ctx context.Context, q nativeQuery) Result {
	if ctx == nil || q == nil {
		return Result{Err: ErrInvalid}
	}
	if e := ctx.Err(); e != nil {
		return Result{Err: e}
	}
	// One aligned fixed-size call, no source-controlled allocation or retry. The
	// aggregate necessarily contains excluded fields; none is decoded or retained.
	storage := make([]uint64, MaxNativeBytes/8)
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&storage[0])), MaxNativeBytes)
	defer clear(storage)
	size := uint32(len(buf))
	e := q(windows.AF_UNSPEC, adapterFlags, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&storage[0])), &size)
	if ctx.Err() != nil {
		return Result{Err: ctx.Err()}
	}
	if errors.Is(e, windows.ERROR_NO_DATA) {
		return Result{Complete: true}
	}
	if errors.Is(e, windows.ERROR_ACCESS_DENIED) {
		return Result{Err: ErrDenied}
	}
	if errors.Is(e, windows.ERROR_NOT_SUPPORTED) {
		return Result{Err: ErrUnsupported}
	}
	if errors.Is(e, windows.ERROR_BUFFER_OVERFLOW) {
		return Result{Err: ErrBounds}
	}
	if e != nil || size == 0 || size > uint32(len(buf)) {
		return Result{Err: ErrUnavailable}
	}
	r := decodeNative(ctx, buf[:size], uint64(uintptr(unsafe.Pointer(&storage[0]))))
	runtime.KeepAlive(storage)
	return r
}
