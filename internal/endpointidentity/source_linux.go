//go:build linux

package endpointidentity

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Reviewed source constructor: it performs no reads itself. Collect validates
// explicit current local consent before construction; callers own protected
// file and activation checks. Tests inject linuxOperations;
// they never construct or invoke linuxOS.
func newLinuxProvider() Provider { return &linuxProvider{ops: &linuxOS{fd: -1}} }

type linuxOperations interface {
	Hostname(context.Context) (string, error)
	InterfaceNames(context.Context) ([]string, error)
	Interface(context.Context, string) (SourceInterface, error)
	IPv4(context.Context) ([]namedAddress, error)
	IPv6(context.Context) ([]indexedAddress, error)
	Close() error
}
type namedAddress struct {
	Name string
	Addr netip.Addr
}
type indexedAddress struct {
	Index uint32
	Name  string
	Addr  netip.Addr
}
type familyObservation struct {
	loaded bool
	rows   map[uint32][]SourceAddress
	err    error
}
type linuxProvider struct {
	ops        linuxOperations
	interfaces map[uint32]SourceInterface
	ipv4, ipv6 familyObservation
}

func (p *linuxProvider) Hostname(ctx context.Context) (string, error) { return p.ops.Hostname(ctx) }
func (p *linuxProvider) Interfaces(ctx context.Context) ([]SourceInterface, error) {
	names, e := p.ops.InterfaceNames(ctx)
	if e != nil {
		return nil, e
	}
	if len(names) > MaxInterfaces {
		return nil, ErrItemLimit
	}
	out := make([]SourceInterface, 0, len(names))
	p.interfaces = map[uint32]SourceInterface{}
	seen := map[string]bool{}
	for _, name := range names {
		if !safeInterfaceName(name) || seen[name] {
			return nil, ErrInvalidSource
		}
		seen[name] = true
		row, e := p.ops.Interface(ctx, name)
		if e != nil {
			return nil, e
		}
		if row.Name != name || row.Index == 0 || row.Index > 1<<31-1 {
			return nil, ErrInvalidSource
		}
		if _, ok := p.interfaces[row.Index]; ok {
			return nil, ErrInvalidSource
		}
		p.interfaces[row.Index] = row
		out = append(out, row)
	}
	return out, nil
}
func (p *linuxProvider) Addresses(ctx context.Context, index uint32, family string) ([]SourceAddress, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if p.interfaces == nil {
		return nil, ErrInvalidSource
	}
	expected, ok := p.interfaces[index]
	if !ok {
		return nil, ErrInvalidSource
	}
	var section *familyObservation
	switch family {
	case "ipv4":
		section = &p.ipv4
	case "ipv6":
		section = &p.ipv6
	default:
		return nil, ErrInvalidInput
	}
	if !section.loaded {
		section.loaded = true
		if family == "ipv4" {
			section.rows, section.err = p.loadIPv4(ctx)
		} else {
			section.rows, section.err = p.loadIPv6(ctx)
		}
	}
	if section.err != nil {
		return nil, section.err
	}
	// An observed rename/index/flag change is explicit, never silent reassignment
	// of addresses to a new interface. Sequential reads cannot prove atomicity.
	current, e := p.ops.Interface(ctx, expected.Name)
	if e != nil {
		return nil, e
	}
	if current != expected {
		return nil, ErrInvalidSource
	}
	return append([]SourceAddress{}, section.rows[index]...), nil
}
func (p *linuxProvider) loadIPv4(ctx context.Context) (map[uint32][]SourceAddress, error) {
	rows, e := p.ops.IPv4(ctx)
	if e != nil {
		return nil, e
	}
	if len(rows) > MaxAddresses {
		return nil, ErrItemLimit
	}
	out := map[uint32][]SourceAddress{}
	for _, row := range rows {
		if !safeAlias(row.Name) || !row.Addr.Is4() {
			return nil, ErrInvalidSource
		}
		// Resolve the kernel-reported address label through the read-only index
		// ioctl. Alias text never becomes a path or an invented interface identity.
		found, e := p.ops.Interface(ctx, row.Name)
		if e != nil {
			return nil, e
		}
		expected, ok := p.interfaces[found.Index]
		base, _, _ := strings.Cut(row.Name, ":")
		if !ok || expected.Name != base || found.Index != expected.Index || found.Up != expected.Up || found.Loopback != expected.Loopback {
			return nil, ErrInvalidSource
		}
		out[found.Index] = append(out[found.Index], SourceAddress{row.Addr})
	}
	return out, nil
}
func (p *linuxProvider) loadIPv6(ctx context.Context) (map[uint32][]SourceAddress, error) {
	rows, e := p.ops.IPv6(ctx)
	if e != nil {
		return nil, e
	}
	if len(rows) > MaxAddresses {
		return nil, ErrItemLimit
	}
	out := map[uint32][]SourceAddress{}
	for _, row := range rows {
		expected, ok := p.interfaces[row.Index]
		if !ok || row.Name != expected.Name || !row.Addr.Is6() || row.Addr.Zone() != "" {
			return nil, ErrInvalidSource
		}
		out[row.Index] = append(out[row.Index], SourceAddress{row.Addr})
	}
	return out, nil
}
func (p *linuxProvider) Close() error { return p.ops.Close() }
func safeAlias(s string) bool {
	if len(s) > MaxInterfaceNameBytes {
		return false
	}
	base, suffix, alias := strings.Cut(s, ":")
	return safeInterfaceName(base) && (!alias || safeInterfaceName(suffix))
}

const maxRawBytes = 64 << 10
const maxLineBytes = 4096
const procDirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
const procReadFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK

type linuxOS struct {
	proc, net *os.File
	fd        int
}

func (o *linuxOS) Hostname(ctx context.Context) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if os.Geteuid() == 0 {
		return "", ErrPermissionDenied
	}
	var u unix.Utsname
	if e := unix.Uname(&u); e != nil {
		return "", osSourceError(e)
	}
	b := u.Nodename[:]
	n := bytes.IndexByte(b, 0)
	if n <= 0 || n >= len(b) {
		return "", ErrInvalidSource
	}
	return string(b[:n]), nil
}
func (o *linuxOS) InterfaceNames(ctx context.Context) ([]string, error) {
	raw, e := o.readProc(ctx, "dev")
	if e != nil {
		return nil, e
	}
	return parseInterfaceNames(raw)
}
func (o *linuxOS) Interface(ctx context.Context, name string) (SourceInterface, error) {
	if ctx.Err() != nil {
		return SourceInterface{}, ctx.Err()
	}
	if !safeAlias(name) {
		return SourceInterface{}, ErrInvalidSource
	}
	if e := o.control(); e != nil {
		return SourceInterface{}, e
	}
	return readInterfaceWith(name, func(request uint, req *unix.Ifreq) error { return unix.IoctlIfreq(o.fd, request, req) })
}
func readInterfaceWith(name string, invoke func(uint, *unix.Ifreq) error) (SourceInterface, error) {
	if !safeAlias(name) || invoke == nil {
		return SourceInterface{}, ErrInvalidSource
	}
	req, e := unix.NewIfreq(name)
	if e != nil {
		return SourceInterface{}, ErrInvalidSource
	}
	if e = invoke(unix.SIOCGIFINDEX, req); e != nil {
		return SourceInterface{}, osSourceError(e)
	}
	index := req.Uint32()
	req, e = unix.NewIfreq(name)
	if e != nil {
		return SourceInterface{}, ErrInvalidSource
	}
	if e = invoke(unix.SIOCGIFFLAGS, req); e != nil {
		return SourceInterface{}, osSourceError(e)
	}
	flags := req.Uint16()
	return SourceInterface{index, name, flags&unix.IFF_UP != 0, flags&unix.IFF_LOOPBACK != 0}, nil
}

func (o *linuxOS) control() error {
	if o.fd >= 0 {
		return nil
	}
	if os.Geteuid() == 0 {
		return ErrPermissionDenied
	}
	fd, e := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		return osSourceError(e)
	}
	o.fd = fd
	return nil
}
func (o *linuxOS) IPv4(ctx context.Context) ([]namedAddress, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if e := o.control(); e != nil {
		return nil, e
	}
	size := int(unsafe.Sizeof(unix.Ifreq{}))
	// One fixed, prebounded extra record makes truncation fail closed. Never ask
	// the kernel for an unbounded size and allocate it; no grow/retry loop.
	raw := make([]byte, (MaxAddresses+1)*size)
	n, e := readIfconf(o.fd, raw)
	if e != nil {
		return nil, osSourceError(e)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return parseIfconf(raw, n, size)
}
func (o *linuxOS) IPv6(ctx context.Context) ([]indexedAddress, error) {
	raw, e := o.readProc(ctx, "if_inet6")
	if e != nil {
		return nil, e
	}
	return parseIPv6(raw)
}

// ifconf's natural Go alignment matches the Linux int/pointer ABI on both
// supported 32-bit and 64-bit architectures. No pointer is hidden in byte data.
// This is the sole raw ioctl; its request is always read-only SIOCGIFCONF.
type ifconf struct {
	Len  int32
	Data unsafe.Pointer
}

func readIfconf(fd int, raw []byte) (int, error) {
	return readIfconfWith(raw, func(arg *ifconf) error {
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.SIOCGIFCONF), uintptr(unsafe.Pointer(arg)))
		runtime.KeepAlive(arg)
		if errno != 0 {
			return errno
		}
		return nil
	})
}
func readIfconfWith(raw []byte, invoke func(*ifconf) error) (int, error) {
	if len(raw) == 0 || len(raw) > maxRawBytes || invoke == nil {
		return 0, ErrInvalidInput
	}
	arg := ifconf{Len: int32(len(raw)), Data: unsafe.Pointer(&raw[0])}
	e := invoke(&arg)
	runtime.KeepAlive(raw)
	runtime.KeepAlive(&arg)
	if e != nil {
		return 0, e
	}
	return int(arg.Len), nil
}

func (o *linuxOS) readProc(ctx context.Context, kind string) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if kind != "dev" && kind != "if_inet6" {
		return nil, ErrInvalidInput
	}
	if e := o.initProc(); e != nil {
		return nil, e
	}
	fd, e := unix.Openat(int(o.net.Fd()), kind, procReadFlags, 0)
	if e != nil {
		return nil, osSourceError(e)
	}
	f := os.NewFile(uintptr(fd), "endpoint-identity-proc-source")
	defer f.Close()
	var stat unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return nil, ErrInvalidSource
	}
	raw, e := io.ReadAll(io.LimitReader(f, maxRawBytes+1))
	if e != nil {
		return nil, osSourceError(e)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(raw) > maxRawBytes {
		return nil, ErrByteLimit
	}
	return raw, nil
}
func (o *linuxOS) initProc() error {
	if o.proc != nil && o.net != nil {
		return nil
	}
	if os.Geteuid() == 0 {
		return ErrPermissionDenied
	}
	proc, e := openProcDirectory(-1, "/proc")
	if e != nil {
		return e
	}
	pid, e := resolveProcSelf(func(name string, target []byte) (int, error) { return unix.Readlinkat(int(proc.Fd()), name, target) })
	if e != nil {
		proc.Close()
		return e
	}
	self, e := openProcDirectory(int(proc.Fd()), pid)
	if e != nil {
		proc.Close()
		return e
	}
	net, e := openProcDirectory(int(self.Fd()), "net")
	self.Close()
	if e != nil {
		proc.Close()
		return e
	}
	o.proc, o.net = proc, net
	return nil
}
func openProcDirectory(parent int, name string) (*os.File, error) {
	var fd int
	var e error
	if parent < 0 {
		fd, e = unix.Open(name, procDirFlags, 0)
	} else {
		fd, e = unix.Openat(parent, name, procDirFlags, 0)
	}
	if e != nil {
		return nil, osSourceError(e)
	}
	var fs unix.Statfs_t
	if unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		unix.Close(fd)
		return nil, ErrInvalidSource
	}
	return os.NewFile(uintptr(fd), "endpoint-identity-proc-directory"), nil
}
func resolveProcSelf(readlink func(string, []byte) (int, error)) (string, error) {
	if readlink == nil {
		return "", ErrInvalidInput
	}
	var b [64]byte
	n, e := readlink("net", b[:])
	if e != nil {
		return "", osSourceError(e)
	}
	if n <= 0 || n >= len(b) || string(b[:n]) != "self/net" {
		return "", ErrInvalidSource
	}
	n, e = readlink("self", b[:])
	if e != nil {
		return "", osSourceError(e)
	}
	if n <= 0 || n >= len(b) {
		return "", ErrInvalidSource
	}
	pid := string(b[:n])
	v, e := strconv.ParseUint(pid, 10, 31)
	if e != nil || v == 0 || strconv.FormatUint(v, 10) != pid {
		return "", ErrInvalidSource
	}
	return pid, nil
}
func (o *linuxOS) Close() error {
	var e error
	if o.fd >= 0 {
		if unix.Close(o.fd) != nil {
			e = ErrInvalidSource
		}
		o.fd = -1
	}
	for _, f := range []*os.File{o.net, o.proc} {
		if f != nil && f.Close() != nil {
			e = ErrInvalidSource
		}
	}
	o.net, o.proc = nil, nil
	return e
}
func osSourceError(e error) error {
	switch {
	case errors.Is(e, os.ErrPermission):
		return ErrPermissionDenied
	case errors.Is(e, os.ErrNotExist):
		return ErrSourceMissing
	case errors.Is(e, unix.EAFNOSUPPORT), errors.Is(e, unix.EPROTONOSUPPORT), errors.Is(e, unix.ENOTTY):
		return ErrNotSupported
	default:
		return errors.New("endpoint_identity_read_failed")
	}
}

func parseInterfaceNames(raw []byte) ([]string, error) {
	if len(raw) > maxRawBytes {
		return nil, ErrByteLimit
	}
	lines := bytes.Split(raw, []byte{'\n'})
	if len(lines) < 3 || len(lines[len(lines)-1]) != 0 {
		return nil, ErrInvalidSource
	}
	if strings.TrimSpace(string(lines[0])) != "Inter-|   Receive                                                |  Transmit" || strings.TrimSpace(string(lines[1])) != "face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed" {
		return nil, ErrInvalidSource
	}
	out := []string{}
	seen := map[string]bool{}
	for _, line := range lines[2 : len(lines)-1] {
		if len(line) > maxLineBytes {
			return nil, ErrByteLimit
		}
		left, right, ok := strings.Cut(string(line), ":")
		name := strings.TrimSpace(left)
		if !ok || !safeInterfaceName(name) || seen[name] {
			return nil, ErrInvalidSource
		}
		fields := strings.Fields(right)
		if len(fields) != 16 {
			return nil, ErrInvalidSource
		}
		for _, v := range fields {
			if _, e := strconv.ParseUint(v, 10, 64); e != nil || strings.ContainsAny(v, "+-") {
				return nil, ErrInvalidSource
			}
		}
		seen[name] = true
		out = append(out, name)
		if len(out) > MaxInterfaces {
			return nil, ErrItemLimit
		}
	}
	return out, nil
}
func parseIPv6(raw []byte) ([]indexedAddress, error) {
	if len(raw) > maxRawBytes {
		return nil, ErrByteLimit
	}
	if len(raw) == 0 {
		return []indexedAddress{}, nil
	}
	lines := bytes.Split(raw, []byte{'\n'})
	if len(lines[len(lines)-1]) != 0 {
		return nil, ErrInvalidSource
	}
	out := []indexedAddress{}
	for _, line := range lines[:len(lines)-1] {
		if len(line) > maxLineBytes {
			return nil, ErrByteLimit
		}
		fields := strings.Fields(string(line))
		if len(fields) != 6 || len(fields[0]) != 32 || !safeInterfaceName(fields[5]) {
			return nil, ErrInvalidSource
		}
		ip, e := hex.DecodeString(fields[0])
		if e != nil || hex.EncodeToString(ip) != fields[0] {
			return nil, ErrInvalidSource
		}
		for _, f := range fields[1:5] {
			for _, c := range f {
				if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
					return nil, ErrInvalidSource
				}
			}
		}
		index, e := strconv.ParseUint(fields[1], 16, 31)
		if e != nil || index == 0 || len(fields[1]) > 8 {
			return nil, ErrInvalidSource
		}
		prefix, e := strconv.ParseUint(fields[2], 16, 8)
		if e != nil || prefix > 128 || len(fields[2]) != 2 {
			return nil, ErrInvalidSource
		}
		for _, f := range fields[3:5] {
			if len(f) < 2 || len(f) > 8 {
				return nil, ErrInvalidSource
			}
			if _, e := strconv.ParseUint(f, 16, 32); e != nil {
				return nil, ErrInvalidSource
			}
		}
		var b [16]byte
		copy(b[:], ip)
		out = append(out, indexedAddress{uint32(index), fields[5], netip.AddrFrom16(b)})
		if len(out) > MaxAddresses {
			return nil, ErrItemLimit
		}
	}
	return out, nil
}
func parseIfconf(raw []byte, n, size int) ([]namedAddress, error) {
	if size != 32 && size != 40 || len(raw) != (MaxAddresses+1)*size || n < 0 || n > len(raw) || n%size != 0 {
		return nil, ErrInvalidSource
	}
	if len(raw)-n < size {
		return nil, ErrItemLimit
	}
	out := []namedAddress{}
	for offset := 0; offset < n; offset += size {
		row := raw[offset : offset+size]
		end := bytes.IndexByte(row[:16], 0)
		if end <= 0 || end > MaxInterfaceNameBytes {
			return nil, ErrInvalidSource
		}
		name := string(row[:end])
		if !safeAlias(name) || binary.NativeEndian.Uint16(row[16:18]) != unix.AF_INET {
			return nil, ErrInvalidSource
		}
		var ip [4]byte
		copy(ip[:], row[20:24])
		out = append(out, namedAddress{name, netip.AddrFrom4(ip)})
	}
	return out, nil
}
