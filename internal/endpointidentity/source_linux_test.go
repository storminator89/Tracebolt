//go:build linux

package endpointidentity

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

const devHeader = "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
const devRow = "  eth0: 100 2 0 0 0 0 0 0 200 3 0 0 0 0 0 0\n"

func TestFixedProcInterfaceParser(t *testing.T) {
	names, e := parseInterfaceNames([]byte(devHeader + devRow + strings.Replace(devRow, "eth0", "lo", 1)))
	if e != nil || !reflect.DeepEqual(names, []string{"eth0", "lo"}) {
		t.Fatal("fixed source rejected", e)
	}
	for _, raw := range []string{"", devRow, devHeader + strings.TrimSuffix(devRow, "\n"), devHeader + devRow + devRow, devHeader + strings.Replace(devRow, "100", "bad", 1), devHeader + strings.Replace(devRow, "eth0", "../eth0", 1), devHeader + strings.Replace(devRow, "100", "-1", 1)} {
		if _, e := parseInterfaceNames([]byte(raw)); e == nil {
			t.Fatal("invalid dev source accepted")
		}
	}
	if _, e := parseInterfaceNames(bytes.Repeat([]byte("x"), maxRawBytes+1)); !errors.Is(e, ErrByteLimit) {
		t.Fatal("raw dev cap ignored")
	}
	names, e = parseInterfaceNames([]byte(devHeader))
	if e != nil || names == nil || len(names) != 0 {
		t.Fatal("empty interface enumeration")
	}
}
func TestFixedIPv6Parser(t *testing.T) {
	literal := "00000000000000000000000000000001 01 80 10 80 lo\nfe800000000000000000000000000042 02 40 20 80 eth0\n"
	rows, e := parseIPv6([]byte(literal))
	if e != nil || len(rows) != 2 || rows[0].Addr.String() != "::1" || rows[1].Addr.String() != "fe80::42" || rows[1].Index != 2 {
		t.Fatal("IPv6 literal source", e)
	}
	for _, bad := range []string{strings.TrimSuffix(literal, "\n"), strings.Replace(literal, " 01 ", " 00 ", 1), strings.Replace(literal, " 80 ", " 81 ", 1), strings.Replace(literal, " 01 ", " +1 ", 1), strings.Replace(literal, " eth0", " ../eth0", 1), strings.Replace(literal, "fe80", "FE80", 1), literal + "\n"} {
		if _, e := parseIPv6([]byte(bad)); e == nil {
			t.Fatal("invalid IPv6 accepted")
		}
	}
	if rows, e = parseIPv6(nil); e != nil || rows == nil || len(rows) != 0 {
		t.Fatal("empty IPv6 not distinct")
	}
	if _, e := parseIPv6(bytes.Repeat([]byte("x"), maxRawBytes+1)); !errors.Is(e, ErrByteLimit) {
		t.Fatal("IPv6 raw cap ignored")
	}
}
func ifconfFixture(size int, names ...string) []byte {
	b := make([]byte, (MaxAddresses+1)*size)
	for i, name := range names {
		offset := i * size
		copy(b[offset:offset+16], name)
		binary.NativeEndian.PutUint16(b[offset+16:offset+18], unix.AF_INET)
		copy(b[offset+20:offset+24], []byte{192, 0, 2, byte(i + 1)})
	}
	return b
}
func TestBoundedIfconfABIAndNoTruncatedSuccess(t *testing.T) {
	for _, size := range []int{32, 40} {
		raw := ifconfFixture(size, "eth0", "eth0", "eth0:1", "lo")
		rows, e := parseIfconf(raw, 4*size, size)
		if e != nil || len(rows) != 4 || rows[2].Name != "eth0:1" || rows[2].Addr != netip.MustParseAddr("192.0.2.3") {
			t.Fatal("IPv4 secondary/alias lost", e)
		}
		for _, n := range []int{-1, 1, len(raw) + 1} {
			if _, e := parseIfconf(raw, n, size); e == nil {
				t.Fatal("bad ifconf length accepted")
			}
		}
		if _, e := parseIfconf(raw, len(raw), size); !errors.Is(e, ErrItemLimit) {
			t.Fatal("full buffer relabeled complete")
		}
		invalid := bytes.Clone(raw)
		binary.NativeEndian.PutUint16(invalid[16:18], unix.AF_INET6)
		if _, e := parseIfconf(invalid, size, size); e == nil {
			t.Fatal("wrong family accepted")
		}
		invalid = bytes.Clone(raw)
		copy(invalid[:16], []byte("no-null-padding!"))
		if _, e := parseIfconf(invalid, size, size); e == nil {
			t.Fatal("nonterminated name accepted")
		}
		if _, e := parseIfconf(raw[:len(raw)-size], 0, size); e == nil {
			t.Fatal("unbounded ABI accepted")
		}
	}
	// The fixture invokes no syscall. It checks the exact preallocated pointer
	// and length handed to the only SIOCGIFCONF wrapper.
	raw := make([]byte, 129*40)
	n, e := readIfconfWith(raw, func(arg *ifconf) error {
		if arg.Len != int32(len(raw)) || arg.Data != unsafe.Pointer(&raw[0]) {
			t.Fatal("ioctl argument not prebounded")
		}
		arg.Len = 40
		return nil
	})
	if e != nil || n != 40 {
		t.Fatal("ifconf wrapper")
	}
	called := false
	if _, e := readIfconfWith(make([]byte, maxRawBytes+1), func(*ifconf) error { called = true; return nil }); e == nil || called {
		t.Fatal("unbounded ioctl admitted")
	}
	if unsafe.Sizeof(ifconf{}) != 2*unsafe.Sizeof(uintptr(0)) {
		t.Fatal("ifconf ABI layout")
	}
}
func TestReadOnlyIndexAndFlagsAllowlist(t *testing.T) {
	var calls []uint
	row, e := readInterfaceWith("eth0:1", func(request uint, req *unix.Ifreq) error {
		if req.Name() != "eth0:1" {
			t.Fatal("label mutated")
		}
		calls = append(calls, request)
		switch request {
		case unix.SIOCGIFINDEX:
			req.SetUint32(2)
		case unix.SIOCGIFFLAGS:
			req.SetUint16(unix.IFF_UP)
		default:
			t.Fatal("unapproved ioctl")
		}
		return nil
	})
	if e != nil || row.Index != 2 || !row.Up || row.Loopback || !reflect.DeepEqual(calls, []uint{unix.SIOCGIFINDEX, unix.SIOCGIFFLAGS}) {
		t.Fatal("ioctl allowlist")
	}
	if _, e := readInterfaceWith("../eth0", func(uint, *unix.Ifreq) error { t.Fatal("unsafe name reached ioctl"); return nil }); e == nil {
		t.Fatal("unsafe name accepted")
	}
	if _, e := readInterfaceWith("eth0", func(uint, *unix.Ifreq) error { return unix.EPERM }); !errors.Is(e, ErrPermissionDenied) {
		t.Fatal("permission hidden")
	}
}
func TestPinnedProcSelfResolution(t *testing.T) {
	var calls []string
	pid, e := resolveProcSelf(func(name string, b []byte) (int, error) {
		calls = append(calls, name)
		if name == "net" {
			return copy(b, "self/net"), nil
		}
		return copy(b, "719"), nil
	})
	if e != nil || pid != "719" || !reflect.DeepEqual(calls, []string{"net", "self"}) {
		t.Fatal("proc namespace PID resolution")
	}
	for _, bad := range []string{"../7", "/proc/7", "0", "007", "self", "2147483648", strings.Repeat("1", 64)} {
		if _, e := resolveProcSelf(func(name string, b []byte) (int, error) {
			if name == "net" {
				return copy(b, "self/net"), nil
			}
			return copy(b, bad), nil
		}); e == nil {
			t.Fatal("unsafe proc PID admitted")
		}
	}
	if _, e := resolveProcSelf(func(string, []byte) (int, error) { return 0, os.ErrPermission }); !errors.Is(e, ErrPermissionDenied) {
		t.Fatal("proc permission hidden")
	}
	if _, e := resolveProcSelf(func(_ string, b []byte) (int, error) { return copy(b, "/elsewhere"), nil }); e == nil {
		t.Fatal("alternate proc net target admitted")
	}
}

type fakeLinuxOps struct {
	names          []string
	byName         map[string]SourceInterface
	v4             []namedAddress
	v6             []indexedAddress
	v4Err, v6Err   error
	changed        bool
	closed         bool
	reads4, reads6 int
}

func (f *fakeLinuxOps) Hostname(context.Context) (string, error)         { return "inert-linux", nil }
func (f *fakeLinuxOps) InterfaceNames(context.Context) ([]string, error) { return f.names, nil }
func (f *fakeLinuxOps) Interface(_ context.Context, name string) (SourceInterface, error) {
	r, ok := f.byName[name]
	if !ok {
		return SourceInterface{}, ErrSourceMissing
	}
	if f.changed {
		r.Index++
	}
	return r, nil
}
func (f *fakeLinuxOps) IPv4(context.Context) ([]namedAddress, error) {
	f.reads4++
	return f.v4, f.v4Err
}
func (f *fakeLinuxOps) IPv6(context.Context) ([]indexedAddress, error) {
	f.reads6++
	return f.v6, f.v6Err
}
func (f *fakeLinuxOps) Close() error { f.closed = true; return nil }
func sourceFixture() *fakeLinuxOps {
	return &fakeLinuxOps{names: []string{"lo", "eth0", "veth0"}, byName: map[string]SourceInterface{"lo": {1, "lo", true, true}, "eth0": {2, "eth0", true, false}, "eth0:1": {2, "eth0:1", true, false}, "veth0": {3, "veth0", false, false}}, v4: []namedAddress{{"lo", netip.MustParseAddr("127.0.0.1")}, {"eth0", netip.MustParseAddr("192.0.2.2")}, {"eth0", netip.MustParseAddr("192.0.2.3")}, {"eth0:1", netip.MustParseAddr("169.254.4.5")}}, v6: []indexedAddress{{1, "lo", netip.MustParseAddr("::1")}, {2, "eth0", netip.MustParseAddr("fe80::42")}}}
}
func TestInjectedLinuxSourcesPreserveSecondaryAliasesEmptyAndFamilies(t *testing.T) {
	ops := sourceFixture()
	s := collect(t, &linuxProvider{ops: ops})
	if s.Interfaces.Meta.Coverage != Complete || len(s.Interfaces.Items) != 3 || ops.reads4 != 1 || ops.reads6 != 1 || !ops.closed {
		t.Fatal("bounded Linux source lifecycle")
	}
	row := s.Interfaces.Items[1]
	if len(row.Addresses.IPv4.Items) != 3 || len(row.Addresses.IPv6.Items) != 1 {
		t.Fatal("secondary/alias addresses lost")
	}
	empty := s.Interfaces.Items[2]
	if empty.Up || empty.HardwareKind != "unknown" || *empty.Addresses.IPv4.Meta.ObservedCount != 0 || *empty.Addresses.IPv6.Meta.ObservedCount != 0 {
		t.Fatal("down/no-address interface lost")
	}
	ops = sourceFixture()
	ops.v6Err = ErrPermissionDenied
	s = collect(t, &linuxProvider{ops: ops})
	row = s.Interfaces.Items[1]
	if s.Interfaces.Meta.Coverage != Partial || row.Addresses.IPv6.Meta.Reason != ReasonPermissionDenied || row.Addresses.IPv4.Meta.Coverage != Complete || len(row.Addresses.IPv4.Items) != 3 {
		t.Fatal("independent family coverage lost")
	}
}
func TestInjectedLinuxDetectedRacesFailExplicitly(t *testing.T) {
	ops := sourceFixture()
	p := &linuxProvider{ops: ops}
	if _, e := p.Interfaces(context.Background()); e != nil {
		t.Fatal(e)
	}
	ops.changed = true
	if _, e := p.Addresses(context.Background(), 2, "ipv6"); !errors.Is(e, ErrInvalidSource) {
		t.Fatal("index race hidden")
	}
	ops = sourceFixture()
	ops.v6[1].Name = "renamed"
	s := collect(t, &linuxProvider{ops: ops})
	if s.Interfaces.Items[1].Addresses.IPv6.Meta.Reason != ReasonInvalidSource {
		t.Fatal("IPv6 name mismatch hidden")
	}
	ops = sourceFixture()
	ops.v4[1].Name = "unknown"
	s = collect(t, &linuxProvider{ops: ops})
	if s.Interfaces.Items[1].Addresses.IPv4.Meta.Coverage != Failed {
		t.Fatal("unresolved alias silently dropped")
	}
}
