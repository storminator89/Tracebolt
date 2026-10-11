//go:build windows && (amd64 || arm64)

package windowsnetworkcontext

import (
	"golang.org/x/sys/windows"
	"testing"
	"unsafe"
)

// Inert SDK-layout checks only; this test never calls an IP Helper provider.
func TestIPHelperSelectedFieldLayouts(t *testing.T) {
	var i windows.MibIfRow2
	var r windows.MibIpForwardRow2
	if unsafe.Sizeof(i) != 1352 || unsafe.Offsetof(i.Alias) != 28 || unsafe.Offsetof(i.InOctets) != 1208 || unsafe.Offsetof(i.OutOctets) != 1280 || unsafe.Offsetof(i.InErrors) != 1240 || unsafe.Offsetof(i.OutErrors) != 1312 || unsafe.Offsetof(i.InDiscards) != 1232 || unsafe.Offsetof(i.OutDiscards) != 1304 {
		t.Fatal("interface ABI changed")
	}
	if unsafe.Sizeof(r) != 104 || unsafe.Offsetof(r.DestinationPrefix) != 12 || unsafe.Offsetof(r.NextHop) != 44 || unsafe.Offsetof(r.Metric) != 84 || unsafe.Offsetof(r.Origin) != 100 {
		t.Fatal("route ABI changed")
	}
	if unsafe.Offsetof(windows.MibIfTable2{}.Table) != 8 || unsafe.Offsetof(windows.MibIpForwardTable2{}.Table) != 8 {
		t.Fatal("table alignment changed")
	}
	if len(i.Alias) != 257 || unsafe.Sizeof(windows.RawSockaddrInet{}) != 28 {
		t.Fatal("selected text/socket layout changed")
	}
}
