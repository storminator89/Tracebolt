//go:build linux

package managersetup

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
)

func procAddress(addr netip.Addr) string {
	raw := addr.AsSlice()
	out := ""
	for i := 0; i < len(raw); i += 4 {
		out += fmt.Sprintf("%08X", binary.NativeEndian.Uint32(raw[i:i+4]))
	}
	return out
}
func TestReadOnlyProcListenerParser(t *testing.T) {
	raw := "  sl local_address rem_address st tx_queue rx_queue\n"
	raw += fmt.Sprintf("0: %s:20FB 00000000:0000 0A 0 0\n", procAddress(netip.MustParseAddr("127.0.0.1")))
	raw += fmt.Sprintf("1: %s:20FC 00000000000000000000000000000000:0000 0A 0 0\n", procAddress(netip.MustParseAddr("::1")))
	raw += "2: 0100007F:20FD 00000000:0000 01 0 0\n"
	rows, err := parseListeners([]byte(raw))
	if err != nil || len(rows) != 2 || rows[0].address != netip.MustParseAddrPort("127.0.0.1:8443") || rows[1].address != netip.MustParseAddrPort("[::1]:8444") {
		t.Fatalf("unexpected parsed listeners: %+v %v", rows, err)
	}
	for _, bad := range []string{"", "private malformed header", "local_address st\nmalformed", "local_address st\n0: GG00007F:20FB 0 0A", "local_address st\n0: 0100007F:0000 0 0A"} {
		if _, err := parseListeners([]byte(bad)); err == nil {
			t.Fatal("accepted incomplete listener snapshot")
		}
	}
}
func TestOverlappingAddresses(t *testing.T) {
	for _, test := range []struct {
		a, b string
		want bool
	}{
		{"0.0.0.0:8443", "127.0.0.1:8443", true},
		{"[::]:8443", "127.0.0.1:8443", true},
		{"[::ffff:127.0.0.1]:8443", "127.0.0.1:8443", true},
		{"127.0.0.1:8443", "127.0.0.2:8443", false},
		{"127.0.0.1:8443", "127.0.0.1:8444", false},
		{"[::1]:8443", "127.0.0.1:8443", false},
	} {
		if got := overlapping(netip.MustParseAddrPort(test.a), netip.MustParseAddrPort(test.b)); got != test.want {
			t.Fatalf("overlap %s %s = %v", test.a, test.b, got)
		}
	}
}
