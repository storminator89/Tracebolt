package windowsfullservices

import (
	"strings"
	"testing"
	"unicode/utf16"
	"unsafe"
)

// Buffer parsing only. No SCM calls, service grants or native enumeration.
func TestNativeServiceStringBoundsAndOwnedUnicode(t *testing.T) {
	units := append(utf16.Encode([]rune(strings.Repeat("界", 256))), 0)
	buf := make([]byte, len(units)*2)
	values := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[0])), len(units))
	copy(values, units)
	got, ok := nativeString(buf, &values[0])
	if !ok || got != strings.Repeat("界", 256) {
		t.Fatal("native-sized Unicode lost")
	}
	clear(buf)
	if got != strings.Repeat("界", 256) {
		t.Fatal("string aliases reused buffer")
	}
	if _, ok = nativeString(buf, nil); ok {
		t.Fatal("nil pointer accepted")
	}
	foreign := uint16(0)
	if _, ok = nativeString(buf, &foreign); ok {
		t.Fatal("foreign pointer accepted")
	}
	if _, ok = nativeString(buf, (*uint16)(unsafe.Pointer(&buf[1]))); ok {
		t.Fatal("unaligned pointer accepted")
	}
	values[0] = 0xd800
	values[1] = 0
	if _, ok = nativeString(buf, &values[0]); ok {
		t.Fatal("unpaired surrogate accepted")
	}
	values[0] = 0xdc00
	values[1] = 0
	if _, ok = nativeString(buf, &values[0]); ok {
		t.Fatal("low surrogate accepted")
	}
	for i := range values {
		values[i] = 'x'
	}
	if _, ok = nativeString(buf, &values[0]); ok {
		t.Fatal("unterminated name accepted")
	}
	if _, ok = nativeState(0xffff); ok {
		t.Fatal("unknown state became observed/stopped")
	}
}

func TestNativeServicePIDValidityIsStateBound(t *testing.T) {
	for n := uint32(0); n <= 8; n++ {
		state, known := nativeState(n)
		var p *string
		if known {
			p = &state
		}
		want := n >= 4 && n <= 7
		if StatePIDValid(p) != want {
			t.Fatal("invalid PID state", n)
		}
	}
	for _, state := range []string{"stopped", "start_pending", "stop_pending"} {
		pid := uint32(99)
		r := Row{Name: "invented", DisplayNameQuality: "unavailable", State: &state, StateQuality: "observed", PID: &pid, PIDQuality: "observed"}
		if ValidateRow(r) == nil {
			t.Fatal("invalid PID was reported observed", state)
		}
	}
}
