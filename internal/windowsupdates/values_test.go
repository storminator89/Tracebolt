package windowsupdates

import (
	"strings"
	"testing"
	"unicode/utf16"
)

func TestNativeUTF16RejectsMalformedAndBounds(t *testing.T) {
	for _, s := range []string{"", "test", "Patch ✓ 😀", strings.Repeat("x", MaxNativeStringUnits)} {
		got, e := decodeNativeString(utf16.Encode([]rune(s)))
		if e != nil || got != s {
			t.Fatal(got, e)
		}
	}
	for _, u := range [][]uint16{{0xd800}, {0xdc00}, {'a', 0xd800, 'b'}, {0xd800, 0xd800}, {0xdfff, 'x'}} {
		if _, e := decodeNativeString(u); e != ErrMetadata {
			t.Fatal(u, e)
		}
	}
	if _, e := decodeNativeString(make([]uint16, MaxNativeStringUnits+1)); e != ErrBounds {
		t.Fatal(e)
	}
}
