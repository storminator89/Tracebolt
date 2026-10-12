package windowssoftwareexecutor

import (
	"encoding/binary"
	"errors"
	"testing"
)

func tokenFixture(width int) (tokenAPI, map[uint32][]byte, *int) {
	records := map[uint32][]byte{}
	scalar := func(c, n uint32) { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, n); records[c] = b }
	scalar(tokenType, 1)
	scalar(tokenElevation, 1)
	scalar(tokenRestrictions, 0)
	ptr := func(b []byte, at, off int) {
		if width == 4 {
			binary.LittleEndian.PutUint32(b[at:], uint32(0x1000+off))
		} else {
			binary.LittleEndian.PutUint64(b[at:], uint64(0x1000+off))
		}
	}
	b := make([]byte, 2*width+12)
	ptr(b, 0, 2*width)
	binary.LittleEndian.PutUint32(b[width:], 0x20)
	copy(b[2*width:], []byte{1, 1, 0, 0, 0, 0, 0, 16})
	binary.LittleEndian.PutUint32(b[2*width+8:], 0x3000)
	records[tokenIntegrity] = b
	b = make([]byte, 3*width+16)
	binary.LittleEndian.PutUint32(b, 1)
	ptr(b, width, 3*width)
	binary.LittleEndian.PutUint32(b[2*width:], 4)
	copy(b[3*width:], []byte{1, 2, 0, 0, 0, 0, 0, 5})
	binary.LittleEndian.PutUint32(b[3*width+8:], 32)
	binary.LittleEndian.PutUint32(b[3*width+12:], 544)
	records[tokenGroups] = b
	closes := new(int)
	return tokenAPI{openThread: func() (uintptr, error) { return 0, errNoToken }, openProcess: func() (uintptr, error) { return 5, nil }, query: func(_ uintptr, c uint32, out []byte) (uint32, error) {
		v := records[c]
		if len(out) < len(v) {
			return uint32(len(v)), errBuffer
		}
		copy(out, v)
		return uint32(len(v)), nil
	}, close: func(uintptr) error { *closes++; return nil }, base: func([]byte) uint64 { return 0x1000 }}, records, closes
}
func TestTokenPrerequisitesAreIndependentAndFailClosed(t *testing.T) {
	for _, width := range []int{4, 8} {
		api, _, closes := tokenFixture(width)
		if err := verifyToken(api, width); err != nil || *closes != 1 {
			t.Fatal(width, err, *closes)
		}
	}
	cases := map[string]func(*tokenAPI, map[uint32][]byte){
		"thread": func(a *tokenAPI, _ map[uint32][]byte) { a.openThread = func() (uintptr, error) { return 7, nil } }, "thread_denied": func(a *tokenAPI, _ map[uint32][]byte) {
			a.openThread = func() (uintptr, error) { return 0, errors.New("denied") }
		}, "process_denied": func(a *tokenAPI, _ map[uint32][]byte) {
			a.openProcess = func() (uintptr, error) { return 0, errors.New("denied") }
		}, "close_failure": func(a *tokenAPI, _ map[uint32][]byte) { a.close = func(uintptr) error { return errors.New("failure") } },
		"not_elevated": func(_ *tokenAPI, r map[uint32][]byte) { binary.LittleEndian.PutUint32(r[tokenElevation], 0) }, "restricted": func(_ *tokenAPI, r map[uint32][]byte) { binary.LittleEndian.PutUint32(r[tokenRestrictions], 1) }, "not_primary": func(_ *tokenAPI, r map[uint32][]byte) { binary.LittleEndian.PutUint32(r[tokenType], 2) }, "medium": func(_ *tokenAPI, r map[uint32][]byte) { binary.LittleEndian.PutUint32(r[tokenIntegrity][24:], 0x2000) }, "admin_disabled": func(_ *tokenAPI, r map[uint32][]byte) { binary.LittleEndian.PutUint32(r[tokenGroups][16:], 0) }, "admin_deny_only": func(_ *tokenAPI, r map[uint32][]byte) { binary.LittleEndian.PutUint32(r[tokenGroups][16:], 0x14) }, "not_admin": func(_ *tokenAPI, r map[uint32][]byte) { binary.LittleEndian.PutUint32(r[tokenGroups][36:], 545) }, "sid_outside": func(_ *tokenAPI, r map[uint32][]byte) {
			binary.LittleEndian.PutUint64(r[tokenGroups][8:], 0xffffffffffffffff)
		}, "count_overflow": func(_ *tokenAPI, r map[uint32][]byte) { binary.LittleEndian.PutUint32(r[tokenGroups], 0xffffffff) }, "unknown_scalar": func(_ *tokenAPI, r map[uint32][]byte) { r[tokenElevation] = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a, r, _ := tokenFixture(8)
			mutate(&a, r)
			if err := verifyToken(a, 8); err == nil {
				t.Fatal("unproven token accepted")
			}
		})
	}
}
