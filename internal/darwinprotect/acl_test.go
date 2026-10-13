package darwinprotect

import (
	"encoding/binary"
	"testing"
)

func securityFixture(count uint32, aceFlags uint32) []byte {
	n := count
	if n == ^uint32(0) {
		n = 0
	}
	raw := make([]byte, 12+44+int(n)*24)
	binary.LittleEndian.PutUint32(raw, uint32(len(raw)))
	binary.LittleEndian.PutUint32(raw[4:], 8)
	binary.LittleEndian.PutUint32(raw[8:], uint32(len(raw)-12))
	binary.LittleEndian.PutUint32(raw[12:], 0x012cc16d)
	binary.LittleEndian.PutUint32(raw[48:], count)
	for i := uint32(0); i < n; i++ {
		binary.LittleEndian.PutUint32(raw[12+44+int(i)*24+16:], aceFlags)
	}
	return raw
}
func TestSecurityAttributesFailClosed(t *testing.T) {
	absent := make([]byte, 12)
	binary.LittleEndian.PutUint32(absent, 12)
	binary.LittleEndian.PutUint32(absent[4:], 8)
	for _, raw := range [][]byte{absent, securityFixture(0, 0), securityFixture(^uint32(0), 0), securityFixture(1, 2), securityFixture(128, 2|0x1f0)} {
		if !safeSecurityAttribute(raw) {
			t.Fatal("safe no-ACL/deny-only fixture rejected")
		}
	}
	for _, flags := range []uint32{0, 1, 3, 4, 1 | 0x10, 1 | 0x100, 2 | 0x200, 2 | 0x80000000} {
		if safeSecurityAttribute(securityFixture(1, flags)) {
			t.Fatalf("unsafe ACE admitted: %x", flags)
		}
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { binary.LittleEndian.PutUint32(b, uint32(len(b)+4)) },
		func(b []byte) { binary.LittleEndian.PutUint32(b, 11) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[4:], ^uint32(0)) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[4:], 0) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[8:], 43) },
		func(b []byte) { b[12] = 0 },
		func(b []byte) { b[16] = 1 },
		func(b []byte) { binary.LittleEndian.PutUint32(b[48:], 129) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[48:], ^uint32(0)) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[52:], 1<<16) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[52:], 1) },
	} {
		b := securityFixture(1, 2)
		mutate(b)
		if safeSecurityAttribute(b) {
			t.Fatal("malformed metadata admitted")
		}
	}
	good := securityFixture(1, 2)
	for n := 0; n < len(good); n++ {
		if safeSecurityAttribute(good[:n]) {
			t.Fatalf("truncation %d admitted", n)
		}
	}
	padded := make([]byte, maxSecurityBytes)
	copy(padded, good)
	if !safeSecurityAttribute(padded) {
		t.Fatal("bounded kernel output buffer rejected")
	}
}
func TestVolumeACLSupportRequiresKnownCapability(t *testing.T) {
	b := make([]byte, 36)
	binary.LittleEndian.PutUint32(b, 36)
	binary.LittleEndian.PutUint32(b[8:], extendedSecurityCapability)
	binary.LittleEndian.PutUint32(b[24:], extendedSecurityCapability)
	if !supportsSecurityAttribute(b) {
		t.Fatal("supported fixture rejected")
	}
	for _, offset := range []int{0, 8, 24} {
		c := append([]byte(nil), b...)
		binary.LittleEndian.PutUint32(c[offset:], 0)
		if supportsSecurityAttribute(c) {
			t.Fatal("unknown or unsupported volume admitted")
		}
	}
	for n := 0; n < len(b); n++ {
		if supportsSecurityAttribute(b[:n]) {
			t.Fatal("truncated capabilities admitted")
		}
	}
}
func FuzzSecurityAttribute(f *testing.F) {
	f.Add(securityFixture(1, 2))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) { _ = safeSecurityAttribute(b) })
}
