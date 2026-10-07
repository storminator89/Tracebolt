package windowsstate

import (
	"encoding/binary"
	"strconv"
	"strings"
	"unicode/utf16"
)

// parseDescriptor decodes only the fixed self-relative descriptor format. It
// never formats raw descriptor or file bytes in an error.
func parseDescriptor(b []byte) (securityPolicy, error) {
	var p securityPolicy
	if len(b) < 20 || len(b) > 65536 || b[0] != 1 {
		return p, ErrPolicy
	}
	control := binary.LittleEndian.Uint16(b[2:4])
	if control&0x8000 == 0 {
		return p, ErrPolicy
	}
	p.present = control&4 != 0
	p.protected = control&0x1000 != 0
	p.defaulted = control&8 != 0
	owner := uint64(binary.LittleEndian.Uint32(b[4:8]))
	acl := uint64(binary.LittleEndian.Uint32(b[16:20]))
	if owner < 20 || owner >= uint64(len(b)) || acl < 20 || acl+8 > uint64(len(b)) {
		return p, ErrPolicy
	}
	var e error
	p.owner, _, e = parseSID(b[owner:])
	if e != nil {
		return p, e
	}
	a := b[acl:]
	size := int(binary.LittleEndian.Uint16(a[2:4]))
	count := int(binary.LittleEndian.Uint16(a[4:6]))
	if a[0] != 2 || size < 8 || size > len(a) || count > 16 {
		return p, ErrPolicy
	}
	a = a[:size]
	off := 8
	for range count {
		if off+8 > len(a) {
			return p, ErrPolicy
		}
		n := int(binary.LittleEndian.Uint16(a[off+2 : off+4]))
		if n < 16 || off+n > len(a) {
			return p, ErrPolicy
		}
		sid, used, e := parseSID(a[off+8 : off+n])
		if e != nil || used+8 != n {
			return p, ErrPolicy
		}
		p.entries = append(p.entries, accessEntry{kind: a[off], flags: a[off+1], mask: binary.LittleEndian.Uint32(a[off+4 : off+8]), sid: sid})
		off += n
	}
	if off != len(a) {
		return p, ErrPolicy
	}
	return p, nil
}
func parseSID(b []byte) (string, int, error) {
	if len(b) < 8 || b[0] != 1 || b[1] == 0 || b[1] > 15 {
		return "", 0, ErrPolicy
	}
	n := 8 + 4*int(b[1])
	if n > len(b) {
		return "", 0, ErrPolicy
	}
	var authority uint64
	for _, c := range b[2:8] {
		authority = authority<<8 | uint64(c)
	}
	var out strings.Builder
	out.WriteString("S-1-")
	out.WriteString(strconv.FormatUint(authority, 10))
	for i := 8; i < n; i += 4 {
		out.WriteByte('-')
		out.WriteString(strconv.FormatUint(uint64(binary.LittleEndian.Uint32(b[i:i+4])), 10))
	}
	return out.String(), n, nil
}

// FILE_ID_BOTH_DIR_INFO has an invariant 104-byte fixed prefix, including on
// 32-bit Windows (LARGE_INTEGER fields are 8-byte aligned by the native ABI).
// The parser is kept platform-independent for malformed-buffer fixtures.
func parseDirectoryBuffer(b []byte) ([]string, error) {
	var names []string
	for {
		if len(b) < 104 {
			return nil, ErrIntegrity
		}
		next := uint64(binary.LittleEndian.Uint32(b[:4]))
		n := uint64(binary.LittleEndian.Uint32(b[60:64]))
		end := uint64(len(b))
		if next != 0 {
			if next%8 != 0 || next < 104 || next > uint64(len(b)) {
				return nil, ErrIntegrity
			}
			end = next
		}
		if n == 0 || n%2 != 0 || 104+n > end || n > 200 {
			return nil, ErrIntegrity
		}
		name, e := decodeUTF16(b[104 : 104+n])
		if e != nil {
			return nil, e
		}
		if name != "." && name != ".." {
			if !validName(name) {
				return nil, ErrIntegrity
			}
			names = append(names, name)
		}
		if next == 0 {
			break
		}
		b = b[next:]
	}
	return names, nil
}
func decodeUTF16(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", ErrIntegrity
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i : 2*i+2])
		if u[i] == 0 || u[i] >= 0xd800 && u[i] <= 0xdfff {
			return "", ErrIntegrity
		}
	}
	return string(utf16.Decode(u)), nil
}
func validateDefaultStream(b []byte) error {
	if len(b) < 24 {
		return ErrIntegrity
	}
	next := binary.LittleEndian.Uint32(b[:4])
	n := uint64(binary.LittleEndian.Uint32(b[4:8]))
	if next != 0 || n != 14 || 24+n > uint64(len(b)) {
		return ErrIntegrity
	}
	name, e := decodeUTF16(b[24 : 24+n])
	if e != nil || name != "::$DATA" {
		return ErrIntegrity
	}
	return nil
}
