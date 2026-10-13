// Package darwinprotect implements conservative, descriptor-based macOS file
// protection. Native functions exist only on Darwin; bounded wire parsers are
// platform-independent so malformed security metadata is testable elsewhere.
package darwinprotect

import "encoding/binary"

const (
	maxSecurityBytes           = 12 + 44 + 128*24
	extendedSecurityCapability = uint32(0x00000400)
)

// Security attributes use host-endian fields; both supported Darwin targets
// (amd64 and arm64) are little-endian. The record contains only the requested
// ATTR_CMN_EXTENDED_SECURITY reference, never other identifying metadata.
// Reference: Apple XNU bsd/sys/attr.h, bsd/sys/kauth.h and
// bsd/vfs/vfs_attrlist.c (attr_pack_common).
func safeSecurityAttribute(raw []byte) bool {
	if len(raw) < 12 || len(raw) > maxSecurityBytes {
		return false
	}
	n := binary.LittleEndian.Uint32(raw)
	if n < 12 || int(n) > len(raw) {
		return false
	}
	offset := int64(int32(binary.LittleEndian.Uint32(raw[4:8])))
	size := int64(binary.LittleEndian.Uint32(raw[8:12]))
	// XNU packs an empty reference when the ACL is absent. This is only safe
	// after the caller independently verifies volume ACL support.
	if size == 0 {
		return n == 12 && (offset == 0 || offset == 8)
	}
	start := int64(4) + offset
	if offset < 8 || start != 12 || size < 44 || start+size != int64(n) {
		return false
	}
	sec := raw[int(start):int(start+size)]
	if binary.LittleEndian.Uint32(sec) != 0x012cc16d {
		return false
	}
	// Owner/group UUIDs are not returned for this attribute by XNU.
	for _, b := range sec[4:36] {
		if b != 0 {
			return false
		}
	}
	count := binary.LittleEndian.Uint32(sec[36:40])
	flags := binary.LittleEndian.Uint32(sec[40:44])
	// Deferred inheritance can change authority upon rename. Unknown and
	// filesystem-private flags are not interpreted as safe.
	if flags & ^uint32(1<<17) != 0 {
		return false
	}
	if count == ^uint32(0) {
		return size == 44
	}
	if count > 128 || size != 44+int64(count)*24 {
		return false
	}
	for i := uint32(0); i < count; i++ {
		ace := sec[44+int(i)*24 : 44+int(i+1)*24]
		f := binary.LittleEndian.Uint32(ace[16:20])
		// Denials can only narrow POSIX access. Permit/audit/alarm/unknown
		// entries are rejected, including inherited and inherit-only permits.
		if f&0xf != 2 || f & ^uint32(0x1ff) != 0 {
			return false
		}
	}
	return true
}

func supportsSecurityAttribute(raw []byte) bool {
	// uint32 length, followed by capabilities[4] and valid[4].
	return len(raw) == 36 && binary.LittleEndian.Uint32(raw) == 36 &&
		binary.LittleEndian.Uint32(raw[8:12])&extendedSecurityCapability != 0 &&
		binary.LittleEndian.Uint32(raw[24:28])&extendedSecurityCapability != 0
}
