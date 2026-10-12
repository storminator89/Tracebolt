package windowssoftwareexecutor

import (
	"bytes"
	"encoding/binary"
)

func foregroundGroups(b []byte, base uint64, width int) bool {
	if (width != 4 && width != 8) || len(b) < width || len(b) > maxTokenBytes {
		return false
	}
	count := uint64(binary.LittleEndian.Uint32(b))
	end := uint64(width) + count*uint64(2*width)
	if count == 0 || count > 128 || end > uint64(len(b)) {
		return false
	}
	found := false
	for i := uint64(0); i < count; i++ {
		at := width + int(i)*2*width
		off, ok := sidOffset(b, at, base, width, int(end), 8)
		if !ok {
			return false
		}
		sid := b[off:]
		if sid[0] != 1 || sid[1] > 15 || len(sid) < 8+4*int(sid[1]) {
			return false
		}
		if sid[1] == 1 && bytes.Equal(sid[:8], []byte{1, 1, 0, 0, 0, 0, 0, 5}) {
			rid := binary.LittleEndian.Uint32(sid[8:])
			attributes := binary.LittleEndian.Uint32(b[at+width:])
			if rid == 6 {
				return false
			} // SERVICE group is not an interactive launch.
			if rid == 4 {
				if found || attributes&4 == 0 || attributes&0x10 != 0 {
					return false
				}
				found = true
			}
		}
	}
	return found
}
