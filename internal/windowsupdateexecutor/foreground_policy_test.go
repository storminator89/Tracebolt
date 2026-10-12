package windowsupdateexecutor

import (
	"encoding/binary"
	"testing"
)

func TestForegroundRequiresBoundedEnabledInteractiveGroup(t *testing.T) {
	for _, width := range []int{4, 8} {
		_, records, _ := tokenFixture(width)
		b := records[tokenGroups]
		copy(b[3*width:], []byte{1, 1, 0, 0, 0, 0, 0, 5})
		binary.LittleEndian.PutUint32(b[3*width+8:], 4)
		if !foregroundGroups(b, 0x1000, width) {
			t.Fatal("interactive group rejected")
		}
		binary.LittleEndian.PutUint32(b[2*width:], 0x10)
		if foregroundGroups(b, 0x1000, width) {
			t.Fatal("deny-only interactive accepted")
		}
		binary.LittleEndian.PutUint32(b[2*width:], 4)
		binary.LittleEndian.PutUint32(b[3*width+8:], 6)
		if foregroundGroups(b, 0x1000, width) {
			t.Fatal("service session accepted")
		}
		binary.LittleEndian.PutUint32(b, 129)
		if foregroundGroups(b, 0x1000, width) {
			t.Fatal("unbounded groups")
		}
	}
}
