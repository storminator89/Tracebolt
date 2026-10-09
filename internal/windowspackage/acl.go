package windowspackage

// ProgramData alone may give unrelated users add-file/write-EA/write-attribute
// rights to the shared parent. Every replacement/destructive right stays denied.
// FILE_ADD_SUBDIRECTORY (0x4) on ancestors does not permit replacing a pinned child.
func ancestorWriteMask(programData bool) uint32 {
	mask := uint32(0x10000000 | 0x40000000 | 0x80000 | 0x40000 | 0x10000 | 0x40)
	if !programData {
		mask |= 0x2 | 0x10 | 0x100
	}
	return mask
}
